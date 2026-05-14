// SPDX-License-Identifier: GPL-2.0
/*
 * Bedrock deterministic I/O channel guest module.
 *
 * Companion to the hypervisor-side I/O channel. The host queues requests
 * via the BEDROCK_VM_QUEUE_IO_ACTION ioctl (which appends to the
 * hypervisor's pending FIFO), the hypervisor asserts IRQ 9 once per
 * request via the emulated IOAPIC, and this module spawns one work item
 * per IRQ on an unbounded workqueue. Each worker briefly mutex-locks the
 * shared page for HYPERCALL_IO_GET_REQUEST / HYPERCALL_IO_PUT_RESPONSE
 * but runs the slow `call_usermodehelper` (podman exec) outside the
 * lock — so many long-running guest commands overlap.
 *
 * Three actions are implemented for now:
 *   ACTION_GET_WORKLOAD_DETAILS — lists each running container; for
 *                                 every container also enumerates the
 *                                 executables under `/opt/bedrock/drivers/`
 *                                 so a fuzzer can pick (container, driver)
 *                                 invocation targets.
 *   ACTION_EXEC_BASH            — runs `podman exec <container> /bin/sh -c <cmd>`
 *   ACTION_EXEC_HOST_BASH       — runs `/bin/sh -c <cmd>` directly on the
 *                                 guest, outside any container
 *
 * GetWorkloadDetails response format — every line is one record with
 * exactly two tab-separated fields, parseable by a single
 * `split('\t', 1)` per line:
 *
 *   <container>\t              — header line: this container exists
 *                                (driver field empty). Always emitted
 *                                once per container, even when the
 *                                container has driver entries below.
 *   <container>\t<driver-path> — one such line per executable found
 *                                under `/opt/bedrock/drivers/` inside
 *                                <container>.
 *
 * Output is sorted (container names alphabetically, drivers within each
 * container alphabetically) so identical guest state yields identical
 * bytes — important for the determinism log.
 *
 * Wire format on the shared page (both directions reuse the same 4KB):
 *
 *   request:  u32 magic | u32 action_id | u32 payload_len | u8 payload[]
 *   response: u32 magic | u32 action_id | i32 status | i32 exit_code | u32 data_len | u8 data[]
 *
 * The response's `action_id` mirrors the request's so the host CLI
 * can dispatch on it without tracking expected response order.
 *
 * For ACTION_EXEC_BASH the payload is two NUL-terminated strings back to
 * back: "<container>\0<cmd>\0". For ACTION_EXEC_HOST_BASH the payload is a
 * single NUL-terminated string: "<cmd>\0".
 *
 * Each parallel worker uses a unique /tmp/bedrock-io-output-<id> file to
 * avoid racing on the shared OUTPUT_PATH that the single-worker version
 * relied on.
 */

#include <linux/atomic.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/umh.h>
#include <linux/workqueue.h>

#define HYPERCALL_IO_REGISTER_PAGE 4ULL
#define HYPERCALL_IO_GET_REQUEST   5ULL
#define HYPERCALL_IO_PUT_RESPONSE  6ULL

/*
 * Pin number must match `IO_CHANNEL_IRQ` on the hypervisor side and the MP
 * table entry the boot setup emits.
 */
#define BEDROCK_IO_IRQ 9

#define BEDROCK_IO_PAGE_SIZE 4096U

#define IO_REQUEST_MAGIC  0xB10C1010U
#define IO_RESPONSE_MAGIC 0x1010B10CU

#define ACTION_GET_WORKLOAD_DETAILS 0U
#define ACTION_EXEC_BASH            1U
#define ACTION_EXEC_HOST_BASH       2U

#define OUTPUT_PATH_FMT "/tmp/bedrock-io-output-%u"
#define OUTPUT_PATH_MAX 64

struct io_request_header {
	__u32 magic;
	__u32 action_id;
	__u32 payload_len;
};

struct io_response_header {
	__u32 magic;
	__u32 action_id;
	__s32 status;
	__s32 exit_code;
	__u32 data_len;
};

/*
 * Per-work-item state. Allocated by the IRQ handler (GFP_ATOMIC) and
 * freed by the work function. The `id` is used to mint a unique
 * /tmp/bedrock-io-output-<id> file so parallel workers don't clobber
 * each other's command output.
 */
struct bedrock_io_work {
	struct work_struct work;
	unsigned int id;
};

static void *shared_page;
static struct workqueue_struct *io_wq;
/* Serialises access to `shared_page` for the VMCALL handshakes only —
 * the slow call_usermodehelper / kernel_read runs outside the lock. */
static DEFINE_MUTEX(page_mutex);
/* Monotonically-increasing worker ID used for per-worker output files.
 * Wrapping is fine (any concurrent collisions would have to be ~4B
 * workers apart, far past tmpfs cleanup pressure). */
static atomic_t worker_counter = ATOMIC_INIT(0);
/* Reserve enough preallocated work items that bursts of concurrent
 * IRQs can always queue under sustained memory pressure. Without this
 * reserve, a kmalloc(GFP_ATOMIC) failure in `bedrock_io_irq_handler`
 * drops the IRQ entirely: the hypervisor side has already set
 * `request_delivered = true`, so no GET_REQUEST is ever issued and the
 * in-flight slot sticks forever. mempool_alloc(GFP_ATOMIC) returns from
 * the reserve when the page allocator can't satisfy the request, which
 * is exactly the regime we have to survive deterministically. Size is
 * generous relative to the I/O queue depth we drive in practice
 * (single-digit concurrent commands). */
#define BEDROCK_IO_WORK_POOL_MIN 16
static mempool_t *work_pool;

/*
 * VMCALL helpers. The "memory" clobber is load-bearing — without it the
 * compiler is free to cache the shared page contents across the VMCALL,
 * which would let HYPERCALL_IO_GET_REQUEST's writes into the page go
 * unobserved on the subsequent read.
 */
static inline __u64 vmcall1(__u64 nr, __u64 arg1)
{
	__u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr), "b"(arg1)
		     : "memory");
	return result;
}

static inline __u64 vmcall0(__u64 nr)
{
	__u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr)
		     : "memory");
	return result;
}

/*
 * IRQ handler — runs in hardirq context, must not block. Just allocate a
 * per-request work struct and queue it to the unbounded workqueue, then
 * return. The actual VMCALL handshake happens later in the worker (which
 * runs in process context and can acquire the page mutex).
 */
static irqreturn_t bedrock_io_irq_handler(int irq, void *dev_id);

/*
 * Read `path` into `out` up to `cap` bytes; returns bytes read or a
 * negative errno. Partial reads pass through — the response payload is
 * truncated stdout, which is fine for the MVP.
 */
static ssize_t read_output_file(const char *path, __u8 *out, size_t cap)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);
	n = kernel_read(f, out, cap, &pos);
	filp_close(f, NULL);
	return n;
}

/*
 * Append `src` to `dst[*off..cap]` enclosed in single quotes, with each
 * embedded `'` rewritten as `'\''` (close quote, escaped quote, open
 * quote). Returns 0 on success and updates `*off`; returns -ENAMETOOLONG
 * if the escaped form (worst case 4× the input plus two outer quotes
 * and a trailing NUL) wouldn't fit. Used so guest-supplied container
 * names and bash commands can be safely interpolated into the
 * `/bin/sh -c …` wrapper without single-quote injection breaking the
 * shell line.
 */
static int append_shell_quoted(char *dst, size_t cap, size_t *off,
			       const char *src)
{
	size_t o = *off;

	if (o + 1 >= cap)
		return -ENAMETOOLONG;
	dst[o++] = '\'';
	for (; *src; src++) {
		if (*src == '\'') {
			if (o + 4 >= cap)
				return -ENAMETOOLONG;
			dst[o++] = '\'';
			dst[o++] = '\\';
			dst[o++] = '\'';
			dst[o++] = '\'';
		} else {
			if (o + 1 >= cap)
				return -ENAMETOOLONG;
			dst[o++] = *src;
		}
	}
	if (o + 2 > cap)
		return -ENAMETOOLONG;
	dst[o++] = '\'';
	dst[o] = '\0';
	*off = o;
	return 0;
}

/*
 * Append a NUL-terminated literal to `dst[*off..cap]`. Returns 0 on
 * success and updates `*off`; returns -ENAMETOOLONG if the literal
 * doesn't fit. Trusted-input cousin of `append_shell_quoted` for the
 * fixed shell scaffolding (`podman exec `, ` /bin/sh -c `,
 * ` > … 2>&1`).
 */
static int append_literal(char *dst, size_t cap, size_t *off,
			  const char *src)
{
	size_t o = *off;
	size_t n = strlen(src);

	if (o + n + 1 > cap)
		return -ENAMETOOLONG;
	memcpy(dst + o, src, n);
	o += n;
	dst[o] = '\0';
	*off = o;
	return 0;
}

/*
 * Extract a short journald tag from a guest-supplied bash command:
 * the basename of the first whitespace-delimited token. Examples:
 *
 *   "bitcoin-cli getblockchaininfo"        → "bitcoin-cli"
 *   "/opt/bedrock/drivers/dummy --arg"     → "dummy"
 *   "podman stop bitcoind1"                → "podman"
 *
 * The result becomes SYSLOG_IDENTIFIER and what the journalctl-side
 * formatter prints as `[<tag>] | <output>` — short and stable across
 * variations in the trailing arguments. Writes a NUL-terminated tag
 * into `out` (capacity `cap`); falls back to "exec" if the command
 * has no parseable first token. Returns -ENAMETOOLONG if the result
 * wouldn't fit.
 */
static int extract_command_name(const char *cmd, char *out, size_t cap)
{
	const char *start, *end, *p;
	const char *fb = "exec";
	size_t len;

	if (cap == 0)
		return -ENAMETOOLONG;

	start = cmd;
	while (*start == ' ' || *start == '\t')
		start++;

	end = start;
	while (*end && *end != ' ' && *end != '\t' && *end != '\n')
		end++;

	/* basename: scan back from end to the byte after the last '/'. */
	for (p = end; p > start; p--) {
		if (*(p - 1) == '/') {
			start = p;
			break;
		}
	}

	len = end - start;
	if (len == 0) {
		len = strlen(fb);
		if (len + 1 > cap)
			return -ENAMETOOLONG;
		memcpy(out, fb, len);
		out[len] = '\0';
		return 0;
	}
	if (len + 1 > cap)
		return -ENAMETOOLONG;
	memcpy(out, start, len);
	out[len] = '\0';
	return 0;
}

/*
 * Append the trailing journal-pipe suffix used by every exec action.
 * Builds:
 *
 *   2>&1 | systemd-cat -t <tag>
 *
 * so the command's combined stdout+stderr lands in journald with
 * SYSLOG_IDENTIFIER=<tag> and shows up in the init script's
 * `journalctl -f` formatter as `[<tag>] | <line>`. The shell's
 * `set -o pipefail` (prepended by `build_command`) makes the
 * pipeline's exit status fall back to the failing command's, so the
 * host-bound `exit_code` still reflects whether the action itself
 * succeeded — even though no output bytes flow back through the I/O
 * response. `tag` is the short command name from
 * `extract_command_name`; it's shell-quoted defensively because the
 * extractor doesn't restrict character classes.
 */
static int append_pipe_to_journal(char *cmd, size_t cmd_cap, size_t *off,
				  const char *tag)
{
	int err;

	err = append_literal(cmd, cmd_cap, off, " 2>&1 | systemd-cat -t ");
	if (err)
		return err;
	return append_shell_quoted(cmd, cmd_cap, off, tag);
}

/*
 * Build the shell command that will run inside call_usermodehelper.
 * Two output paths:
 *
 *   - ACTION_GET_WORKLOAD_DETAILS captures stdout+stderr to
 *     `output_path` so the worker can read it back into the I/O
 *     response payload; the host needs the structured workload list
 *     (e.g. to pick fuzz targets).
 *   - Exec actions pipe stdout+stderr straight into `systemd-cat`,
 *     so journald owns the output and the host-bound response carries
 *     just an exit code (no payload bytes). `set -o pipefail` is
 *     prepended so the pipeline's exit status falls back to the exec
 *     command's failure instead of always being systemd-cat's zero.
 *
 * `output_path` is per-worker so concurrent ACTION_GET_WORKLOAD_DETAILS
 * invocations don't race on a shared file; exec actions don't touch it.
 *
 * Emits a pr_info trace identifying the action and its parameters,
 * tagged with `worker_id`, so concurrent workers can be followed in
 * the kernel log.
 *
 * Returns 0 on success, negative on a malformed request.
 */
static int build_command(const struct io_request_header *hdr,
			 const __u8 *payload, char *cmd, size_t cmd_cap,
			 const char *output_path, unsigned int worker_id)
{
	switch (hdr->action_id) {
	case ACTION_GET_WORKLOAD_DETAILS:
		pr_info("bedrock-io: worker %u: list\n", worker_id);
		/*
		 * For each running container, emit one `<container>\t` header
		 * line, then one `<container>\t<driver>` line per executable
		 * found under `/opt/bedrock/drivers/` inside that container.
		 * Every output line therefore has the same shape (two
		 * tab-separated fields) which a consumer can parse with a
		 * single split per line — no state carried between lines.
		 *
		 * `-perm -100` matches files with at least user-execute
		 * (POSIX-portable, no `-executable` dependency on BusyBox
		 * version). Sorting at both levels (container names and
		 * drivers within each container) keeps the output
		 * byte-identical across runs with the same workload set,
		 * which bedrock's determinism log compares.
		 *
		 * Inner `2>/dev/null` swallows `find`'s errors when
		 * `/opt/bedrock/drivers` is absent in a container; outer
		 * `2>/dev/null` does the same for `podman exec` against a
		 * non-running container.
		 */
		snprintf(cmd, cmd_cap,
			 "podman ps --format '{{.Names}}' 2>/dev/null | sort | "
			 "while IFS= read -r c; do "
			 "printf '%%s\\t\\n' \"$c\"; "
			 "podman exec \"$c\" sh -c "
			 "'find /opt/bedrock/drivers -type f -perm -100 2>/dev/null | sort' "
			 "2>/dev/null | "
			 "while IFS= read -r f; do "
			 "printf '%%s\\t%%s\\n' \"$c\" \"$f\"; "
			 "done; "
			 "done > %s 2>&1",
			 output_path);
		return 0;
	case ACTION_EXEC_BASH: {
		const char *container = (const char *)payload;
		size_t clen;
		const char *bash_cmd;
		size_t blen;
		size_t off = 0;
		int err;

		if (hdr->payload_len == 0)
			return -EINVAL;
		clen = strnlen(container, hdr->payload_len);
		if (clen == hdr->payload_len)
			return -EINVAL;
		bash_cmd = container + clen + 1;
		blen = strnlen(bash_cmd, hdr->payload_len - clen - 1);
		if (blen == hdr->payload_len - clen - 1)
			return -EINVAL;

		pr_info("bedrock-io: worker %u: exec '%s' '%s'\n",
			worker_id, container, bash_cmd);

		/*
		 * `podman exec ... /bin/sh -c <cmd>` lets the caller supply
		 * arbitrary shell expressions (pipes, redirects). The outer
		 * `/bin/sh -c "<full>"` is the call_usermodehelper wrapper.
		 * Combined stdout+stderr is piped into systemd-cat (see
		 * `append_pipe_to_journal`) so journald receives the output;
		 * `set -o pipefail` keeps the pipeline's exit reflective of
		 * the inner command. `container` and `bash_cmd` are
		 * guest-supplied so they get single-quote-escaped via
		 * `append_shell_quoted` — a `'` in either would otherwise
		 * break out of the wrapper.
		 */
		err = append_literal(cmd, cmd_cap, &off,
				     "set -o pipefail; podman exec ");
		if (err)
			return err;
		err = append_shell_quoted(cmd, cmd_cap, &off, container);
		if (err)
			return err;
		err = append_literal(cmd, cmd_cap, &off, " /bin/sh -c ");
		if (err)
			return err;
		err = append_shell_quoted(cmd, cmd_cap, &off, bash_cmd);
		if (err)
			return err;
		{
			char cmd_name[64];
			char tag[128];

			err = extract_command_name(bash_cmd, cmd_name,
						   sizeof(cmd_name));
			if (err)
				return err;
			/* Append " [<container>]" so the formatter shows
			 * which container each exec ran inside
			 * (e.g. `[bitcoin-cli [bitcoind1]] | …`), matching
			 * the " [host]" convention used by ACTION_EXEC_HOST_BASH. */
			snprintf(tag, sizeof(tag), "%s [%s]", cmd_name, container);
			return append_pipe_to_journal(cmd, cmd_cap, &off, tag);
		}
	}
	case ACTION_EXEC_HOST_BASH: {
		const char *bash_cmd = (const char *)payload;
		size_t blen;
		size_t off = 0;
		int err;

		if (hdr->payload_len == 0)
			return -EINVAL;
		blen = strnlen(bash_cmd, hdr->payload_len);
		if (blen == hdr->payload_len)
			return -EINVAL;

		pr_info("bedrock-io: worker %u: exec-host '%s'\n",
			worker_id, bash_cmd);

		/*
		 * Run `/bin/sh -c <cmd>` directly on the guest — no
		 * `podman exec` wrapper. Combined stdout+stderr is piped
		 * into systemd-cat (see `append_pipe_to_journal`) so the
		 * output lands in journald rather than being buffered for
		 * the host. `set -o pipefail` keeps the pipeline's exit
		 * reflective of the inner command. `bash_cmd` is
		 * guest-supplied so it gets single-quote-escaped before
		 * being spliced into the inner `-c` argument.
		 */
		err = append_literal(cmd, cmd_cap, &off,
				     "set -o pipefail; /bin/sh -c ");
		if (err)
			return err;
		err = append_shell_quoted(cmd, cmd_cap, &off, bash_cmd);
		if (err)
			return err;
		{
			char cmd_name[64];
			char tag[80];

			err = extract_command_name(bash_cmd, cmd_name,
						   sizeof(cmd_name));
			if (err)
				return err;
			/* Append " [host]" so the journal formatter can tell
			 * host-side execs apart from in-container ones at a
			 * glance (e.g. `[dummy [host]] | …`). */
			snprintf(tag, sizeof(tag), "%s [host]", cmd_name);
			return append_pipe_to_journal(cmd, cmd_cap, &off, tag);
		}
	}
	default:
		pr_warn("bedrock-io: worker %u: unknown action_id=%u\n",
			worker_id, hdr->action_id);
		return -EINVAL;
	}
}

static void bedrock_io_work_fn(struct work_struct *work)
{
	struct bedrock_io_work *w =
		container_of(work, struct bedrock_io_work, work);
	struct io_request_header req_hdr;
	struct io_response_header resp_hdr;
	__u64 req_len;
	char *cmd = NULL;
	char *payload_copy = NULL;
	char output_path[OUTPUT_PATH_MAX];
	char *argv[4];
	int exit_code = 0;
	ssize_t data_read = 0;
	__s32 read_status = 0;
	__u8 *resp_data;
	size_t resp_data_cap;
	int rc;
	bool got_request = false;
	static char *envp[] = {
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
		"HOME=/",
		NULL,
	};

	snprintf(output_path, sizeof(output_path), OUTPUT_PATH_FMT, w->id);

	cmd = kmalloc(BEDROCK_IO_PAGE_SIZE, GFP_KERNEL);
	if (!cmd)
		goto out;

	/*
	 * Phase 1: page-mutexed GET_REQUEST.
	 *
	 * We copy the request into local kthread storage so the lock can be
	 * dropped before the slow call_usermodehelper call. That's what
	 * lets long-running guest commands overlap: many workers can be in
	 * call_usermodehelper at once, but only one holds the page mutex at
	 * any moment.
	 */
	mutex_lock(&page_mutex);
	req_len = vmcall0(HYPERCALL_IO_GET_REQUEST);
	if (req_len == 0 || req_len == ~0ULL) {
		/* No request available — either the hypervisor drained the
		 * queue first or this is a spurious IRQ. Both benign. */
		mutex_unlock(&page_mutex);
		goto out;
	}
	if (req_len < sizeof(req_hdr)) {
		mutex_unlock(&page_mutex);
		pr_err("bedrock-io: short request len=%llu\n", req_len);
		goto out;
	}
	memcpy(&req_hdr, shared_page, sizeof(req_hdr));
	if (req_hdr.magic != IO_REQUEST_MAGIC) {
		mutex_unlock(&page_mutex);
		pr_err("bedrock-io: bad request magic %#x\n", req_hdr.magic);
		goto out;
	}
	if (sizeof(req_hdr) + (size_t)req_hdr.payload_len > req_len) {
		mutex_unlock(&page_mutex);
		pr_err("bedrock-io: payload overruns request (payload_len=%u, req_len=%llu)\n",
		       req_hdr.payload_len, req_len);
		goto out;
	}
	if (req_hdr.payload_len > 0) {
		payload_copy = kmalloc(req_hdr.payload_len, GFP_KERNEL);
		if (!payload_copy) {
			mutex_unlock(&page_mutex);
			goto out;
		}
		memcpy(payload_copy,
		       (__u8 *)shared_page + sizeof(req_hdr),
		       req_hdr.payload_len);
	}
	got_request = true;
	mutex_unlock(&page_mutex);

	/*
	 * Phase 2: build + run command (no lock held).
	 *
	 * Other workers can run their GET_REQUEST / PUT_RESPONSE during
	 * this window; the only contention is for `shared_page`, which we
	 * don't touch here.
	 */
	rc = build_command(&req_hdr, (const __u8 *)payload_copy, cmd,
			   BEDROCK_IO_PAGE_SIZE, output_path, w->id);
	if (rc) {
		pr_err("bedrock-io: worker %u: build_command failed: %d\n",
		       w->id, rc);
		exit_code = rc;
	} else {
		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = cmd;
		argv[3] = NULL;
		/*
		 * call_usermodehelper starts the child with an empty
		 * environment by default; we mirror the PATH the initrd's
		 * init script exports so unqualified binaries resolve the
		 * same way they would from an interactive guest shell.
		 */
		exit_code = call_usermodehelper("/bin/sh", argv, envp,
						UMH_WAIT_PROC);
		pr_info("bedrock-io: worker %u: command finished, exit=%d\n",
			w->id, exit_code);
	}

	/*
	 * Phase 3: page-mutexed PUT_RESPONSE.
	 *
	 * Only ACTION_GET_WORKLOAD_DETAILS sends bytes back through the
	 * I/O response — exec actions stream their output into journald
	 * via systemd-cat, so the response for them is exit-code only
	 * and `data_read` stays 0.
	 *
	 * `read_status` preserves any negative errno from
	 * `read_output_file`; `data_read` is clamped to 0 so the
	 * data_len field stays a valid byte count, but the original
	 * error code reaches the host via `resp_hdr.status`.
	 */
	mutex_lock(&page_mutex);
	resp_data = (__u8 *)shared_page + sizeof(resp_hdr);
	resp_data_cap = BEDROCK_IO_PAGE_SIZE - sizeof(resp_hdr);
	memset(resp_data, 0, resp_data_cap);
	if (req_hdr.action_id == ACTION_GET_WORKLOAD_DETAILS) {
		data_read = read_output_file(output_path, resp_data,
					     resp_data_cap);
		if (data_read < 0) {
			pr_warn("bedrock-io: read_output_file(%s) failed: %zd\n",
				output_path, data_read);
			read_status = (__s32)data_read;
			data_read = 0;
		}
	}

	resp_hdr.magic = IO_RESPONSE_MAGIC;
	resp_hdr.action_id = req_hdr.action_id;
	resp_hdr.status = read_status;
	resp_hdr.exit_code = (__s32)exit_code;
	resp_hdr.data_len = (__u32)data_read;
	memcpy(shared_page, &resp_hdr, sizeof(resp_hdr));

	vmcall1(HYPERCALL_IO_PUT_RESPONSE,
		sizeof(resp_hdr) + (size_t)data_read);
	mutex_unlock(&page_mutex);

	/* Unlink the per-worker temp file once the response has been
	 * handed to the host. Only ACTION_GET_WORKLOAD_DETAILS writes to
	 * this path; exec actions stream through systemd-cat and never
	 * touch the filesystem here.
	 *
	 * vfs_unlink requires the parent inode's i_rwsem held for write
	 * (LOOKUP semantics for non-NULL `delegated_inode`), so lock the
	 * parent dentry's inode before calling and unlock after. */
	if (got_request && req_hdr.action_id == ACTION_GET_WORKLOAD_DETAILS) {
		struct path p;
		int unlink_err = kern_path(output_path, 0, &p);

		if (unlink_err == 0) {
			struct dentry *parent = dget_parent(p.dentry);

			inode_lock_nested(d_inode(parent), I_MUTEX_PARENT);
			unlink_err = vfs_unlink(mnt_idmap(p.mnt), d_inode(parent),
						p.dentry, NULL);
			inode_unlock(d_inode(parent));
			dput(parent);
			path_put(&p);
			if (unlink_err && unlink_err != -ENOENT)
				pr_warn("bedrock-io: vfs_unlink(%s) failed: %d\n",
					output_path, unlink_err);
		}
	}

out:
	kfree(payload_copy);
	kfree(cmd);
	mempool_free(w, work_pool);
}

static irqreturn_t bedrock_io_irq_handler(int irq, void *dev_id)
{
	struct bedrock_io_work *w;

	(void)irq;
	(void)dev_id;

	/*
	 * mempool_alloc returns from the BEDROCK_IO_WORK_POOL_MIN reserve
	 * when the page allocator can't satisfy GFP_ATOMIC, so dropping
	 * the IRQ only happens if every reserved item is already in use —
	 * a state we don't reach at realistic queue depths. The pool
	 * keeps the determinism contract: every IRQ either runs the
	 * worker or the hypervisor sees the failure via the dropped
	 * GET_REQUEST, never silently sticks.
	 */
	w = mempool_alloc(work_pool, GFP_ATOMIC);
	if (!w) {
		pr_err_once("bedrock-io: work pool exhausted in IRQ handler\n");
		return IRQ_HANDLED;
	}
	w->id = atomic_inc_return(&worker_counter);
	INIT_WORK(&w->work, bedrock_io_work_fn);
	queue_work(io_wq, &w->work);
	return IRQ_HANDLED;
}

static int __init bedrock_io_init(void)
{
	__u64 rc;
	int err;

	shared_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!shared_page)
		return -ENOMEM;

	/*
	 * WQ_UNBOUND lets workers run on any CPU; default max_active gives
	 * us a generous concurrency budget (so many long-running podman
	 * commands can overlap). WQ_MEM_RECLAIM ensures forward progress
	 * even under memory pressure.
	 */
	io_wq = alloc_workqueue("bedrock-io",
				WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!io_wq) {
		free_page((unsigned long)shared_page);
		return -ENOMEM;
	}

	work_pool = mempool_create_kmalloc_pool(BEDROCK_IO_WORK_POOL_MIN,
						sizeof(struct bedrock_io_work));
	if (!work_pool) {
		destroy_workqueue(io_wq);
		free_page((unsigned long)shared_page);
		return -ENOMEM;
	}

	/*
	 * Register the page first so the hypervisor knows where to write
	 * request bytes — without this, the channel IRQ would deliver but
	 * the GET_REQUEST hypercall would fail.
	 */
	rc = vmcall1(HYPERCALL_IO_REGISTER_PAGE, (__u64)shared_page);
	if (rc != 0) {
		pr_err("bedrock-io: HYPERCALL_IO_REGISTER_PAGE failed: %#llx\n",
		       rc);
		mempool_destroy(work_pool);
		destroy_workqueue(io_wq);
		free_page((unsigned long)shared_page);
		return -EIO;
	}

	err = request_irq(BEDROCK_IO_IRQ, bedrock_io_irq_handler, 0,
			  "bedrock-io", &worker_counter);
	if (err) {
		pr_err("bedrock-io: request_irq(%d) failed: %d\n",
		       BEDROCK_IO_IRQ, err);
		mempool_destroy(work_pool);
		destroy_workqueue(io_wq);
		free_page((unsigned long)shared_page);
		return err;
	}

	pr_info("bedrock-io: registered page=%p irq=%d (parallel workers)\n",
		shared_page, BEDROCK_IO_IRQ);
	return 0;
}

static void __exit bedrock_io_exit(void)
{
	free_irq(BEDROCK_IO_IRQ, &worker_counter);
	/* Flush any pending workers before tearing down the workqueue, so
	 * no in-flight worker is left dereferencing the pool we're about
	 * to destroy. */
	destroy_workqueue(io_wq);
	mempool_destroy(work_pool);
	free_page((unsigned long)shared_page);
}

module_init(bedrock_io_init);
module_exit(bedrock_io_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bedrock deterministic I/O channel");
