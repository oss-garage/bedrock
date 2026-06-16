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
 * The channel does exactly one thing: run a bash command. The request
 * names a target (a container, or the host itself when the container
 * field is empty) and a command, and a flag says whether to record the
 * command's output.
 *
 * Wire format on the shared page (both directions reuse the same 4KB):
 *
 *   request:  u32 magic | u32 flags | u32 payload_len | u8 payload[]
 *   response: u32 magic | u32 flags | i32 status | i32 exit_code | u32 output_len
 *
 * The request payload is two NUL-terminated strings back to back:
 * "<container>\0<cmd>\0". An empty <container> means "run on the host"
 * (`/bin/sh -c <cmd>`); otherwise the command runs via
 * `podman exec <container> /bin/sh -c <cmd>`.
 *
 * The command's combined stdout+stderr always flows into journald via
 * systemd-cat, so it is observable on the serial/journal path regardless
 * of recording. The IO_FLAG_RECORD_OUTPUT request flag additionally
 * captures it for the host:
 *
 *   - set:   the output is `tee`'d into a per-worker temp file on its way
 *            to systemd-cat, then copied into the dedicated output
 *            *feedback buffer* (registered once at init under
 *            OUTPUT_BUFFER_ID) and its length reported in the response's
 *            `output_len`. The host reads the bytes back through the
 *            feedback-buffer mechanism. The copy into the shared output
 *            buffer happens under the page mutex, immediately before
 *            PUT_RESPONSE, so concurrent workers can't clobber each
 *            other's bytes before the host reads them at the (serialised)
 *            response exit.
 *   - clear: nothing is captured for the host; `output_len` stays 0.
 *
 * `set -o pipefail` is prepended so the exit status reflects the command
 * (not the trailing tee / systemd-cat), and the host-bound `exit_code` is
 * meaningful in both modes.
 *
 * Each parallel worker uses a unique /tmp/bedrock-io-output-<id> file so
 * concurrent recorded commands don't race on a shared capture path.
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
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "libvmcall.h"

/*
 * Pin number must match `IO_CHANNEL_IRQ` on the hypervisor side and the MP
 * table entry the boot setup emits.
 */
#define BEDROCK_IO_IRQ 9

#define BEDROCK_IO_PAGE_SIZE 4096U

#define IO_REQUEST_MAGIC  0xB10C1010U
#define IO_RESPONSE_MAGIC 0x1010B10CU

/* Request flag: capture combined stdout+stderr into the output feedback
 * buffer instead of routing it to the guest journal. Must match
 * `bedrock_vm::io_channel::IO_FLAG_RECORD_OUTPUT`. */
#define IO_FLAG_RECORD_OUTPUT 0x1U

/* Identifier the host reads recorded command output under; must match
 * `bedrock_vm::io_channel::IO_OUTPUT_BUFFER_ID`. */
#define OUTPUT_BUFFER_ID "bedrock-io-output"
/* Capacity of the command-output feedback buffer (<= the hypervisor's
 * FEEDBACK_BUFFER_MAX_PAGES * 4096 = 1 MB). */
#define BEDROCK_IO_OUTPUT_SIZE (256U * 1024U)

#define OUTPUT_PATH_FMT "/tmp/bedrock-io-output-%u"
#define OUTPUT_PATH_MAX 64

struct io_request_header {
	__u32 magic;
	__u32 flags;
	__u32 payload_len;
};

struct io_response_header {
	__u32 magic;
	__u32 flags;
	__s32 status;
	__s32 exit_code;
	__u32 output_len;
};

/*
 * Per-work-item state. Allocated by the IRQ handler (GFP_ATOMIC) and
 * freed by the work function. The `id` is used to mint a unique
 * /tmp/bedrock-io-output-<id> file so parallel recorded commands don't
 * clobber each other's captured output.
 */
struct bedrock_io_work {
	struct work_struct work;
	unsigned int id;
};

static void *shared_page;
/* Dedicated feedback buffer holding the most recent recorded command's
 * combined stdout+stderr. Registered once at init; written under
 * `page_mutex` right before PUT_RESPONSE so the host reads a consistent
 * snapshot at each response exit. */
static __u8 *output_buf;
static struct workqueue_struct *io_wq;
/* Serialises access to `shared_page` and `output_buf` for the VMCALL
 * handshakes only — the slow call_usermodehelper / file read runs outside
 * the lock. */
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
 * is exactly the regime we have to survive deterministically. */
#define BEDROCK_IO_WORK_POOL_MIN 16
static mempool_t *work_pool;

/*
 * IRQ handler — runs in hardirq context, must not block. Just allocate a
 * per-request work struct and queue it to the unbounded workqueue, then
 * return. The actual VMCALL handshake happens later in the worker (which
 * runs in process context and can acquire the page mutex).
 */
static irqreturn_t bedrock_io_irq_handler(int irq, void *dev_id);

/*
 * Read `path` into `out` up to `cap` bytes; returns bytes read or a
 * negative errno. Partial reads pass through — the recorded output is
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
 * fixed shell scaffolding (`podman exec `, ` /bin/sh -c `, the redirect /
 * journal-pipe suffix).
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
 *   "/usr/local/bin/bedrock-miner --arg"   → "bedrock-miner"
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
 * Build the shell command that will run inside call_usermodehelper.
 *
 * `container` is the (possibly empty) target container; an empty string
 * runs the command directly on the host. `command` is the guest-supplied
 * bash command. Both are single-quote-escaped before being spliced into
 * the wrapper so a stray `'` can't break out of it.
 *
 * Combined stdout+stderr always flows into journald via `systemd-cat`, so
 * the output is observable on the serial/journal path regardless of
 * recording. When `record` is set, the output is additionally `tee`'d into
 * the per-worker capture file on the way, so the worker can read it back
 * into the output feedback buffer.
 *
 * `set -o pipefail` keeps the pipeline exit status reflective of the inner
 * command (not `tee` / `systemd-cat`). Emits a pr_info trace tagged with
 * `worker_id`.
 *
 * Returns 0 on success, negative on a malformed request.
 */
static int build_command(const char *container, const char *command,
			 bool record, char *cmd, size_t cmd_cap,
			 const char *output_path, unsigned int worker_id)
{
	size_t off = 0;
	int err;

	pr_info("bedrock-io: worker %u: exec target=%s record=%d cmd='%s'\n",
		worker_id, *container ? container : "host", record, command);

	err = append_literal(cmd, cmd_cap, &off, "set -o pipefail; ");
	if (err)
		return err;

	if (*container) {
		err = append_literal(cmd, cmd_cap, &off, "podman exec ");
		if (err)
			return err;
		err = append_shell_quoted(cmd, cmd_cap, &off, container);
		if (err)
			return err;
		err = append_literal(cmd, cmd_cap, &off, " /bin/sh -c ");
		if (err)
			return err;
	} else {
		err = append_literal(cmd, cmd_cap, &off, "/bin/sh -c ");
		if (err)
			return err;
	}
	err = append_shell_quoted(cmd, cmd_cap, &off, command);
	if (err)
		return err;

	/* Redirect combined stdout+stderr into the pipeline. */
	err = append_literal(cmd, cmd_cap, &off, " 2>&1 | ");
	if (err)
		return err;

	/* When recording, `tee` the output into the per-worker capture file
	 * on its way to journald, so the worker can read it back into the
	 * output feedback buffer. The path is module-generated (alnum + fixed
	 * prefix), so it needs no shell quoting. */
	if (record) {
		err = append_literal(cmd, cmd_cap, &off, "tee ");
		if (err)
			return err;
		err = append_literal(cmd, cmd_cap, &off, output_path);
		if (err)
			return err;
		err = append_literal(cmd, cmd_cap, &off, " | ");
		if (err)
			return err;
	}

	/* Always pipe into journald via systemd-cat, so the output is visible
	 * on the journal regardless of recording. */
	{
		char cmd_name[64];
		char tag[128];

		err = extract_command_name(command, cmd_name, sizeof(cmd_name));
		if (err)
			return err;
		/* Tag with the command name and where it ran, so the journal
		 * formatter shows e.g. `[bitcoin-cli [bitcoind1]] | …` or
		 * `[dummy [host]] | …`. */
		snprintf(tag, sizeof(tag), "%s [%s]", cmd_name,
			 *container ? container : "host");
		err = append_literal(cmd, cmd_cap, &off, "systemd-cat -t ");
		if (err)
			return err;
		return append_shell_quoted(cmd, cmd_cap, &off, tag);
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
	const char *container;
	const char *command;
	size_t clen;
	bool record;
	char output_path[OUTPUT_PATH_MAX];
	char *argv[4];
	int exit_code = 0;
	ssize_t data_read = 0;
	__s32 read_status = 0;
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
	 * Copy the request into local kthread storage so the lock can be
	 * dropped before the slow call_usermodehelper. That's what lets
	 * long-running guest commands overlap: many workers can be in
	 * call_usermodehelper at once, but only one holds the page mutex at
	 * any moment.
	 */
	mutex_lock(&page_mutex);
	req_len = vmcall_io_get_request();
	if (req_len == 0 || req_len == VMCALL_ERR) {
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

	record = (req_hdr.flags & IO_FLAG_RECORD_OUTPUT) != 0;

	/*
	 * Parse the payload: "<container>\0<cmd>\0". An empty container
	 * (leading NUL) means "run on the host".
	 */
	if (req_hdr.payload_len == 0) {
		pr_err("bedrock-io: worker %u: empty request payload\n", w->id);
		exit_code = -EINVAL;
		goto respond;
	}
	container = payload_copy;
	clen = strnlen(container, req_hdr.payload_len);
	if (clen == req_hdr.payload_len) {
		pr_err("bedrock-io: worker %u: unterminated container\n", w->id);
		exit_code = -EINVAL;
		goto respond;
	}
	command = container + clen + 1;
	if (strnlen(command, req_hdr.payload_len - clen - 1) ==
	    req_hdr.payload_len - clen - 1) {
		pr_err("bedrock-io: worker %u: unterminated command\n", w->id);
		exit_code = -EINVAL;
		goto respond;
	}

	/*
	 * Phase 2: build + run command (no lock held).
	 *
	 * Other workers can run their GET_REQUEST / PUT_RESPONSE during this
	 * window; the only shared state is `shared_page` / `output_buf`,
	 * which we don't touch here.
	 */
	rc = build_command(container, command, record, cmd,
			   BEDROCK_IO_PAGE_SIZE, output_path, w->id);
	if (rc) {
		pr_err("bedrock-io: worker %u: build_command failed: %d\n",
		       w->id, rc);
		exit_code = rc;
		goto respond;
	}
	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = cmd;
	argv[3] = NULL;
	/*
	 * call_usermodehelper starts the child with an empty environment by
	 * default; we mirror the PATH the initrd's init script exports so
	 * unqualified binaries resolve the same way they would from an
	 * interactive guest shell.
	 */
	exit_code = call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_PROC);
	pr_info("bedrock-io: worker %u: command finished, exit=%d\n",
		w->id, exit_code);

respond:
	/*
	 * Phase 3: page-mutexed copy-into-output-buffer + PUT_RESPONSE.
	 *
	 * For a recorded command, read the per-worker capture file straight
	 * into the shared output feedback buffer, then PUT_RESPONSE — both
	 * under `page_mutex` so a concurrent worker can't overwrite the
	 * output buffer before the host reads it at this command's
	 * (serialised) response exit. Non-recorded commands stream to
	 * journald, so `output_len` stays 0 and the buffer is untouched.
	 */
	mutex_lock(&page_mutex);
	if (got_request && record) {
		data_read = read_output_file(output_path, output_buf,
					     BEDROCK_IO_OUTPUT_SIZE);
		if (data_read < 0) {
			pr_warn("bedrock-io: read_output_file(%s) failed: %zd\n",
				output_path, data_read);
			read_status = (__s32)data_read;
			data_read = 0;
		}
	}

	resp_hdr.magic = IO_RESPONSE_MAGIC;
	resp_hdr.flags = req_hdr.flags;
	resp_hdr.status = read_status;
	resp_hdr.exit_code = (__s32)exit_code;
	resp_hdr.output_len = (__u32)data_read;
	memcpy(shared_page, &resp_hdr, sizeof(resp_hdr));

	vmcall_io_put_response(sizeof(resp_hdr));
	mutex_unlock(&page_mutex);

	/*
	 * Unlink the per-worker capture file once the response has been
	 * handed to the host. Only recorded commands write it.
	 *
	 * vfs_unlink requires the parent inode's i_rwsem held for write, so
	 * lock the parent dentry's inode before calling and unlock after.
	 */
	if (got_request && record) {
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
	 * when the page allocator can't satisfy GFP_ATOMIC, so dropping the
	 * IRQ only happens if every reserved item is already in use — a state
	 * we don't reach at realistic queue depths. The pool keeps the
	 * determinism contract: every IRQ either runs the worker or the
	 * hypervisor sees the failure via the dropped GET_REQUEST, never
	 * silently sticks.
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
	static const char output_id[] = OUTPUT_BUFFER_ID;
	__u64 rc;
	int err;

	shared_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!shared_page)
		return -ENOMEM;

	/*
	 * Output feedback buffer for recorded command output. vmalloc gives
	 * a virtually-contiguous region the hypervisor translates page by
	 * page when it reads the buffer back.
	 */
	output_buf = vzalloc(BEDROCK_IO_OUTPUT_SIZE);
	if (!output_buf) {
		free_page((unsigned long)shared_page);
		return -ENOMEM;
	}

	/*
	 * WQ_UNBOUND lets workers run on any CPU; default max_active gives us
	 * a generous concurrency budget. WQ_MEM_RECLAIM ensures forward
	 * progress under memory pressure.
	 */
	io_wq = alloc_workqueue("bedrock-io", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!io_wq) {
		vfree(output_buf);
		free_page((unsigned long)shared_page);
		return -ENOMEM;
	}

	work_pool = mempool_create_kmalloc_pool(BEDROCK_IO_WORK_POOL_MIN,
						sizeof(struct bedrock_io_work));
	if (!work_pool) {
		destroy_workqueue(io_wq);
		vfree(output_buf);
		free_page((unsigned long)shared_page);
		return -ENOMEM;
	}

	/*
	 * Register the output feedback buffer so recorded command output has
	 * somewhere to go before the first request arrives.
	 */
	rc = vmcall_register_feedback_buffer(output_buf, BEDROCK_IO_OUTPUT_SIZE,
					     output_id, sizeof(output_id) - 1);
	if (rc == VMCALL_ERR) {
		pr_err("bedrock-io: HYPERCALL_REGISTER_FEEDBACK_BUFFER failed\n");
		mempool_destroy(work_pool);
		destroy_workqueue(io_wq);
		vfree(output_buf);
		free_page((unsigned long)shared_page);
		return -EIO;
	}

	/*
	 * Register the request/response page so the hypervisor knows where to
	 * write request bytes — without this, the channel IRQ would deliver
	 * but the GET_REQUEST hypercall would fail.
	 */
	rc = vmcall_io_register_page(shared_page);
	if (rc != VMCALL_OK) {
		pr_err("bedrock-io: HYPERCALL_IO_REGISTER_PAGE failed: %#llx\n",
		       rc);
		mempool_destroy(work_pool);
		destroy_workqueue(io_wq);
		vfree(output_buf);
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
		vfree(output_buf);
		free_page((unsigned long)shared_page);
		return err;
	}

	pr_info("bedrock-io: registered page=%p output_buf=%p irq=%d (parallel workers)\n",
		shared_page, output_buf, BEDROCK_IO_IRQ);
	return 0;
}

static void __exit bedrock_io_exit(void)
{
	free_irq(BEDROCK_IO_IRQ, &worker_counter);
	/* Flush any pending workers before tearing down the workqueue, so no
	 * in-flight worker is left dereferencing the pool we're about to
	 * destroy. */
	destroy_workqueue(io_wq);
	mempool_destroy(work_pool);
	vfree(output_buf);
	free_page((unsigned long)shared_page);
}

module_init(bedrock_io_init);
module_exit(bedrock_io_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bedrock deterministic I/O channel");
