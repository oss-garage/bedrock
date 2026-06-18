// SPDX-License-Identifier: GPL-2.0
// Bedrock guest-side file downloader.
//
// Downloads one or more host-side files into the guest filesystem over the
// file-transmission hypercall (HYPERCALL_FILE_FETCH). This is how the workload's
// compose.yaml / images.tar reach the guest from the host at boot.
//
// It registers a single 1 MB buffer as a feedback buffer (under the id
// "bedrock-file-xfer") to use as the shared transport, then for each
// <name> <path> argument pair pulls the file named <name> from the host in
// chunks and writes it to <path>. The request (offset + name) and the response
// (chunk length + data) are framed inside the buffer — see libvmcall.h and
// crates/bedrock-vm/src/file_xfer.rs, which must stay in sync with this.
//
// Usage: bedrock-file-fetch <name> <path> [<name> <path> ...]
// e.g.   bedrock-file-fetch compose.yaml /workload/compose.yaml
//                           images.tar   /images/images.tar
//
// The transfer runs at boot, before the guest issues HYPERCALL_READY, so it is
// part of the deterministic boot: the host always serves identical bytes and
// the chunk boundaries are fixed by the buffer size. The buffer is held mapped
// and mlock'd for the program's whole lifetime so its guest-physical pages stay
// stable while the host writes into them.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libvmcall.h"

// 1 MB shared transport buffer — the max a single feedback buffer can be.
#define XFER_BUF_SIZE VMCALL_FEEDBACK_BUFFER_MAX_SIZE

// Download the host file named `name` into `path`, chunked through `buf`.
// Returns 0 on success, -1 on failure.
static int fetch_one(unsigned char *buf, size_t buf_size, const char *name,
		     const char *path)
{
	size_t name_len = strlen(name);
	size_t data_cap = buf_size - VMCALL_FILE_XFER_HEADER_LEN;

	if (name_len == 0 || name_len > data_cap) {
		fprintf(stderr, "file-fetch: invalid name length for '%s'\n",
			name);
		return -1;
	}

	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "file-fetch: cannot create '%s': %s\n", path,
			strerror(errno));
		return -1;
	}

	uint64_t offset = 0;
	for (;;) {
		// Frame the request at the start of the buffer: u64 offset,
		// u32 name_len, u32 reserved, then the file name. x86-64 is
		// little-endian, so a native memcpy is already LE on the wire.
		memset(buf, 0, VMCALL_FILE_XFER_HEADER_LEN);
		memcpy(buf + 0, &offset, sizeof(offset));
		uint32_t nl = (uint32_t)name_len;
		memcpy(buf + 8, &nl, sizeof(nl));
		memcpy(buf + VMCALL_FILE_XFER_HEADER_LEN, name, name_len);

		// The host reads the request out of the buffer, reads the next
		// chunk of the file, and overwrites the buffer with the response.
		vmcall_file_fetch();

		int64_t result;
		memcpy(&result, buf, sizeof(result));

		if (result == VMCALL_FILE_XFER_NOT_FOUND) {
			fprintf(stderr,
				"file-fetch: host has no file named '%s'\n",
				name);
			close(fd);
			return -1;
		}
		if (result < 0) {
			fprintf(stderr,
				"file-fetch: unexpected result %lld for '%s'\n",
				(long long)result, name);
			close(fd);
			return -1;
		}
		if (result == 0)
			break; // EOF

		size_t want = (size_t)result;
		if (want > data_cap) {
			fprintf(stderr,
				"file-fetch: host returned oversized chunk %zu for '%s'\n",
				want, name);
			close(fd);
			return -1;
		}

		size_t written = 0;
		while (written < want) {
			ssize_t w = write(
				fd, buf + VMCALL_FILE_XFER_HEADER_LEN + written,
				want - written);
			if (w < 0) {
				if (errno == EINTR)
					continue;
				fprintf(stderr,
					"file-fetch: write to '%s' failed: %s\n",
					path, strerror(errno));
				close(fd);
				return -1;
			}
			written += (size_t)w;
		}
		offset += want;
	}

	if (close(fd) != 0) {
		fprintf(stderr, "file-fetch: close '%s' failed: %s\n", path,
			strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3 || (argc - 1) % 2 != 0) {
		fprintf(stderr,
			"usage: %s <name> <path> [<name> <path> ...]\n",
			argv[0]);
		return 2;
	}

	unsigned char *buf = mmap(NULL, XFER_BUF_SIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	// Fault in and touch every page so the GVA->GPA walk the hypervisor
	// does at registration succeeds, then pin so the GPAs stay stable while
	// the host writes chunks into them.
	memset(buf, 0, XFER_BUF_SIZE);
	if (mlock(buf, XFER_BUF_SIZE) != 0) {
		perror("mlock");
		return 1;
	}

	// Stage the buffer id on the (written, resident) stack before passing it
	// to the hypervisor. The hypervisor translates the id pointer by walking
	// the guest page tables and can't fault a not-present page in. A string
	// literal lives in .rodata, and `strlen(literal)` is constant-folded at
	// -O2 — so nothing ever reads the literal and its page may never be faulted
	// in, yielding VMCALL_FB_ERR_ID_NOT_RESIDENT. Copying into a stack array we
	// then write forces that page resident.
	char id[VMCALL_FEEDBACK_BUFFER_ID_MAX_LEN];
	size_t id_len = strlen(VMCALL_FILE_XFER_BUFFER_ID);
	memcpy(id, VMCALL_FILE_XFER_BUFFER_ID, id_len);

	uint64_t slot =
		vmcall_register_feedback_buffer(buf, XFER_BUF_SIZE, id, id_len);
	// Registration returns a small slot index on success; every failure
	// code sits at the very top of the u64 range (VMCALL_FB_ERR_NO_SLOTS is
	// the smallest of them), so this comparison never rejects a real slot.
	if (slot >= VMCALL_FB_ERR_NO_SLOTS) {
		fprintf(stderr,
			"file-fetch: feedback buffer registration failed (rax=0x%llx)\n",
			(unsigned long long)slot);
		return 1;
	}

	for (int i = 1; i + 1 < argc; i += 2) {
		if (fetch_one(buf, XFER_BUF_SIZE, argv[i], argv[i + 1]) != 0)
			return 1;
		printf("file-fetch: downloaded %s -> %s\n", argv[i],
		       argv[i + 1]);
	}

	return 0;
}
