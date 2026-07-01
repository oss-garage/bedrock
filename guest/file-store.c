// SPDX-License-Identifier: GPL-2.0
//
// Downloads one or more guest-side files into the host filesystem via
// HYPERCALL_FILE_STORE. This allows the host to download files that the guest
// creates.
//
// It registers a single 1 MB buffer as a feedback buffer (under the id
// "bedrock-file-store") to use as the shared transport, then for each
// <guest-path> <host-path> argument pair, the file at <guest-path> on
// the guest is written in chunks to <host-path> on the host. See
// libvmcall.h and crates/bedrock-vm/src/file_store.rs which must stay
// in sync with this. 
//
// Usage: bedrock-file-store <guest-path> <host-path> [<path> <path> ...]
// e.g.   bedrock-file-store guest-log.txt /host/guest-log-copy.txt
//
// The buffer is held mapped and mlock'd for the program's lifetime so it is
// stable while both the host and guest are reading from and writing to it.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libvmcall.h"

// Maximum-size 1 MB shared transport buffer
#define STORE_BUF_SIZE VMCALL_FEEDBACK_BUFFER_MAX_SIZE

// Download the guest file at `guest_path` into a file at `host_path` on
// the host, in buf_size chunks. Returns 0 on success, -1 on failure.
static int send_chunk(unsigned char *buf, size_t buf_size,
                      const char *guest_path, const char *host_path)
{
    size_t host_len = strlen(host_path);
    size_t chunk_cap = buf_size - VMCALL_FILE_STORE_HEADER_LEN - host_len;

    if (host_len == 0) {
            fprintf(stderr, "file-store: invalid host length for '%s'\n",
                    host_path);
            return -1;
    }

    int fd = open(guest_path, O_RDONLY);
    if (fd < 0) {
            fprintf(stderr, "file-store: cannot open '%s': %s\n", guest_path,
                    strerror(errno));
            return -1;
    }

    for (;;) {
            ssize_t n = read(fd, buf + VMCALL_FILE_STORE_HEADER_LEN + host_len, chunk_cap);
            if (n < 0) {
                    if (errno == EINTR)
                            continue;
                    close(fd);
                    return -1;
            }
            if (n == 0)
                    break; // EOF

            uint32_t hl = (uint32_t)host_len;
            uint32_t dl = (uint32_t)n;
            memcpy(buf, &hl, sizeof(hl));
            memcpy(buf + 4, &dl, sizeof(dl));
            memcpy(buf + VMCALL_FILE_STORE_HEADER_LEN, host_path, host_len);

            vmcall_file_store();

            int64_t result;
            memcpy(&result, buf, sizeof(result));
            if (result < 0) {
                    fprintf(stderr, "file-store: host failed to write chunk to '%s' failed: %s\n",
                            host_path, strerror(errno));
                    close(fd);
                    return -1;
            }
    }

    if (close(fd) != 0) {
            fprintf(stderr, "file-store: close '%s' failed: %s\n", guest_path,
                    strerror(errno));
            return -1;
    }
    return 0;
}

// Note: This is essentially identical to guest/file-fetch.c
int main(int argc, char **argv)
{
        if (argc < 3 || (argc - 1) % 2 != 0) {
                fprintf(stderr,
                        "usage: %s <guest_path> <host_path> [<guest_path> <host_path> ...]\n",
                        argv[0]);
                return 2;
        }

        unsigned char *buf = mmap(NULL, STORE_BUF_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
                perror("mmap");
                return 1;
        }

        // Fault in and touch every page so the GVA->GPA walk the hypervisor
        // does at registration succeeds, then pin so the GPAs stay stable while
        // the host writes chunks into them.
        memset(buf, 0, STORE_BUF_SIZE);
        if (mlock(buf, STORE_BUF_SIZE) != 0) {
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
        size_t id_len = strlen(VMCALL_FILE_STORE_BUFFER_ID);
        memcpy(id, VMCALL_FILE_STORE_BUFFER_ID, id_len);

        uint64_t slot =
                vmcall_register_feedback_buffer(buf, STORE_BUF_SIZE, id, id_len);
        // Errors are VMCALL_FB_ERR_NO_SLOTS and above.
        if (slot >= VMCALL_FB_ERR_NO_SLOTS) {
                fprintf(stderr,
                        "file-store: feedback buffer registration failed (rax=0x%llx)\n",
                        (unsigned long long)slot);
                return 1;
        }

        for (int i = 1; i + 1 < argc; i += 2) {
                if (send_chunk(buf, STORE_BUF_SIZE, argv[i], argv[i + 1]) != 0)
                        return 1;
                printf("file-store: downloaded %s -> %s\n", argv[i],
                       argv[i + 1]);
        }

        return 0;
}
