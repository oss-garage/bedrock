// SPDX-License-Identifier: GPL-2.0
// Integration-test workload driver: feedback-buffer round-trip.
//
// Writes the caller-supplied payload (argv[1]) into a zeroed page and
// registers it as a feedback buffer via HYPERCALL_REGISTER_FEEDBACK_BUFFER,
// so the host (bedrock-lab) can read the page back through
// Branch::feedback_buffers and confirm the bytes the test asked for survived
// the GVA->GPA translation and host mapping.
//
// Then it stays alive forever. The host reads the buffer's *live* guest-
// physical frames, so the pages must remain mapped and pinned: if this process
// exited, the guest kernel would free them and could hand the GPA the
// hypervisor recorded at registration to another allocation, leaving the host
// to read junk. mlock keeps them resident (and, in this quiescent guest,
// migration-free) so the recorded GPA keeps pointing at our payload.
//
// Launch it detached in the background: it puts itself in its own session so
// it outlives the podman-exec session that started it, and the launcher is
// expected to redirect its stdio so it doesn't hold the I/O channel's
// output-capture pipe open.

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libvmcall.h"

#define BUF_SIZE 4096u

// Identifier the host groups this registration under; mirrored by the test in
// tests/integration/feedback.rs.
static const char FB_ID[] = "bedrock-test-fb";

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload>\n", argv[0]);
        return 2;
    }
    const char *payload = argv[1];
    size_t plen = strlen(payload);
    if (plen > BUF_SIZE)
        plen = BUF_SIZE;

    // Detach into our own session so the podman-exec teardown that follows the
    // launcher's return doesn't take us down with it.
    setsid();

    void *map = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    unsigned char *buf = map;

    // Zero the whole buffer (also faults every page in before the host records
    // their GPAs at registration), then write the caller's payload at the
    // front. The host expects payload bytes followed by zero padding.
    memset(buf, 0, BUF_SIZE);
    memcpy(buf, payload, plen);

    // Pin so the pages stay resident and don't migrate to a GPA other than the
    // recorded one.
    if (mlock(buf, BUF_SIZE) != 0) {
        perror("mlock");
        return 1;
    }

    // Copy the identifier onto the stack before registering. The hypervisor
    // translates the id pointer by walking the guest page tables and rejects a
    // not-present page; a .rodata string literal we never read before the
    // hypercall may not be faulted in yet, but the stack page is live.
    char id[sizeof(FB_ID)];
    memcpy(id, FB_ID, sizeof(FB_ID));

    vmcall_u64 slot =
        vmcall_register_feedback_buffer(buf, BUF_SIZE, id, sizeof(FB_ID) - 1);
    // Errors are the high sentinels VMCALL_FB_ERR_* (down to NO_SLOTS); a valid
    // slot index is small, so anything in that band is a failure.
    if (slot >= VMCALL_FB_ERR_NO_SLOTS) {
        const char *why;
        switch (slot) {
        case VMCALL_FB_ERR_BAD_SIZE:
            why = "bad buffer size";
            break;
        case VMCALL_FB_ERR_BAD_ID_LEN:
            why = "bad id length";
            break;
        case VMCALL_FB_ERR_ID_NOT_RESIDENT:
            why = "id page not resident";
            break;
        case VMCALL_FB_ERR_BUFFER_NOT_RESIDENT:
            why = "buffer page not resident";
            break;
        case VMCALL_FB_ERR_NO_SLOTS:
            why = "no free feedback-buffer slots";
            break;
        default:
            why = "unknown error";
            break;
        }
        fprintf(stderr,
                "test_feedback_buffers: registration failed: %s (rax=0x%llx)\n",
                why, (unsigned long long)slot);
        return 1;
    }
    printf("test_feedback_buffers: registered id=%s size=%u payload_len=%zu "
           "slot=%llu\n",
           FB_ID, BUF_SIZE, plen, (unsigned long long)slot);
    fflush(stdout);

    // Stay alive forever so the buffer stays mapped and pinned for the host to
    // read. A dead driver means freed pages and a reused GPA -> junk reads.
    for (;;)
        pause();
}
