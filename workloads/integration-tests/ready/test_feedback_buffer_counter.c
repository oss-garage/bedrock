// SPDX-License-Identifier: GPL-2.0
// Integration-test workload driver: a feedback buffer that keeps changing.
//
// Registers a feedback buffer like test_feedback_buffers, but then bumps a
// 64-bit little-endian counter at the front of the buffer forever (one
// increment per ~1ms of guest time). This lets the host map the buffer once
// and observe *live* updates through that single mapping as the guest keeps
// running — in particular on a forked child that maps the buffer before it
// has written it, which the kernel handles by copy-on-writing the buffer's
// pages into the child at map time (see Vm::map_feedback_buffer_at).
//
// Like test_feedback_buffers it faults in and mlocks the page (so the
// recorded GPA is stable and pinned) and detaches into its own session so it
// outlives the podman-exec session that launched it.

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libvmcall.h"

#define BUF_SIZE 4096u

// Distinct id so this driver's buffer doesn't get grouped with the
// fixed-payload test_feedback_buffers driver. Mirrored by the test in
// tests/integration/feedback.rs.
static const char FB_ID[] = "bedrock-test-fb-counter";

int main(void) {
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

    // Zero the buffer (also faults the page in before the host records its GPA
    // at registration), then pin it so the page stays resident and keeps the
    // recorded GPA.
    memset(buf, 0, BUF_SIZE);
    if (mlock(buf, BUF_SIZE) != 0) {
        perror("mlock");
        return 1;
    }

    // Copy the identifier onto the live stack before registering (see the note
    // in test_feedback_buffers.c about the id pointer needing to be resident).
    char id[sizeof(FB_ID)];
    memcpy(id, FB_ID, sizeof(FB_ID));

    vmcall_u64 slot =
        vmcall_register_feedback_buffer(buf, BUF_SIZE, id, sizeof(FB_ID) - 1);
    if (slot >= VMCALL_FB_ERR_NO_SLOTS) {
        fprintf(stderr,
                "test_feedback_buffer_counter: registration failed (rax=0x%llx)\n",
                (unsigned long long)slot);
        return 1;
    }
    printf("test_feedback_buffer_counter: registered id=%s slot=%llu\n", FB_ID,
           (unsigned long long)slot);
    fflush(stdout);

    // Bump a 64-bit counter at the front of the buffer forever. The host reads
    // it back as a little-endian u64; all it asserts is that the value keeps
    // advancing while the guest runs, so the exact rate doesn't matter.
    volatile unsigned long long *counter = (volatile unsigned long long *)buf;
    for (;;) {
        (*counter)++;
        usleep(1000);
    }
}
