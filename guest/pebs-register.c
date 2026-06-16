// SPDX-License-Identifier: GPL-2.0
// Bedrock PEBS scratch page registration.
//
// Allocates one 4KB page, mlocks it so it stays resident at a stable guest
// physical address, and issues VMCALL with RAX=3 (HYPERCALL_REGISTER_PEBS_PAGE)
// passing the page's guest virtual address in RBX. The hypervisor walks the
// guest's page tables to translate to a GPA, populates the DS Management
// Area at that page, and remaps it R+E in EPT so subsequent PEBS record
// writes trap as precise EPT-violation VM exits. The page is never actually
// written to; we just need it to be mapped and writable in guest paging so
// the EPT layer is what produces the trap.
//
// After registration the program forks and the child sleeps forever to keep
// the mmap'd page pinned. If it ever exits the kernel reclaims the page and
// could re-allocate the underlying host-physical frame for some other use —
// which would then take a spurious (non-PEBS) EPT write trap when the
// guest kernel touches it, breaking the dispatch.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libvmcall.h"

#define PAGE_SIZE 4096

int main(void) {
    void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Touch the page so the kernel actually allocates a backing physical
    // frame and installs the PTE — without this the GVA→GPA walk in the
    // hypervisor would fault.
    memset(page, 0, PAGE_SIZE);

    // Pin the page so it can't be reclaimed / migrated to a different GPA.
    if (mlock(page, PAGE_SIZE) != 0) {
        perror("mlock");
        return 1;
    }

    printf("Registering PEBS scratch page at %p...\n", page);
    uint64_t result = vmcall_register_pebs_page(page);
    if (result == VMCALL_OK) {
        printf("PEBS scratch page registered successfully; pinning page\n");
        // Sleep forever to keep the mmap'd page pinned for the lifetime of
        // the guest. If we exited, the kernel would reclaim the page and
        // potentially re-allocate the underlying host-physical frame for
        // something else — and any write to it would then take an EPT
        // trap that's not PEBS-induced, confusing the dispatcher. Run this
        // program in the background from init so it stays alive.
        for (;;) {
            pause();
        }
    }

    // Failure codes mirror RegisterPebsPageResult in
    // crates/bedrock-vmx/src/exits/pebs.rs. Decode them for diagnostics.
    fprintf(stderr, "PEBS registration failed (rax=0x%lx): ", result);
    if (result == VMCALL_PEBS_ERR_UNSUPPORTED) {
        fprintf(stderr, "host CPU does not support EPT-friendly PEBS "
                        "(IA32_PERF_CAPABILITIES.PEBS_BASELINE clear, "
                        "or running under a hypervisor that doesn't expose "
                        "PEBS to nested guests — common with KVM L1)\n");
    } else if (result == VMCALL_PEBS_ERR_UNALIGNED) {
        fprintf(stderr, "page address not 4KB-aligned\n");
    } else if (result == VMCALL_PEBS_ERR_WALK_FAILED) {
        fprintf(stderr, "guest page-table walk failed\n");
    } else if (result == VMCALL_PEBS_ERR_NO_EPT) {
        fprintf(stderr, "EPT mapping missing — page not faulted in?\n");
    } else if (result == VMCALL_PEBS_ERR_ALREADY) {
        fprintf(stderr, "PEBS page already registered\n");
    } else {
        fprintf(stderr, "unknown error (not running in bedrock VM?)\n");
    }
    return 1;
}
