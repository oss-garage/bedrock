// SPDX-License-Identifier: GPL-2.0
// Bedrock VM helper - executes ready/shutdown VMCALL hypercalls.

#include <stdio.h>
#include <string.h>

static inline void bedrock_ready(void) {
    __asm__ volatile(
        "mov $7, %%rax\n\t"  // HYPERCALL_READY = 7
        "vmcall\n\t"
        :
        :
        : "rax"
    );
}

static inline void bedrock_shutdown(void) {
    __asm__ volatile(
        "mov $0, %%rax\n\t"  // HYPERCALL_SHUTDOWN = 0
        "vmcall\n\t"
        :
        :
        : "rax"
    );
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--ready") == 0) {
        printf("Signaling bedrock VM ready...\n");
        bedrock_ready();
        return 0;
    }

    printf("Initiating bedrock VM shutdown...\n");
    bedrock_shutdown();
    // Should not reach here
    printf("VMCALL returned unexpectedly\n");
    return 1;
}
