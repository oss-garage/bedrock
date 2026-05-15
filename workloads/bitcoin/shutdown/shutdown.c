// SPDX-License-Identifier: GPL-2.0
// Bedrock VM shutdown program - executes VMCALL hypercall with RAX=0

#include <stdio.h>

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
    printf("Initiating bedrock VM shutdown...\n");
    bedrock_shutdown();
    // Should not reach here
    printf("VMCALL returned unexpectedly\n");
    return 1;
}
