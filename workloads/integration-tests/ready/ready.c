// SPDX-License-Identifier: GPL-2.0
// Integration-test workload helper.
//
// Issues bedrock's ready VMCALL so the lab can carve the initial
// checkpoint, then returns. The compose wrapper keeps the container (and
// thus the VM) alive afterwards with `sleep infinity`; lifetime is owned by
// the lab, which forks branches off the ready checkpoint and terminates the
// tree when the test process exits. Unlike the bitcoin workload's shutdown
// helper, this never issues the shutdown VMCALL itself.

#include <stdio.h>

#include "libvmcall.h"

int main(void) {
    printf("integration-test: signaling bedrock VM ready...\n");
    vmcall_ready();
    return 0;
}
