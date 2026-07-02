// SPDX-License-Identifier: GPL-2.0
// Bedrock VM helper - executes ready/shutdown VMCALL hypercalls.
//
//   bedrock-vmcall --ready   -> signal the VM ready (boot checkpoint)
//   bedrock-vmcall           -> shut the VM down
//
// Same shape as workloads/bitcoin/shutdown/shutdown.c; the header-only
// libvmcall.h is staged into this build context by build.sh.

#include <stdio.h>
#include <string.h>

#include "libvmcall.h"

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--ready") == 0) {
		printf("Signaling bedrock VM ready...\n");
		vmcall_ready();
		return 0;
	}

	printf("Initiating bedrock VM shutdown...\n");
	vmcall_shutdown();
	// Should not reach here
	printf("VMCALL returned unexpectedly\n");
	return 1;
}
