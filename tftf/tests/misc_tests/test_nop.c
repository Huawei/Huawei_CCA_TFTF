/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <power_management.h>
#include <test_helpers.h>

__attribute__((noinline))
static void debug_hook_func(void)
{
	__asm__ volatile(
		"nop\n"
		"nop\n"
		"nop\n"
		"nop\n"
		"debug_hook:\n"
		".global debug_hook\n"
		"nop\n"
		"nop\n"
		"nop\n"
		"nop\n"
	);

	return;
}

static test_result_t secondary_cpu(void)
{
	debug_hook_func();
	return TEST_RESULT_SUCCESS;
}

/*
 * This is intended for use in conjunction with Trusted Firmware eXplorer
 * (TFX).
 *
 * 1. Power up all secondary CPUs and execute test_nop.
 * 2. TFX is expected to set a breakpoint on debug_hook.  When this is hit,
 *    TFX takes over control and starts injecting test code.
 * 3. Once the test is complete, TFX powers down all CPUs.
 */
test_result_t test_nop(void)
{
	u_register_t lead_mpid, target_mpid;
	int cpu_node;
	long long ret;

	lead_mpid = read_mpidr_el1() & MPID_MASK;

	/* Start all other CPUs */
	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		ret = tftf_cpu_on(target_mpid, (uintptr_t)secondary_cpu, 0);
		if (ret != PSCI_E_SUCCESS) {
			ERROR("CPU ON failed for 0x0x%llx\n", (unsigned long long)target_mpid);
			return TEST_RESULT_FAIL;
		}
	}

	/* Do the actual work */
	debug_hook_func();

	/* Wait for other CPUs to complete */
	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		while (tftf_psci_affinity_info(target_mpid, MPIDR_AFFLVL0) != PSCI_STATE_OFF) {
			continue;
		}
	}

	return TEST_RESULT_SUCCESS;
}
