/*
 * Copyright (c) 2018, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <arch_helpers.h>
#include <assert.h>
#include <debug.h>
#include <events.h>
#include <irq.h>
#include <plat_topology.h>
#include <platform.h>
#include <platform_def.h>
#include <power_management.h>
#include <psci.h>
#include <sgi.h>
#include <tftf_lib.h>
#include <timer.h>

/*
 * Desired affinity level, state type (standby or powerdown), and entry time for
 * each CPU in the next CPU_SUSPEND operation. We need these shared variables
 * because there is no way to pass arguments to non-lead CPUs...
 */
static unsigned int test_aff_level[PLATFORM_CORE_COUNT];
static unsigned int test_suspend_type[PLATFORM_CORE_COUNT];
static unsigned int test_suspend_entry_time[PLATFORM_CORE_COUNT];

static event_t cpu_booted[PLATFORM_CORE_COUNT];
static event_t cpu_ready[PLATFORM_CORE_COUNT];

/*
 * Variable used by the non-lead CPUs to tell the lead CPU they
 * were woken up by IRQ_WAKE_SGI
 */
static event_t event_received_wake_irq[PLATFORM_CORE_COUNT];

/* Variable used to confirm the CPU is woken up by IRQ_WAKE_SGI or Timer IRQ */
static volatile int requested_irq_received[PLATFORM_CORE_COUNT];

static int requested_irq_handler(void *data)
{
	unsigned int core_pos = platform_get_core_pos(read_mpidr_el1());
#if ENABLE_ASSERTIONS
	unsigned int irq_id = *(unsigned int *) data;
#endif

	assert(irq_id == IRQ_WAKE_SGI || irq_id == tftf_get_timer_irq());
	assert(requested_irq_received[core_pos] == 0);

	requested_irq_received[core_pos] = 1;

	return 0;
}

static test_result_t test_init(unsigned int aff_level,
			       unsigned int suspend_type)
{
	if (aff_level > MPIDR_MAX_AFFLVL)
		return TEST_RESULT_SKIPPED;

	assert((suspend_type == PSTATE_TYPE_POWERDOWN) ||
	       (suspend_type == PSTATE_TYPE_STANDBY));

	for (unsigned int i = 0; i < PLATFORM_CORE_COUNT; ++i) {
		/* Export these variables for the non-lead CPUs */
		test_aff_level[i] = aff_level;
		test_suspend_type[i] = suspend_type;
		test_suspend_entry_time[i] =
			PLAT_SUSPEND_ENTRY_TIME * PLATFORM_CORE_COUNT;

		/*
		 * All testcases in this file use the same arrays so it needs to
		 * be re-initialised each time.
		 */
		tftf_init_event(&cpu_booted[i]);
		tftf_init_event(&cpu_ready[i]);
		tftf_init_event(&event_received_wake_irq[i]);
		requested_irq_received[i] = 0;
	}

	/* Ensure the above writes are seen before any read */
	dmbsy();

	return TEST_RESULT_SUCCESS;
}

/*
 * Suspend the calling (non-lead) CPU.
 * 1) Program a wake-up event to come out of suspend state
 * 2) Suspend the CPU to the desired affinity level and power state (standby or
 *    powerdown)
 * 3) Report success/failure of the suspend operation
 */
static test_result_t suspend_non_lead_cpu(void)
{
	unsigned int mpid = read_mpidr_el1();
	unsigned int core_pos = platform_get_core_pos(mpid);
	unsigned int aff_level = test_aff_level[core_pos];
	unsigned int suspend_type = test_suspend_type[core_pos];
	uint32_t power_state, stateid;
	int rc, expected_return_val;
	u_register_t flags;

	tftf_timer_register_handler(requested_irq_handler);

	/* Signal to the lead CPU that the calling CPU has entered the test */
	tftf_send_event(&cpu_booted[core_pos]);

	/* Wait for signal from the lead CPU before suspending itself */
	tftf_wait_for_event(&cpu_ready[core_pos]);

	/* IRQs need to be disabled prior to programming the timer */
	/* Preserve DAIF flags*/
	flags = read_daif();
	disable_irq();

	rc = tftf_program_timer(test_suspend_entry_time[core_pos]);
	if (rc != 0) {
		/* Restore previous DAIF flags */
		write_daif(flags);
		isb();
		ERROR("Timer programming failed with error %d\n", rc);
		return TEST_RESULT_FAIL;
	}

	expected_return_val = tftf_psci_make_composite_state_id(aff_level,
								suspend_type,
								&stateid);

	/*
	 * Suspend the calling CPU to the desired affinity level and power state
	 */
	power_state = tftf_make_psci_pstate(aff_level, suspend_type, stateid);
	rc = tftf_cpu_suspend(power_state);

	/* Restore previous DAIF flags */
	write_daif(flags);
	isb();

	/* Wait until the IRQ wake interrupt is received */
	while (!requested_irq_received[core_pos])
		;

	tftf_send_event(&event_received_wake_irq[core_pos]);
	tftf_timer_unregister_handler();

	if (rc == expected_return_val)
		return TEST_RESULT_SUCCESS;

	tftf_testcase_printf("Wrong value: expected %i, got %i\n",
					expected_return_val, rc);
	return TEST_RESULT_FAIL;
}

/*
 * CPU suspend test to the desired affinity level and power state
 *
 * 1) Power on all cores
 * 2) Each core registers a wake-up event to come out of suspend state
 * 3) Each core tries to enter suspend state
 *
 * The test is skipped if an error occurs during the bring-up of non-lead CPUs.
 */
static test_result_t test_psci_suspend(void)
{
	unsigned int lead_mpid = read_mpidr_el1() & MPID_MASK;
	unsigned int target_mpid, target_node;
	unsigned int core_pos;
	unsigned int aff_level, suspend_type;
	uint32_t power_state, stateid;
	int rc, expected_return_val;
	int aff_info;
	u_register_t flags;

	/*
	 * Preparation step: Power on all cores.
	 */
	for_each_cpu(target_node) {
		target_mpid = tftf_get_mpidr_from_node(target_node);
		/* Skip lead CPU as it is already on */
		if (target_mpid == lead_mpid)
			continue;

		rc = tftf_cpu_on(target_mpid,
				 (uintptr_t) suspend_non_lead_cpu,
				 0);
		if (rc != PSCI_E_SUCCESS) {
			tftf_testcase_printf(
				"Failed to power on CPU 0x%x (%d)\n",
				target_mpid, rc);
			return TEST_RESULT_SKIPPED;
		}
	}

	/* Wait for all non-lead CPUs to enter the test */
	for_each_cpu(target_node) {
		target_mpid = tftf_get_mpidr_from_node(target_node);
		/* Skip lead CPU */
		if (target_mpid == lead_mpid)
			continue;

		core_pos = platform_get_core_pos(target_mpid);
		tftf_wait_for_event(&cpu_booted[core_pos]);
	}

	/* Signal to each non-lead CPU to suspend itself */
	for_each_cpu(target_node) {
		target_mpid = tftf_get_mpidr_from_node(target_node);
		/* Skip lead CPU */
		if (target_mpid == lead_mpid)
			continue;

		core_pos = platform_get_core_pos(target_mpid);
		tftf_send_event(&cpu_ready[core_pos]);
		waitms(PLAT_SUSPEND_ENTRY_TIME);
	}

	/* IRQs need to be disabled prior to programming the timer */
	/* Preserve DAIF flags*/
	flags = read_daif();
	disable_irq();

	/*
	 * Program the timer, this will serve as the
	 * wake-up event to come out of suspend state.
	 */
	rc = tftf_program_timer(PLAT_SUSPEND_ENTRY_TIME * PLATFORM_CORE_COUNT);
	if (rc) {
		/* Restore previous DAIF flags */
		write_daif(flags);
		isb();
		ERROR("Timer programming failed with error %d\n", rc);
		return TEST_RESULT_FAIL;
	}

	core_pos = platform_get_core_pos(lead_mpid);
	aff_level = test_aff_level[core_pos];
	suspend_type = test_suspend_type[core_pos];
	expected_return_val = tftf_psci_make_composite_state_id(aff_level,
								suspend_type,
								&stateid);

	/*
	 * Suspend the calling CPU to the desired affinity level and power state
	 */
	power_state = tftf_make_psci_pstate(aff_level, suspend_type, stateid);
	if (aff_level >= PSTATE_AFF_LVL_2)
		rc = tftf_cpu_suspend_save_sys_ctx(power_state);
	else
		rc = tftf_cpu_suspend(power_state);

	/* Restore previous DAIF flags */
	write_daif(flags);
	isb();

	/*
	 * Cancel the timer set up by lead CPU in case we have returned early
	 * due to invalid parameters or it will lead to spurious wake-up later.
	 */
	tftf_cancel_timer();

	/*
	 * Wait for all non-lead CPUs to receive IRQ_WAKE_SGI. This will also
	 * ensure that the lead CPU has received the system timer IRQ
	 * because SGI #IRQ_WAKE_SGI is sent only after that.
	 */
	for_each_cpu(target_node) {
		target_mpid = tftf_get_mpidr_from_node(target_node);
		/* Skip lead CPU */
		if (target_mpid == lead_mpid)
			continue;

		core_pos = platform_get_core_pos(target_mpid);
		tftf_wait_for_event(&event_received_wake_irq[core_pos]);
	}

	/* Wait for all non-lead CPUs to power down */
	for_each_cpu(target_node) {
		target_mpid = tftf_get_mpidr_from_node(target_node);
		/* Skip lead CPU */
		if (target_mpid == lead_mpid)
			continue;

		do {
			aff_info = tftf_psci_affinity_info(target_mpid,
							   MPIDR_AFFLVL0);
		} while (aff_info != PSCI_STATE_OFF);
	}

	if (rc == expected_return_val)
		return TEST_RESULT_SUCCESS;

	tftf_testcase_printf("Wrong value: expected %i, got %i\n",
					expected_return_val, rc);
	return TEST_RESULT_FAIL;
}

/*
 * @Test_Aim@ Suspend to the specified suspend type targeted at the specified
 * affinity level
 */
static test_result_t test_psci_suspend_level(unsigned int aff_level,
					     unsigned int suspend_type)
{
	int rc;

	rc = test_init(aff_level, suspend_type);
	if (rc != TEST_RESULT_SUCCESS)
		return rc;

	return test_psci_suspend();
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 0
 */
test_result_t test_psci_suspend_powerdown_level0(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_0, PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 0
 */
test_result_t test_psci_suspend_standby_level0(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_0, PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 1
 */
test_result_t test_psci_suspend_powerdown_level1(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_1, PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 1
 */
test_result_t test_psci_suspend_standby_level1(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_1, PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 2
 */
test_result_t test_psci_suspend_powerdown_level2(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_2, PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 2
 */
test_result_t test_psci_suspend_standby_level2(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_2, PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 3
 */
test_result_t test_psci_suspend_powerdown_level3(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_3, PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 3
 */
test_result_t test_psci_suspend_standby_level3(void)
{
	return test_psci_suspend_level(PSTATE_AFF_LVL_3, PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to the specified suspend type targeted at affinity level 0
 * in OS-initiated mode
 */
static test_result_t test_psci_suspend_level0_osi(unsigned int suspend_type)
{
	int err, rc;

	err = tftf_psci_set_suspend_mode(PSCI_OS_INIT);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	rc = test_psci_suspend_level(PSTATE_AFF_LVL_0, suspend_type);

	err = tftf_psci_set_suspend_mode(PSCI_PLAT_COORD);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	return rc;
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 0 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_powerdown_level0_osi(void)
{
	return test_psci_suspend_level0_osi(PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 0 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_standby_level0_osi(void)
{
	return test_psci_suspend_level0_osi(PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to the specified suspend type targeted at affinity level 1
 * in OS-initiated mode
 */
static test_result_t test_psci_suspend_level1_osi(unsigned int suspend_type)
{
	unsigned int lead_mpid = read_mpidr_el1() & MPID_MASK;
	unsigned int lead_lvl_1_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_1);
	unsigned int target_mpid, target_node, lvl_1_node, lvl_1_end_node;
	unsigned int core_pos;
	tftf_pwr_domain_node_t pd_node;
	int err, rc;

	err = test_init(PSTATE_AFF_LVL_1, suspend_type);
	if (err != TEST_RESULT_SUCCESS)
		return err;

	err = tftf_psci_set_suspend_mode(PSCI_OS_INIT);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	for_each_power_domain_idx(lvl_1_node, PSTATE_AFF_LVL_1) {
		pd_node = tftf_pd_nodes[lvl_1_node];
		lvl_1_end_node = pd_node.cpu_start_node + pd_node.ncpus - 1;

		for_each_cpu_in_power_domain(target_node, lvl_1_node) {
			target_mpid = tftf_get_mpidr_from_node(target_node);
			/* Skip lead CPU as it is already on */
			if (target_mpid == lead_mpid)
				continue;

			core_pos = platform_get_core_pos(target_mpid);
			if (target_node == lvl_1_end_node &&
			    lvl_1_node != lead_lvl_1_node) {
				test_aff_level[core_pos] = PSTATE_AFF_LVL_1;
			} else {
				test_aff_level[core_pos] = PSTATE_AFF_LVL_0;
			}
		}
	}

	rc = test_psci_suspend();

	err = tftf_psci_set_suspend_mode(PSCI_PLAT_COORD);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	return rc;
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 1 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_powerdown_level1_osi(void)
{
	return test_psci_suspend_level1_osi(PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 1 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_standby_level1_osi(void)
{
	return test_psci_suspend_level1_osi(PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to the specified suspend type targeted at affinity level 2
 * in OS-initiated mode
 */
static test_result_t test_psci_suspend_level2_osi(unsigned int suspend_type)
{
	unsigned int lead_mpid = read_mpidr_el1() & MPID_MASK;
	unsigned int lead_lvl_1_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_1);
	unsigned int lead_lvl_2_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_2);
	unsigned int target_mpid, target_node;
	unsigned int lvl_1_node, lvl_2_node;
	unsigned int lvl_1_end_node, lvl_2_end_node;
	unsigned int core_pos;
	tftf_pwr_domain_node_t lvl_1_pd_node, lvl_2_pd_node;
	int err, rc;

	err = test_init(PSTATE_AFF_LVL_2, suspend_type);
	if (err != TEST_RESULT_SUCCESS)
		return err;

	err = tftf_psci_set_suspend_mode(PSCI_OS_INIT);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	for_each_power_domain_idx(lvl_2_node, PSTATE_AFF_LVL_2) {
		lvl_2_pd_node = tftf_pd_nodes[lvl_2_node];
		lvl_2_end_node =
			lvl_2_pd_node.cpu_start_node + lvl_2_pd_node.ncpus - 1;

		for_each_power_domain_idx(lvl_1_node, PSTATE_AFF_LVL_1) {
			lvl_1_pd_node = tftf_pd_nodes[lvl_1_node];
			if (lvl_1_pd_node.parent_node != lvl_2_node)
				continue;

			lvl_1_end_node =
				lvl_1_pd_node.cpu_start_node +
				lvl_1_pd_node.ncpus - 1;

			for_each_cpu_in_power_domain(target_node, lvl_1_node) {
				target_mpid =
					tftf_get_mpidr_from_node(target_node);
				/* Skip lead CPU as it is already on */
				if (target_mpid == lead_mpid)
					continue;

				core_pos = platform_get_core_pos(target_mpid);
				if (target_node == lvl_1_end_node &&
				    target_node == lvl_2_end_node &&
				    lvl_2_node != lead_lvl_2_node) {
					test_aff_level[core_pos] =
							PSTATE_AFF_LVL_2;
				} else if (target_node == lvl_1_end_node &&
					   lvl_1_node != lead_lvl_1_node) {
					test_aff_level[core_pos] =
							PSTATE_AFF_LVL_1;
				} else {
					test_aff_level[core_pos] =
							PSTATE_AFF_LVL_0;
				}
			}
		}

	}

	rc = test_psci_suspend();

	err = tftf_psci_set_suspend_mode(PSCI_PLAT_COORD);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	return rc;
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 2 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_powerdown_level2_osi(void)
{
	return test_psci_suspend_level2_osi(PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 2 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_standby_level2_osi(void)
{
	return test_psci_suspend_level2_osi(PSTATE_TYPE_STANDBY);
}

/*
 * @Test_Aim@ Suspend to the specified suspend type targeted at affinity level 3
 * in OS-initiated mode
 */
static test_result_t test_psci_suspend_level3_osi(unsigned int suspend_type)
{
	unsigned int lead_mpid = read_mpidr_el1() & MPID_MASK;
	unsigned int lead_lvl_1_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_1);
	unsigned int lead_lvl_2_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_2);
	unsigned int lead_lvl_3_node =
		tftf_get_parent_node_from_mpidr(lead_mpid, PSTATE_AFF_LVL_3);
	unsigned int target_mpid, target_node;
	unsigned int lvl_1_node, lvl_2_node, lvl_3_node;
	unsigned int lvl_1_end_node, lvl_2_end_node, lvl_3_end_node;
	unsigned int core_pos;
	tftf_pwr_domain_node_t lvl_1_pd_node, lvl_2_pd_node, lvl_3_pd_node;
	int err, rc;

	err = test_init(PSTATE_AFF_LVL_3, PSTATE_TYPE_POWERDOWN);
	if (err != TEST_RESULT_SUCCESS)
		return err;

	err = tftf_psci_set_suspend_mode(PSCI_OS_INIT);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	for_each_power_domain_idx(lvl_3_node, PSTATE_AFF_LVL_3) {
		lvl_3_pd_node = tftf_pd_nodes[lvl_3_node];
		lvl_3_end_node =
			lvl_3_pd_node.cpu_start_node + lvl_3_pd_node.ncpus - 1;

		for_each_power_domain_idx(lvl_2_node, PSTATE_AFF_LVL_2) {
			lvl_2_pd_node = tftf_pd_nodes[lvl_2_node];
			if (lvl_2_pd_node.parent_node != lvl_3_node)
				continue;

			lvl_2_end_node =
				lvl_2_pd_node.cpu_start_node + lvl_2_pd_node.ncpus - 1;

			for_each_power_domain_idx(lvl_1_node, PSTATE_AFF_LVL_1) {
				lvl_1_pd_node = tftf_pd_nodes[lvl_1_node];
				if (lvl_1_pd_node.parent_node != lvl_2_node)
					continue;

				lvl_1_end_node =
					lvl_1_pd_node.cpu_start_node +
					lvl_1_pd_node.ncpus - 1;

				for_each_cpu_in_power_domain(target_node, lvl_1_node) {
					target_mpid =
						tftf_get_mpidr_from_node(target_node);
					/* Skip lead CPU as it is already on */
					if (target_mpid == lead_mpid)
						continue;

					core_pos = platform_get_core_pos(target_mpid);
					if (target_node == lvl_1_end_node &&
					    target_node == lvl_2_end_node &&
					    target_node == lvl_3_end_node &&
					    lvl_3_node != lead_lvl_3_node) {
						test_aff_level[core_pos] =
								PSTATE_AFF_LVL_3;
					}
					if (target_node == lvl_1_end_node &&
					    target_node == lvl_2_end_node &&
					    lvl_2_node != lead_lvl_2_node) {
						test_aff_level[core_pos] =
								PSTATE_AFF_LVL_2;
					} else if (target_node == lvl_1_end_node &&
						   lvl_1_node != lead_lvl_1_node) {
						test_aff_level[core_pos] =
								PSTATE_AFF_LVL_1;
					} else {
						test_aff_level[core_pos] =
								PSTATE_AFF_LVL_0;
					}
				}
			}

		}
	}

	rc = test_psci_suspend();

	err = tftf_psci_set_suspend_mode(PSCI_PLAT_COORD);
	if (err != PSCI_E_SUCCESS)
		return TEST_RESULT_FAIL;

	return rc;
}

/*
 * @Test_Aim@ Suspend to powerdown state targeted at affinity level 3 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_powerdown_level3_osi(void)
{
	return test_psci_suspend_level3_osi(PSTATE_TYPE_POWERDOWN);
}

/*
 * @Test_Aim@ Suspend to standby state targeted at affinity level 3 in
 * OS-initiated mode
 */
test_result_t test_psci_suspend_standby_level3_osi(void)
{
	return test_psci_suspend_level3_osi(PSTATE_TYPE_STANDBY);
}
