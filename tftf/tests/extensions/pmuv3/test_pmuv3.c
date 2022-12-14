/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch_helpers.h>
#include <arm_arch_svc.h>
#include <test_helpers.h>

/* tests target aarch64. Aarch32 is too different to even build */
#if defined(__aarch64__)

#define PMU_EVT_INST_RETIRED	0x0008
#define NOP_REPETITIONS		50
#define MAX_COUNTERS		32

static inline void read_all_counters(u_register_t *array, int impl_ev_ctrs)
{
	array[0] = read_pmccntr_el0();
	for (int i = 0; i < impl_ev_ctrs; i++) {
		array[i + 1] = read_pmevcntrn_el0(i);
	}
}

static inline void read_all_counter_configs(u_register_t *array, int impl_ev_ctrs)
{
	array[0] = read_pmccfiltr_el0();
	for (int i = 0; i < impl_ev_ctrs; i++) {
		array[i + 1] = read_pmevtypern_el0(i);
	}
}

static inline void read_all_pmu_configs(u_register_t *array)
{
	array[0] = read_pmcntenset_el0();
	array[1] = read_pmcr_el0();
	array[2] = read_pmselr_el0();
	array[3] = (IS_IN_EL2()) ? read_mdcr_el2() : 0;
}

static inline void enable_counting(void)
{
	write_pmcr_el0(read_pmcr_el0() | PMCR_EL0_E_BIT);
	/* this function means we are about to use the PMU, synchronize */
	isb();
}

static inline void disable_counting(void)
{
	write_pmcr_el0(read_pmcr_el0() & ~PMCR_EL0_E_BIT);
	/* we also rely that disabling really did work */
	isb();
}

static inline void clear_counters(void)
{
	write_pmcr_el0(read_pmcr_el0() | PMCR_EL0_C_BIT | PMCR_EL0_P_BIT);
}

/*
 * tftf runs in EL2, don't bother enabling counting at lower ELs and secure
 * world. TF-A has other controls for them and counting there doesn't impact us
 */
static inline void enable_cycle_counter(void)
{
	write_pmccfiltr_el0(PMCCFILTR_EL0_NSH_BIT);
	write_pmcntenset_el0(read_pmcntenset_el0() | PMCNTENSET_EL0_C_BIT);
}

static inline void enable_event_counter(int ctr_num)
{
	write_pmevtypern_el0(ctr_num, PMEVTYPER_EL0_NSH_BIT |
		(PMU_EVT_INST_RETIRED & PMEVTYPER_EL0_EVTCOUNT_BITS));
	write_pmcntenset_el0(read_pmcntenset_el0() |
		PMCNTENSET_EL0_P_BIT(ctr_num));
}

/* doesn't really matter what happens, as long as it happens a lot */
static inline void execute_nops(void)
{
	for (int i = 0; i < NOP_REPETITIONS; i++) {
		__asm__ ("orr x0, x0, x0\n");
	}
}

static inline void execute_el3_nop(void)
{
	/* ask EL3 for some info, no side effects */
	smc_args args = { SMCCC_VERSION };

	/* return values don't matter */
	tftf_smc(&args);
}

#endif /* defined(__aarch64__) */

/*
 * try the cycle counter with some NOPs to see if it works
 */
test_result_t test_pmuv3_cycle_works_ns(void)
{
	SKIP_TEST_IF_AARCH32();
#if defined(__aarch64__)
	u_register_t ccounter_start;
	u_register_t ccounter_end;

	SKIP_TEST_IF_PMUV3_NOT_SUPPORTED();

	enable_cycle_counter();
	enable_counting();

	ccounter_start = read_pmccntr_el0();
	execute_nops();
	ccounter_end = read_pmccntr_el0();
	disable_counting();
	clear_counters();

	tftf_testcase_printf("Counted from %ld to %ld\n",
		ccounter_start, ccounter_end);
	if (ccounter_start != ccounter_end) {
		return TEST_RESULT_SUCCESS;
	}
	return TEST_RESULT_FAIL;
#endif /* defined(__aarch64__) */
}

/*
 * try an event counter with some NOPs to see if it works. MDCR_EL2.HPMN can
 * make this tricky so take extra care.
 */
test_result_t test_pmuv3_event_works_ns(void)
{
	SKIP_TEST_IF_AARCH32();
#if defined(__aarch64__)
	u_register_t evcounter_start;
	u_register_t evcounter_end;
	u_register_t mdcr_el2 = ~0;

	SKIP_TEST_IF_PMUV3_NOT_SUPPORTED();

	/* use the real value or use the dummy value to skip checks later */
	if (IS_IN_EL2()) {
		mdcr_el2 = read_mdcr_el2();
	}

	if (((read_pmcr_el0() >> PMCR_EL0_N_SHIFT) & PMCR_EL0_N_MASK) == 0) {
		tftf_testcase_printf("No event counters implemented\n");
		return TEST_RESULT_SKIPPED;
	}

	/* FEAT_HPMN0 only affects event counters */
	if ((mdcr_el2 & MDCR_EL2_HPMN_MASK) == 0) {
		if (!get_feat_hpmn0_supported()) {
			tftf_testcase_printf(
				"FEAT_HPMN0 not implemented but HPMN is 0\n");
			return TEST_RESULT_FAIL;
		}

		/* the test will fail in this case */
		if ((mdcr_el2 & MDCR_EL2_HPME_BIT) == 0) {
			tftf_testcase_printf(
				"HPMN is 0 and HPME is not set!\n");
		}
	}

	enable_event_counter(0);
	enable_counting();

	/*
	 * if any are enabled it will be the very first one. HPME can disable
	 * the higher end of the counters and HPMN can put the boundary
	 * anywhere
	 */
	evcounter_start = read_pmevcntrn_el0(0);
	execute_nops();
	evcounter_end = read_pmevcntrn_el0(0);
	disable_counting();
	clear_counters();

	tftf_testcase_printf("Counted from %ld to %ld\n",
		evcounter_start, evcounter_end);
	if (evcounter_start != evcounter_end) {
		return TEST_RESULT_SUCCESS;
	}
	return TEST_RESULT_FAIL;
#endif /* defined(__aarch64__) */
}


/*
 * check if entering/exiting EL3 (with a NOP) preserves all PMU registers.
 */
test_result_t test_pmuv3_el3_preserves(void)
{
	SKIP_TEST_IF_AARCH32();
#if defined(__aarch64__)
	u_register_t ctr_start[MAX_COUNTERS] = {0};
	u_register_t ctr_cfg_start[MAX_COUNTERS] = {0};
	u_register_t pmu_cfg_start[4];
	u_register_t ctr_end[MAX_COUNTERS] = {0};
	u_register_t ctr_cfg_end[MAX_COUNTERS] = {0};
	u_register_t pmu_cfg_end[4];
	int impl_ev_ctrs = (read_pmcr_el0() >> PMCR_EL0_N_SHIFT) & PMCR_EL0_N_MASK;

	SKIP_TEST_IF_PMUV3_NOT_SUPPORTED();

	/* start from 0 so we know we can't overflow */
	clear_counters();
	/* pretend counters have just been used */
	enable_cycle_counter();
	enable_event_counter(0);
	enable_counting();
	execute_nops();
	disable_counting();

	/* get before reading */
	read_all_counters(ctr_start, impl_ev_ctrs);
	read_all_counter_configs(ctr_cfg_start, impl_ev_ctrs);
	read_all_pmu_configs(pmu_cfg_start);

	/* give EL3 a chance to scramble everything */
	execute_el3_nop();

	/* get after reading */
	read_all_counters(ctr_end, impl_ev_ctrs);
	read_all_counter_configs(ctr_cfg_end, impl_ev_ctrs);
	read_all_pmu_configs(pmu_cfg_end);

	if (memcmp(ctr_start, ctr_end, sizeof(ctr_start)) != 0) {
		tftf_testcase_printf("SMC call did not preserve counters\n");
		return TEST_RESULT_FAIL;
	}

	if (memcmp(ctr_cfg_start, ctr_cfg_end, sizeof(ctr_cfg_start)) != 0) {
		tftf_testcase_printf("SMC call did not preserve counter config\n");
		return TEST_RESULT_FAIL;
	}

	if (memcmp(pmu_cfg_start, pmu_cfg_end, sizeof(pmu_cfg_start)) != 0) {
		tftf_testcase_printf("SMC call did not preserve PMU registers\n");
		return TEST_RESULT_FAIL;
	}

	return TEST_RESULT_SUCCESS;
#endif /* defined(__aarch64__) */
}
