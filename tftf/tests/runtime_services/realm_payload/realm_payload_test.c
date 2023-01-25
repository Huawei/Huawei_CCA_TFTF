/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <arch_features.h>
#include <plat_topology.h>
#include <power_management.h>
#include <platform.h>
#include <runtime_services/realm_payload/realm_payload_test.h>
#include <test_helpers.h>

#define DELEGATE(grn) \
	do { \
		u_register_t rmmretval = realm_granule_delegate((u_register_t)(grn)); \
		if (rmmretval) { \
			tftf_testcase_printf("Delegate " #grn " failed. errno=%lx. %s:%d\n", \
					rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define UNDELEGATE(grn) \
	do { \
		u_register_t rmmretval = realm_granule_undelegate((u_register_t)(grn)); \
		if (rmmretval) { \
			tftf_testcase_printf("Undelegating " #grn " failed. errno=%lx. %s:%d\n", \
					rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define REALM_CREATE(rd, params) \
	do { \
		u_register_t rmmretval = realm_realm_create((u_register_t)(rd), \
				(u_register_t)(params)); \
		if (rmmretval) { \
			tftf_testcase_printf("Realm Create(" #rd ", " #params \
					") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define REALM_DESTROY(rd) \
	do { \
		u_register_t rmmretval = realm_realm_destroy((u_register_t)(rd)); \
		if (rmmretval) { \
			tftf_testcase_printf("Realm destroy(" #rd ") failed. errno=%lx. %s:%d\n", \
					rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define RTT_CREATE(rtt, rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_rtt_create((u_register_t)(rtt), \
				(u_register_t)(rd), (u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("RTT Create(" #rtt ", " #rd ", " #addr \
					", " #level ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define RTT_DESTROY(rtt, rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_rtt_destroy((u_register_t)(rtt), \
				(u_register_t)(rd), (u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("RTT Destroy(" #rtt ", " #rd ", " #addr \
					", " #level ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define MAP_UNPROTECTED(rd, addr, level, rtte) \
	do { \
		u_register_t rmmretval = realm_rtt_map_unprotected((u_register_t)(rd), \
				(u_register_t)(addr), (u_register_t)(level), (u_register_t)(rtte)); \
		if (rmmretval) { \
			tftf_testcase_printf("Map Unprotected(" #rd ", " #addr ", " #level \
					", " #rtte ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define UNMAP_UNPROTECTED(rd, addr, level, ns) \
	do { \
		u_register_t rmmretval = realm_rtt_unmap_unprotected((u_register_t)(rd), \
				(u_register_t)(addr), (u_register_t)(level), (u_register_t)(ns)); \
		if (rmmretval) { \
			tftf_testcase_printf("Unmap Unprotected(" #rd ", " #addr ", " #level \
					", " #ns ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define MAP_PROTECTED(rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_rtt_map_protected((u_register_t)(rd), \
				(u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("Map protected(" #rd ", " #addr ", " #level \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define UNMAP_PROTECTED(rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_rtt_unmap_protected((u_register_t)(rd), \
				(u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("Unmap protected(" #rd ", " #addr ", " #level \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_CREATE(data, rd, addr, src) \
	do { \
		u_register_t rmmretval = realm_data_create((u_register_t)(data), \
				(u_register_t)(rd), (u_register_t)(addr), (u_register_t)(src)); \
		if (rmmretval) { \
			tftf_testcase_printf("Create data(" #data ", " #rd ", " #addr \
					", " #src ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_CREATE_UNKNOWN(data, rd, addr) \
	do { \
		u_register_t rmmretval = realm_data_create_unknown((u_register_t)(data), \
				(u_register_t)(rd), (u_register_t)(addr)); \
		if (rmmretval) { \
			tftf_testcase_printf("Create data unknown(" #data ", " #rd ", " #addr \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_DESTROY(rd, addr) \
	do { \
		u_register_t rmmretval = realm_data_destroy((u_register_t)(rd), \
				(u_register_t)(addr)); \
		if (rmmretval) { \
			tftf_testcase_printf("Destroy data(" #rd ", " #addr \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_CREATE_LEVEL(data, rd, addr, src, level) \
	do { \
		u_register_t rmmretval = realm_data_create_level((u_register_t)(data), \
				(u_register_t)(rd), (u_register_t)(addr), (u_register_t)(src), \
				(u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("Create data(" #data ", " #rd ", " #addr \
					", " #src ", " #level ") failed. errno=%lx. %s:%d\n", rmmretval, \
					__FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_CREATE_UNKNOWN_LEVEL(data, rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_data_create_unknown_level((u_register_t)(data), \
				(u_register_t)(rd), (u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("Create data unknown(" #data ", " #rd ", " #addr \
					", " #level ") failed. errno=%lx. %s:%d\n", \
					rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define DATA_DESTROY_LEVEL(rd, addr, level) \
	do { \
		u_register_t rmmretval = realm_data_destroy_level((u_register_t)(rd), \
				(u_register_t)(addr), (u_register_t)(level)); \
		if (rmmretval) { \
			tftf_testcase_printf("Destroy data(" #rd ", " #addr ", " #level \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define REC_CREATE(rec, rd, mpidr, params) \
	do { \
		u_register_t rmmretval = realm_rec_create((u_register_t)(rec), \
				(u_register_t)(rd), (u_register_t)(mpidr), (u_register_t)(params)); \
		if (rmmretval) { \
			tftf_testcase_printf("Create REC(" #rec ", " #rd ", " #mpidr ", " #params \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define REC_ENTER(rec, run) \
	do { \
		u_register_t rmmretval = realm_rec_enter((u_register_t)(rec), \
				(u_register_t)(run)); \
		if (rmmretval) { \
			tftf_testcase_printf("Enter REC(" #rec ", " #run \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

#define REC_DESTROY(rec) \
	do { \
		u_register_t rmmretval = realm_rec_destroy((u_register_t)(rec)); \
		if (rmmretval) { \
			tftf_testcase_printf("Destroy REC(" #rec \
					") failed. errno=%lx. %s:%d\n", rmmretval, __FILE__, __LINE__); \
			return TEST_RESULT_FAIL; \
		} \
	} while(false)

/* Follows the AddrIsRttLevelAligned(addr, level) definition: L3=4KB */
#define RTT_ADDR_SIZE(level) (1UL << (39 - 9 * (level)))
#define RTT_ADDR_MASK(level) (~(RTT_ADDR_SIZE(level) - 1UL))
#define RTT_MASK_L1 RTT_ADDR_MASK(1)
#define RTT_MASK_L2 RTT_ADDR_MASK(2)
#define RTT_MASK_L3 RTT_ADDR_MASK(3)
#define ESR_EC_HVC64 0x16
#define ESR_EC_SMC64 0x17
#define ESR_EC_DALOW 0x24
#define GET_ESR_EC(esr) (((esr) >> 26) & 0x3fUL)
#define GET_ESR_ISS(esr) ((esr) & 0xffffffUL)
#define ESR_ISS_SRT(esr) (((esr) >> 16) & 0x1fUL)
#define ESR_ISS_ISV_MASK (1UL << 24)
#define ESR_ISS_WNR_MASK (1UL << 6)
#define HPFAR_EL2_FIPA 0xFFFFFFFFFF0UL


extern const uint64_t __REALM_TEXT_START__;
extern const uint64_t __REALM_TEXT_END__;

static test_result_t realm_multi_cpu_payload_test(void);
static test_result_t realm_multi_cpu_payload_del_undel(void);

/* Buffer to delegate and undelegate */
static char bufferdelegate[NUM_GRANULES * GRANULE_SIZE * PLATFORM_CORE_COUNT] __aligned(GRANULE_SIZE);
static char bufferstate[NUM_GRANULES * PLATFORM_CORE_COUNT];

/*
 * Overall test for realm payload in three sections:
 * 1. Single CPU version check: SMC call to realm payload to return
 * version information
 * 2. Multi CPU version check: SMC call to realm payload to return
 * version information from all CPU's in system
 * 3. Delegate and Undelegate Non-Secure granule via
 * SMC call to realm payload
 * 4. Multi CPU delegation where random assignment of states
 * (realm, non-secure)is assigned to a set of granules.
 * Each CPU is given a number of granules to delegate in
 * parallel with the other CPU's
 * 5. Fail testing of delegation parameters such as
 * attempting to perform a delegation on the same granule
 * twice and then testing a misaligned address
 */

test_result_t init_buffer_del(void)
{
	u_register_t retrmm;

	for (int i = 0; i < (NUM_GRANULES * PLATFORM_CORE_COUNT) ; i++) {
		if ((rand() % 2) == 0) {
			retrmm = realm_granule_delegate((u_register_t)&bufferdelegate[i * GRANULE_SIZE]);
			bufferstate[i] = B_DELEGATED;
			if (retrmm != 0UL) {
				tftf_testcase_printf("Delegate operation returns fail, %lx\n", retrmm);
				return TEST_RESULT_FAIL;
			}
		} else {
			bufferstate[i] = B_UNDELEGATED;
		}
	}
	return TEST_RESULT_SUCCESS;
}

/*
 * Single CPU version check function
 */
test_result_t realm_version_single_cpu(void)
{
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	retrmm = realm_version();

	tftf_testcase_printf("RMM version is: %lu.%lu\n",
			RMI_ABI_VERSION_GET_MAJOR(retrmm),
			RMI_ABI_VERSION_GET_MINOR(retrmm));

	return TEST_RESULT_SUCCESS;
}

/*
 * Multi CPU version check function in parallel.
 */
test_result_t realm_version_multi_cpu(void)
{
	u_register_t lead_mpid, target_mpid;
	int cpu_node;
	long long ret;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	lead_mpid = read_mpidr_el1() & MPID_MASK;

	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		ret = tftf_cpu_on(target_mpid,
			(uintptr_t)realm_multi_cpu_payload_test, 0);

		if (ret != PSCI_E_SUCCESS) {
			ERROR("CPU ON failed for 0x%llx\n",
				(unsigned long long)target_mpid);
			return TEST_RESULT_FAIL;
		}

	}

	ret = realm_multi_cpu_payload_test();

	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		while (tftf_psci_affinity_info(target_mpid, MPIDR_AFFLVL0) !=
				PSCI_STATE_OFF) {
			continue;
		}
	}

	return ret;
}

/*
 * Delegate and Undelegate Non Secure Granule
 */
test_result_t realm_delegate_undelegate(void)
{
	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	DELEGATE(bufferdelegate);
	UNDELEGATE(bufferdelegate);
	tftf_testcase_printf("Delegate and undelegate of buffer 0x%lx succeeded\n",
			(uintptr_t)bufferdelegate);

	return TEST_RESULT_SUCCESS;
}

static test_result_t realm_multi_cpu_payload_test(void)
{
	u_register_t retrmm = realm_version();

	tftf_testcase_printf("Multi CPU RMM version on CPU %llx is: %lu.%lu\n",
			(long long)read_mpidr_el1() & MPID_MASK, RMI_ABI_VERSION_GET_MAJOR(retrmm),
			RMI_ABI_VERSION_GET_MINOR(retrmm));

	return TEST_RESULT_SUCCESS;
}

/*
 * Select all CPU's to randomly delegate/undelegate
 * granule pages to stress the delegate mechanism
 */
test_result_t realm_delundel_multi_cpu(void)
{
	u_register_t lead_mpid, target_mpid;
	int cpu_node;
	long long ret;
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	lead_mpid = read_mpidr_el1() & MPID_MASK;

	if (init_buffer_del() == TEST_RESULT_FAIL) {
		return TEST_RESULT_FAIL;
	}

	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		ret = tftf_cpu_on(target_mpid,
			(uintptr_t)realm_multi_cpu_payload_del_undel, 0);

		if (ret != PSCI_E_SUCCESS) {
			ERROR("CPU ON failed for 0x%llx\n",
				(unsigned long long)target_mpid);
			return TEST_RESULT_FAIL;
		}

	}

	for_each_cpu(cpu_node) {
		target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;

		if (lead_mpid == target_mpid) {
			continue;
		}

		while (tftf_psci_affinity_info(target_mpid, MPIDR_AFFLVL0) !=
				PSCI_STATE_OFF) {
			continue;
		}
	}

	/*
	 * Cleanup to set all granules back to undelegated
	 */

	for (int i = 0; i < (NUM_GRANULES * PLATFORM_CORE_COUNT) ; i++) {
		if (bufferstate[i] == B_DELEGATED) {
			retrmm = realm_granule_undelegate((u_register_t)&bufferdelegate[i * GRANULE_SIZE]);
			bufferstate[i] = B_UNDELEGATED;
			if (retrmm != 0UL) {
				tftf_testcase_printf("Delegate operation returns fail, %lx\n", retrmm);
				return TEST_RESULT_FAIL;
			}
		}
	}

	ret = TEST_RESULT_SUCCESS;
	return ret;
}

/*
 * Multi CPU testing of delegate and undelegate of granules
 * The granules are first randomly initialized to either realm or non secure
 * using the function init_buffer_del and then the function below
 * assigns NUM_GRANULES to each CPU for delegation or undelgation
 * depending upon the initial state
 */
static test_result_t realm_multi_cpu_payload_del_undel(void)
{
	u_register_t retrmm;
	unsigned int cpu_node;

	cpu_node = platform_get_core_pos(read_mpidr_el1() & MPID_MASK);

	for (int i = 0; i < NUM_GRANULES; i++) {
		if (bufferstate[((cpu_node * NUM_GRANULES) + i)] == B_UNDELEGATED) {
			retrmm = realm_granule_delegate((u_register_t)
					&bufferdelegate[((cpu_node * NUM_GRANULES) + i) * GRANULE_SIZE]);
			bufferstate[((cpu_node * NUM_GRANULES) + i)] = B_DELEGATED;
		} else {
			retrmm = realm_granule_undelegate((u_register_t)
					&bufferdelegate[((cpu_node * NUM_GRANULES) + i) * GRANULE_SIZE]);
			bufferstate[((cpu_node * NUM_GRANULES) + i)] = B_UNDELEGATED;
		}
		if (retrmm != 0UL) {
			tftf_testcase_printf("Delegate operation returns fail, %lx\n", retrmm);
			return TEST_RESULT_FAIL;
		}
	}
	return TEST_RESULT_SUCCESS;
}

/*Fail testing of delegation process. The first is an error expected
 * for processing the same granule twice and the second is submission of
 * a misaligned address
 */

test_result_t realm_fail_del(void)
{
	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	u_register_t retrmm;

	retrmm = realm_granule_delegate((u_register_t)&bufferdelegate[0]);

	if (retrmm != 0UL) {
		tftf_testcase_printf
			("Delegate operation does not pass as expected for double delegation, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	retrmm = realm_granule_delegate((u_register_t)&bufferdelegate[0]);

	if (retrmm == 0UL) {
		tftf_testcase_printf
			("Delegate operation does not fail as expected for double delegation, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	retrmm = realm_granule_undelegate((u_register_t)&bufferdelegate[1]);

	if (retrmm == 0UL) {
		tftf_testcase_printf
			("Delegate operation does not return fail for misaligned address, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	retrmm = realm_granule_undelegate((u_register_t)&bufferdelegate[0]);

	if (retrmm != 0UL) {
		tftf_testcase_printf
			("Delegate operation returns fail for cleanup, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	return TEST_RESULT_SUCCESS;
}

test_result_t realm_create_destroy (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	DELEGATE(grn_rd);
	DELEGATE(grn_rtt);

	params->par_base = 0;
	params->par_size = GRANULE_SIZE * 100;
	params->rtt_base = (uint64_t)grn_rtt;
	params->measurement_algo = 0;
	params->features_0 = 24; // 16M space
	params->rtt_level_start = 2;
	params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	REALM_DESTROY(grn_rd);

	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rtt);

	return TEST_RESULT_SUCCESS;
}

test_result_t rtt_create_destroy (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	DELEGATE(grn_rd);
	DELEGATE(grn_rtt);

	params->par_base = 0;
	params->par_size = GRANULE_SIZE * 100;
	params->rtt_base = (uint64_t)grn_rtt;
	params->measurement_algo = 0;
	params->features_0 = 37; // 128GB space
	params->rtt_level_start = 1;
	params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	/* RTT test start */
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	const uint64_t target_addr = 98765432100UL; // 98GB

	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	RTT_CREATE(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);
	RTT_CREATE(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	RTT_DESTROY(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	RTT_DESTROY(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);

	/* RTT test end */
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rtt);

	return TEST_RESULT_SUCCESS;
}

test_result_t rtt_map_unmap_ns (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt[GRANULE_SIZE*4] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U) {
		return TEST_RESULT_SKIPPED;
	}

	DELEGATE(grn_rd);
	for (int i = 0; i < 4; i ++) {
		DELEGATE(grn_rtt + GRANULE_SIZE * i);
	}

	params->par_base = 0;
	params->par_size = GRANULE_SIZE * 100;
	params->rtt_base = (uint64_t)grn_rtt;
	params->measurement_algo = 0;
	params->features_0 = 41; // 2TB space
	params->rtt_level_start = 1; // level1 = 512GB
	params->rtt_num_start = 4; // 4*512GB = 2TB
	REALM_CREATE(grn_rd, grn_params);

	static char grn_rtt21[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt22[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt31[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt32[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	const uint64_t target_addr1 =  0x1234567000UL; // 1TB
	const uint64_t target_addr2 = 0x1d345678000UL; // 2TB

	DELEGATE(grn_rtt21);
	DELEGATE(grn_rtt22);
	DELEGATE(grn_rtt31);
	DELEGATE(grn_rtt32);
	RTT_CREATE(grn_rtt21, grn_rd, target_addr1 & RTT_MASK_L1, 2);
	RTT_CREATE(grn_rtt31, grn_rd, target_addr1 & RTT_MASK_L2, 3);
	RTT_CREATE(grn_rtt22, grn_rd, target_addr2 & RTT_MASK_L1, 2);
	RTT_CREATE(grn_rtt32, grn_rd, target_addr2 & RTT_MASK_L2, 3);

	/* RTT map test 1 start: do some random mappings */
	MAP_UNPROTECTED(grn_rd, target_addr1, 3, grn_params);
	retrmm = realm_rtt_map_unprotected((u_register_t)grn_rd, (u_register_t)target_addr1, 3, (u_register_t)grn_params);
	if (retrmm == 0UL) {
		tftf_testcase_printf("map_uprotected grn_params should fail, but succeeded\n");
		return TEST_RESULT_FAIL;
	}
	MAP_UNPROTECTED(grn_rd, target_addr1 + 4096, 3, grn_params);
	retrmm = realm_rtt_destroy((u_register_t)grn_rtt31, (u_register_t)grn_rd, (u_register_t)(target_addr1 & RTT_MASK_L2), 3);
	if (retrmm == 0UL) {
		tftf_testcase_printf("destroy rtt31 should fail, but succeeded\n");
		return TEST_RESULT_FAIL;
	}

	UNMAP_UNPROTECTED(grn_rd, target_addr1, 3, grn_params);
	UNMAP_UNPROTECTED(grn_rd, target_addr1 + 4096, 3, grn_params);
	retrmm = realm_rtt_unmap_unprotected((u_register_t)grn_rd, (u_register_t)target_addr1 + 8192, 3, (u_register_t)grn_params);
	if (retrmm == 0UL) {
		tftf_testcase_printf("unmap_unprotected grn_params3 should fail, but succeeded\n");
		return TEST_RESULT_FAIL;
	}
	/* RTT map test 1 end */

	/* RTT map test 2 start: map 512 individual pages, rtt delete, unmap 1 block as a whole */
	for (int i = 0; i < 512; i ++) {
		MAP_UNPROTECTED(grn_rd, (target_addr2 & RTT_MASK_L2) + i * 4096, 3, ((uint64_t)grn_params & RTT_MASK_L2) + i * 4096);
	}
	RTT_DESTROY(grn_rtt32, grn_rd, target_addr2 & RTT_MASK_L2, 3);
	UNMAP_UNPROTECTED(grn_rd, target_addr2 & RTT_MASK_L2, 2, (uint64_t)grn_params & RTT_MASK_L2);
	/* RTT map test 2 end */

	RTT_DESTROY(grn_rtt31, grn_rd, target_addr1 & RTT_MASK_L2, 3);
	RTT_DESTROY(grn_rtt21, grn_rd, target_addr1 & RTT_MASK_L1, 2);
	RTT_DESTROY(grn_rtt22, grn_rd, target_addr2 & RTT_MASK_L1, 2);
	UNDELEGATE(grn_rtt21);
	UNDELEGATE(grn_rtt22);
	UNDELEGATE(grn_rtt31);
	UNDELEGATE(grn_rtt32);

	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	for (int i = 0; i < 4; i ++) {
		UNDELEGATE(grn_rtt + GRANULE_SIZE * i);
	}

	return TEST_RESULT_SUCCESS;
}

// TODO: move to shared header file
typedef enum rmm_rtt_entry_state {
	ES_ASSIGNED, ES_DESTROYED, ES_TABLE, ES_UNASSIGNED, ES_VALID, ES_VALID_NS
} rmm_rtt_entry_state_e;

test_result_t rtt_read (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt1[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	DELEGATE(grn_rd);
	DELEGATE(grn_rtt1);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);

	params->par_base = 0;
	params->par_size = GRANULE_SIZE * 100;
	params->rtt_base = (uint64_t)grn_rtt1;
	params->measurement_algo = 0;
	params->features_0 = 32; // 4GB space
	params->rtt_level_start = 1;
	params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	const uint64_t target_addr = 0x87654321UL;
	u_register_t read_results[4];
	RTT_CREATE(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);
	/* check test level >= rtt_level_start */
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, 0, 0);
	if (read_results[0] == 0UL) {
		tftf_testcase_printf("read_entry level 0 should fail, but succeed\n");
		return TEST_RESULT_FAIL;
	}
	/* check reading address 0 */
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, 0, 1);
	if (read_results[0] != 0UL || read_results[1] != 1 ||
			read_results[2] != ES_UNASSIGNED ||
			read_results[3] != 0) {
		tftf_testcase_printf("read_entry level 1 incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 1, %d, 0)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_UNASSIGNED);
		return TEST_RESULT_FAIL;
	}
	/* check before mapping */
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, target_addr & RTT_MASK_L2, 2);
	if (read_results[0] != 0UL || read_results[1] != 2 ||
			read_results[2] != ES_UNASSIGNED ||
			read_results[3] != 0) {
		tftf_testcase_printf("read_entry level 2 before mapping incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 2, %d, 0)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_UNASSIGNED);
		return TEST_RESULT_FAIL;
	}
	MAP_UNPROTECTED(grn_rd, target_addr & RTT_MASK_L2, 2, (u_register_t)grn_params & RTT_MASK_L2);
	/* check after mapping */
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, target_addr & RTT_MASK_L2, 2);
	if (read_results[0] != 0UL || read_results[1] != 2 ||
			read_results[2] != ES_VALID_NS ||
			read_results[3] != ((u_register_t)grn_params & RTT_MASK_L2)) {
		tftf_testcase_printf("read_entry level 2 after mapping incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 2, %d, 0x%lx)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_VALID_NS, (u_register_t)grn_params & (u_register_t)RTT_MASK_L2);
		return TEST_RESULT_FAIL;
	}

	/* do the unfolding and check the entry */
	RTT_CREATE(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, target_addr & RTT_MASK_L3, 3);
	u_register_t expected_entry = (u_register_t)grn_params & RTT_MASK_L2;
	expected_entry |= target_addr & (RTT_MASK_L3 & ~RTT_MASK_L2);
	if (read_results[0] != 0UL || read_results[1] != 3 ||
			read_results[2] != ES_VALID_NS ||
			read_results[3] != expected_entry) {
		tftf_testcase_printf("read_entry level 3 after unfolding incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 3, %d, 0x%lx)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_VALID_NS, expected_entry);
		return TEST_RESULT_FAIL;
	}

	/* let's unmap 512 pages individually */
	for (int i = 0; i < 512; i ++) {
		UNMAP_UNPROTECTED(grn_rd, (target_addr & RTT_MASK_L2) + (i << 12UL), 3, ((uint64_t)grn_params & RTT_MASK_L2) + (i << 12UL));
	}
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, target_addr & RTT_MASK_L3, 3);
	if (read_results[0] != 0UL || read_results[1] != 3 ||
			read_results[2] != ES_UNASSIGNED ||
			read_results[3] != 0UL) {
		tftf_testcase_printf("read_entry level 3 after unmapping incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 3, %d, 0)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_UNASSIGNED);
		return TEST_RESULT_FAIL;
	}
	RTT_DESTROY(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);

	/* let's do the reverse, map 512 pages individually, then unmap 2M block */
	RTT_CREATE(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	for (int i = 0; i < 512; i ++) {
		MAP_UNPROTECTED(grn_rd, (target_addr & RTT_MASK_L2) + (i << 12UL), 3, ((uint64_t)grn_params & RTT_MASK_L2) + (i << 12UL));
	}
	realm_rtt_read_entry(read_results, (u_register_t)grn_rd, target_addr & RTT_MASK_L3, 3);
	expected_entry = (u_register_t)grn_params & RTT_MASK_L2;
	expected_entry |= target_addr & (RTT_MASK_L3 & ~RTT_MASK_L2);
	if (read_results[0] != 0UL || read_results[1] != 3 ||
			read_results[2] != ES_VALID_NS ||
			read_results[3] != expected_entry) {
		tftf_testcase_printf("read_entry level 3 after unfolding incorrect: got (0x%lx, %ld, %ld, 0x%lx) expect (0, 3, %d, 0x%lx)\n",
				read_results[0], read_results[1], read_results[2], read_results[3], ES_VALID_NS, expected_entry);
		return TEST_RESULT_FAIL;
	}
	RTT_DESTROY(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	UNMAP_UNPROTECTED(grn_rd, target_addr & RTT_MASK_L2, 2, (u_register_t)grn_params & RTT_MASK_L2);

	RTT_DESTROY(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rtt1);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	return TEST_RESULT_SUCCESS;
}

test_result_t data_create_destroy (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_data[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_datau[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	DELEGATE(grn_rd);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	DELEGATE(grn_data);
	DELEGATE(grn_datau);

	params->par_base = 0;
	params->par_size = 0x20000000UL;
	params->rtt_base = (uint64_t)grn_rtt2;
	params->measurement_algo = 0;
	params->features_0 = 30; // 1GB space
	params->rtt_level_start = 2;
	params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	const uint64_t target_addr = 0x12345678UL;
	RTT_CREATE(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);

	DATA_CREATE_UNKNOWN(grn_datau, grn_rd, target_addr & RTT_MASK_L3);
	DATA_CREATE(grn_data, grn_rd, ((u_register_t)target_addr & RTT_MASK_L3) + 4096, grn_params);
	MAP_PROTECTED(grn_rd, target_addr & RTT_MASK_L3, 3);
	MAP_PROTECTED(grn_rd, (target_addr & RTT_MASK_L3) + 4096, 3);
	UNMAP_PROTECTED(grn_rd, target_addr & RTT_MASK_L3, 3);
	UNMAP_PROTECTED(grn_rd, (target_addr & RTT_MASK_L3) + 4096, 3);
	DATA_DESTROY(grn_rd, target_addr & RTT_MASK_L3);
	DATA_DESTROY(grn_rd, ((u_register_t)target_addr & RTT_MASK_L3) + 4096);

	RTT_DESTROY(grn_rtt3, grn_rd, target_addr & RTT_MASK_L2, 3);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	UNDELEGATE(grn_data);
	UNDELEGATE(grn_datau);
	return TEST_RESULT_SUCCESS;
}

test_result_t data_create_destroy_level (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt1[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE * 512] __aligned(GRANULE_SIZE * 512);
	static char grn_data[GRANULE_SIZE * 512] __aligned(GRANULE_SIZE * 512);
	static char grn_datau[GRANULE_SIZE * 512] __aligned(GRANULE_SIZE * 512);
	rmi_realm_params_t *params = (rmi_realm_params_t *)grn_params;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	DELEGATE(grn_rd);
	DELEGATE(grn_rtt1);
	DELEGATE(grn_rtt2);
	for (int i = 0; i < 512; i ++)
		DELEGATE(grn_data + GRANULE_SIZE * i);
	for (int i = 0; i < 512; i ++)
		DELEGATE(grn_datau + GRANULE_SIZE * i);

	params->par_base = 0;
	params->par_size = 0xA00000000UL;
	params->rtt_base = (uint64_t)grn_rtt1;
	params->measurement_algo = 0;
	params->features_0 = 36; // 64GB space
	params->rtt_level_start = 1;
	params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	const uint64_t target_addr = 0x987654321UL;
	RTT_CREATE(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);

	DATA_CREATE_UNKNOWN_LEVEL(grn_datau, grn_rd, target_addr & RTT_MASK_L2, 2);
	DATA_CREATE_LEVEL(grn_data, grn_rd,
			((u_register_t)target_addr & RTT_MASK_L2) + 4096 * 512, grn_params, 2);
	MAP_PROTECTED(grn_rd, target_addr & RTT_MASK_L2, 2);
	MAP_PROTECTED(grn_rd, (target_addr & RTT_MASK_L2) + 4096 * 512, 2);
	UNMAP_PROTECTED(grn_rd, target_addr & RTT_MASK_L2, 2);
	UNMAP_PROTECTED(grn_rd, (target_addr & RTT_MASK_L2) + 4096 * 512, 2);
	DATA_DESTROY_LEVEL(grn_rd, target_addr & RTT_MASK_L2, 2);
	DATA_DESTROY_LEVEL(grn_rd,
			((u_register_t)target_addr & RTT_MASK_L2) + 4096 * 512, 2);

	RTT_DESTROY(grn_rtt2, grn_rd, target_addr & RTT_MASK_L1, 2);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rtt1);
	UNDELEGATE(grn_rtt2);
	for (int i = 0; i < 512; i ++)
		UNDELEGATE(grn_data + GRANULE_SIZE * i);
	for (int i = 0; i < 512; i ++)
		UNDELEGATE(grn_datau + GRANULE_SIZE * i);
	return TEST_RESULT_SUCCESS;
}

test_result_t rec_create_destroy (void)
{
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec0[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec1[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	DELEGATE(grn_rd);
	DELEGATE(grn_rec0);
	DELEGATE(grn_rec1);
	DELEGATE(grn_rtt2);

	rmi_realm_params_t *rd_params = (rmi_realm_params_t *)grn_params;
	rd_params->par_base = 0;
	rd_params->par_size = 0x20000000UL;
	rd_params->rtt_base = (uint64_t)grn_rtt2;
	rd_params->measurement_algo = 0;
	rd_params->features_0 = 30; // 1GB space
	rd_params->rtt_level_start = 2;
	rd_params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	rmi_rec_params_t *rec_params = (rmi_rec_params_t *)grn_params;
	for (int i = 0; i < 8; i ++)
		rec_params->gprs[i] = 0;
	rec_params->pc = 0;
	rec_params->flags = 0;
	REC_CREATE(grn_rec0, grn_rd, 0, grn_params);
	retrmm = realm_rec_create((u_register_t)grn_rec0, (u_register_t)grn_rd, (u_register_t)0, (u_register_t)grn_params);
	if (retrmm == 0UL) {
		tftf_testcase_printf("rec0 create2 should fail, but succeed\n");
		return TEST_RESULT_FAIL;
	}
	retrmm = realm_rec_create((u_register_t)grn_rec1, (u_register_t)grn_rd, (u_register_t)0, (u_register_t)grn_params);
	if (retrmm == 0UL) {
		tftf_testcase_printf("rec1 create should fail, but succeed\n");
		return TEST_RESULT_FAIL;
	}
	REC_CREATE(grn_rec1, grn_rd, 1, grn_params);

	REC_DESTROY(grn_rec0);
	retrmm = realm_rec_destroy((u_register_t)grn_rec0);
	if (retrmm == 0UL) {
		tftf_testcase_printf("rec0 destroy should fail, but succeed\n");
		return TEST_RESULT_FAIL;
	}
	retrmm = realm_realm_destroy((u_register_t)grn_rd);
	if (retrmm == 0UL) {
		tftf_testcase_printf("realm destroy should fail, but succeed\n");
		return TEST_RESULT_FAIL;
	}
	REC_DESTROY(grn_rec1);

	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rec0);
	UNDELEGATE(grn_rec1);
	UNDELEGATE(grn_rtt2);
	return TEST_RESULT_SUCCESS;
}

test_result_t rec_enter (void)
{
	const uint64_t code_addr = 4096UL;
	const uint64_t data_addr = 4096UL * 10UL;
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec1[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt0[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt1[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_code[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_data[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	DELEGATE(grn_rd);
	DELEGATE(grn_rec1);
	DELEGATE(grn_rec2);
	DELEGATE(grn_rec3);
	DELEGATE(grn_rtt0);
	DELEGATE(grn_rtt1);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	DELEGATE(grn_code);
	DELEGATE(grn_data);

	rmi_realm_params_t *rd_params = (rmi_realm_params_t *)grn_params;
	rd_params->par_base = 0;
	rd_params->par_size = 0x800000000000UL;
	rd_params->rtt_base = (uint64_t)grn_rtt0;
	rd_params->measurement_algo = 0;
	rd_params->features_0 = 48; // 128TB space
	rd_params->rtt_level_start = 0;
	rd_params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	RTT_CREATE(grn_rtt1, grn_rd, 0, 1);
	RTT_CREATE(grn_rtt2, grn_rd, 0, 2);
	RTT_CREATE(grn_rtt3, grn_rd, 0, 3);
	memset(grn_params, 0, 4096);
	/* entry1: // offset=0x0
	 *   mov x9, #777
	 * loop1:
	 *   add x9, x9, x0
	 *   mov x0, x9
	 *   hvc #0
	 *   b loop1
	 * entry2: // offset=0x14
	 *   mov x10, #0xa000 // 40960
	 *   ldr x11, [x10]
	 *   add x11, x11, x0
	 *   str x11, [x10]
	 *   mov x0, x11
	 *   hvc #0
	 *   b _start2
	 * fib:
	 *   ...
	 * entry3: // offset=0x74
	 *   mov x1, #0xaff0 // 4096 * 11 - 16
	 *   mov sp, x1
	 * loop3:
	 *   bl fibo
	 *   hvc #0
	 *   b loop3 // offset=0x84
	 * */
	memcpy(grn_params,
			"\x29\x61\x80\xd2\x29\x01\x00\x8b\xe0\x03\x09\xaa\x02\x00\x00\xd4"
			"\xfd\xff\xff\x17\x0a\x00\x94\xd2\x4b\x01\x40\xf9\x6b\x01\x00\x8b"
			"\x4b\x01\x00\xf9\xe0\x03\x0b\xaa\x02\x00\x00\xd4\x00\x00\x00\x14"
			"\xfd\x7b\xbe\xa9\xfd\x03\x00\x91\xf3\x53\x01\xa9\xf3\x03\x00\xaa"
			"\x20\x01\x00\xb4\x1f\x04\x00\xf1\xe0\x00\x00\x54\x00\x04\x00\xd1"
			"\xf8\xff\xff\x97\xf4\x03\x00\xaa\x60\x0a\x00\xd1\xf5\xff\xff\x97"
			"\x93\x02\x00\x8b\xe0\x03\x13\xaa\xf3\x53\x41\xa9\xfd\x7b\xc2\xa8"
			"\xc0\x03\x5f\xd6\x01\xfe\x95\xd2\x3f\x00\x00\x91\xed\xff\xff\x97"
			"\x02\x00\x00\xd4\xfe\xff\xff\x17", 136);
	DATA_CREATE(grn_code, grn_rd, code_addr, grn_params);
	MAP_PROTECTED(grn_rd, code_addr, 3);
	memcpy(grn_params, "\x2b\x02\x00\x00\x00\x00\x00\x00", 8); // counter initial value = 555
	DATA_CREATE(grn_data, grn_rd, data_addr, grn_params);
	MAP_PROTECTED(grn_rd, data_addr, 3);

	// create 1st REC
	rmi_rec_params_t *rec_params = (rmi_rec_params_t *)grn_params;
	for (int i = 0; i < 8; i ++)
		rec_params->gprs[i] = 0;
	rec_params->pc = code_addr;
	rec_params->flags = 1;
	REC_CREATE(grn_rec1, grn_rd, 0, grn_params);
	// create 2nd REC
	rec_params->pc = code_addr + 0x14L;
	rec_params->gprs[0] = 9;
	REC_CREATE(grn_rec2, grn_rd, 1, grn_params);
	// create 3rd REC
	rec_params->pc = code_addr + 0x74L;
	rec_params->gprs[0] = 10;
	REC_CREATE(grn_rec3, grn_rd, 2, grn_params);

	retrmm = realm_realm_activate((u_register_t)grn_rd);
	if (retrmm != 0UL) {
		tftf_testcase_printf("realm activate operation returns fail, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	// test 1st REC
	rmi_rec_run_t *rec_run = (rmi_rec_run_t *)grn_params;
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	REC_ENTER(grn_rec1, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 777) {
		tftf_testcase_printf("1 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}
	// call it again
	rec_run->entry.gprs[0] = 5;
	REC_ENTER(grn_rec1, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 777 + 5) {
		tftf_testcase_printf("2 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}

	// test 2nd REC
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	REC_ENTER(grn_rec2, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 555 + 9) {
		tftf_testcase_printf("3 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}

	// test 3rd REC
	REC_ENTER(grn_rec3, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 55) { // fib(10) = 55
		tftf_testcase_printf("4 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}

	REC_DESTROY(grn_rec1);
	REC_DESTROY(grn_rec2);
	REC_DESTROY(grn_rec3);

	UNMAP_PROTECTED(grn_rd, code_addr, 3);
	UNMAP_PROTECTED(grn_rd, data_addr, 3);
	DATA_DESTROY(grn_rd, code_addr);
	DATA_DESTROY(grn_rd, data_addr);
	RTT_DESTROY(grn_rtt3, grn_rd, 0, 3);
	RTT_DESTROY(grn_rtt2, grn_rd, 0, 2);
	RTT_DESTROY(grn_rtt1, grn_rd, 0, 1);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rec1);
	UNDELEGATE(grn_rec2);
	UNDELEGATE(grn_rec3);
	UNDELEGATE(grn_rtt0);
	UNDELEGATE(grn_rtt1);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	UNDELEGATE(grn_code);
	UNDELEGATE(grn_data);
	return TEST_RESULT_SUCCESS;
}

test_result_t rec_enter_second_cpu (void)
{
	u_register_t lead_mpid, worker_mpid;
	int cpu_node;

	worker_mpid = lead_mpid = read_mpidr_el1() & MPID_MASK;
	for_each_cpu(cpu_node) {
		worker_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;
		if (lead_mpid != worker_mpid) {
			int32_t ret = tftf_cpu_on(worker_mpid, (uintptr_t)rec_enter, 0);
			if (ret != PSCI_E_SUCCESS) {
				ERROR("CPU ON failed for 0x%llx\n", (unsigned long long)worker_mpid);
				return TEST_RESULT_FAIL;
			}
			break;
		}
	}
	if (worker_mpid == lead_mpid)
		return TEST_RESULT_SKIPPED;
	while (tftf_psci_affinity_info(worker_mpid, MPIDR_AFFLVL0) != PSCI_STATE_OFF) {
		continue;
	}
	return TEST_RESULT_SUCCESS;
}

test_result_t test_testbin (void)
{
	const uint64_t CODE_ADDR = GRANULE_SIZE;
	const uint64_t BSS_ADDR = CODE_ADDR + GRANULE_SIZE;
	const uint64_t STACK_ADDR = BSS_ADDR + GRANULE_SIZE;
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_code[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_bss[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_stack[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	/* Look for the VM image tag */
	uint64_t vm_base_addr;
	for (vm_base_addr = (uint64_t)&__REALM_TEXT_START__; vm_base_addr < (uint64_t)&__REALM_TEXT_END__; vm_base_addr += 0x1000UL) {
		if (*(unsigned long *)vm_base_addr == 0x6e696274474d4956UL)
			goto found;
	}
	tftf_testcase_printf("Cannot find testbin image\n");
	return TEST_RESULT_FAIL;
found:
	//INFO("found testbin vm image at 0x%lx\n", (unsigned long)vm_base_addr);

	DELEGATE(grn_rd);
	DELEGATE(grn_rec);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	DELEGATE(grn_code);
	DELEGATE(grn_bss);
	DELEGATE(grn_stack);

	rmi_realm_params_t *rd_params = (rmi_realm_params_t *)grn_params;
	rd_params->par_base = 0;
	rd_params->par_size = 0x20000000UL;
	rd_params->rtt_base = (uint64_t)grn_rtt2;
	rd_params->measurement_algo = 0;
	rd_params->features_0 = 30; // 1GB space
	rd_params->rtt_level_start = 2;
	rd_params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	RTT_CREATE(grn_rtt3, grn_rd, 0, 3);
	memcpy(grn_params, (void *)vm_base_addr, GRANULE_SIZE);
	DATA_CREATE(grn_code, grn_rd, CODE_ADDR, grn_params);
	MAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_bss, grn_rd, BSS_ADDR);
	MAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_stack, grn_rd, STACK_ADDR);
	MAP_PROTECTED(grn_rd, STACK_ADDR, 3);

	rmi_rec_params_t *rec_params = (rmi_rec_params_t *)grn_params;
	rec_params->gprs[0] = 1;
	rec_params->gprs[1] = 3;
	rec_params->pc = CODE_ADDR + 8UL;
	rec_params->flags = 1;
	REC_CREATE(grn_rec, grn_rd, 0, grn_params);

	retrmm = realm_realm_activate((u_register_t)grn_rd);
	if (retrmm != 0UL) {
		tftf_testcase_printf("realm activate operation returns fail, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	rmi_rec_run_t *rec_run = (rmi_rec_run_t *)grn_params;
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	REC_ENTER(grn_rec, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 5) { // fibo(1+1+3) = 5
		tftf_testcase_printf("1 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}
	// call it again
	rec_run->entry.gprs[0] = 3;
	rec_run->entry.gprs[1] = 2;
	REC_ENTER(grn_rec, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64 || rec_run->exit.gprs[0] != 13) { // fibo(2+3+2) = 13
		tftf_testcase_printf("2 unexpected ESR=0x%llx, exit.gprs[0] = %llu\n",
				rec_run->exit.esr, rec_run->exit.gprs[0]);
		return TEST_RESULT_FAIL;
	}
	// unmap stack should generate data abort exception
	UNMAP_PROTECTED(grn_rd, STACK_ADDR, 3);
	rec_run->entry.gprs[0] = 3;
	rec_run->entry.gprs[1] = 2;
	REC_ENTER(grn_rec, rec_run);
	if (GET_ESR_EC(rec_run->exit.esr) != ESR_EC_DALOW ||
			(GET_ESR_ISS(rec_run->exit.esr) & 0x3f) != 7 || // DFSC=Translation fault, level 3
			((rec_run->exit.hpfar & HPFAR_EL2_FIPA) << 8) < STACK_ADDR ||
		((rec_run->exit.hpfar & HPFAR_EL2_FIPA) << 8) > STACK_ADDR + GRANULE_SIZE) {
		tftf_testcase_printf("3 unexpected ESR=0x%llx, exit.far=0x%llx, exit.hpfar=0x%llx\n",
				rec_run->exit.esr, rec_run->exit.far_, rec_run->exit.hpfar);
		return TEST_RESULT_FAIL;
	}

	REC_DESTROY(grn_rec);
	UNMAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	DATA_DESTROY(grn_rd, CODE_ADDR);
	DATA_DESTROY(grn_rd, BSS_ADDR);
	DATA_DESTROY(grn_rd, STACK_ADDR);
	RTT_DESTROY(grn_rtt3, grn_rd, 0, 3);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rec);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	UNDELEGATE(grn_code);
	UNDELEGATE(grn_bss);
	UNDELEGATE(grn_stack);
	return TEST_RESULT_SUCCESS;
}

test_result_t test_serialp (void)
{
	const uint64_t CODE_ADDR = GRANULE_SIZE;
	const uint64_t RODATA_ADDR = CODE_ADDR + GRANULE_SIZE;
	const uint64_t BSS_ADDR = RODATA_ADDR + GRANULE_SIZE;
	const uint64_t STACK_ADDR = BSS_ADDR + GRANULE_SIZE;
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rec[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_code[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rodata[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_bss[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_stack[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	/* Look for the VM image tag */
	uint64_t vm_base_addr;
	for (vm_base_addr = (uint64_t)&__REALM_TEXT_START__; vm_base_addr < (uint64_t)&__REALM_TEXT_END__; vm_base_addr += 0x1000UL) {
		if (*(unsigned long *)vm_base_addr == 0x6c726573474d4956UL)
			goto found;
	}
	tftf_testcase_printf("Cannot find serialp image\n");
	return TEST_RESULT_FAIL;
found:
	//INFO("found serialp vm image at 0x%lx\n", (unsigned long)vm_base_addr);

	DELEGATE(grn_rd);
	DELEGATE(grn_rec);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	DELEGATE(grn_code);
	DELEGATE(grn_rodata);
	DELEGATE(grn_bss);
	DELEGATE(grn_stack);

	rmi_realm_params_t *rd_params = (rmi_realm_params_t *)grn_params;
	rd_params->par_base = 0;
	rd_params->par_size = 0x20000000UL;
	rd_params->rtt_base = (uint64_t)grn_rtt2;
	rd_params->measurement_algo = 0;
	rd_params->features_0 = 30; // 1GB space
	rd_params->rtt_level_start = 2;
	rd_params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	RTT_CREATE(grn_rtt3, grn_rd, 0, 3);
	DATA_CREATE(grn_code, grn_rd, CODE_ADDR, (void *)vm_base_addr);
	MAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	DATA_CREATE(grn_rodata, grn_rd, RODATA_ADDR, (void *)(vm_base_addr + GRANULE_SIZE));
	MAP_PROTECTED(grn_rd, RODATA_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_bss, grn_rd, BSS_ADDR);
	MAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_stack, grn_rd, STACK_ADDR);
	MAP_PROTECTED(grn_rd, STACK_ADDR, 3);

	rmi_rec_params_t *rec_params = (rmi_rec_params_t *)grn_params;
	for (int i = 0; i < 8; i ++)
		rec_params->gprs[i] = 0;
	rec_params->pc = CODE_ADDR + 8UL;
	rec_params->flags = 1;
	REC_CREATE(grn_rec, grn_rd, 0, grn_params);

	retrmm = realm_realm_activate((u_register_t)grn_rd);
	if (retrmm != 0UL) {
		tftf_testcase_printf("realm activate operation returns fail, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	rmi_rec_run_t *rec_run = (rmi_rec_run_t *)grn_params;
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	char output_str[32];
	int output_str_len = 0;
	while (true) {
		REC_ENTER(grn_rec, rec_run);
		if (rec_run->exit.reason != RMI_EXIT_SYNC ||
				GET_ESR_EC(rec_run->exit.esr) != ESR_EC_HVC64) {
			tftf_testcase_printf("unexpected exit reason=%llu, esr=0x%llx\n",
					rec_run->exit.reason, rec_run->exit.esr);
			return TEST_RESULT_FAIL;
		}
		if (rec_run->exit.gprs[0] == 0)
			break;
		if (rec_run->exit.gprs[0] == 1) {
			output_str[output_str_len++] = (char)rec_run->exit.gprs[1];
			if (output_str_len > sizeof(output_str) - 2) {
				output_str[output_str_len++] = '\0';
				tftf_testcase_printf("unexpected serial print0: %s\n", output_str);
				return TEST_RESULT_FAIL;
			}
		} else {
			tftf_testcase_printf("unexpected hvc fid: %lu\n", (unsigned long)rec_run->exit.gprs[0]);
			return TEST_RESULT_FAIL;
		}
	}
	output_str[output_str_len++] = '\0';
	if (strcmp("Hello World!\n", output_str)) {
		tftf_testcase_printf("unexpected serial print1: %s\n", output_str);
		return TEST_RESULT_FAIL;
	}

	REC_DESTROY(grn_rec);
	UNMAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, RODATA_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, STACK_ADDR, 3);
	DATA_DESTROY(grn_rd, CODE_ADDR);
	DATA_DESTROY(grn_rd, RODATA_ADDR);
	DATA_DESTROY(grn_rd, BSS_ADDR);
	DATA_DESTROY(grn_rd, STACK_ADDR);
	RTT_DESTROY(grn_rtt3, grn_rd, 0, 3);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(grn_rec);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	UNDELEGATE(grn_code);
	UNDELEGATE(grn_rodata);
	UNDELEGATE(grn_bss);
	UNDELEGATE(grn_stack);
	return TEST_RESULT_SUCCESS;
}

static unsigned int test_psci_mpids[4];
static char test_psci_grn_rec[4][GRANULE_SIZE] __aligned(GRANULE_SIZE);
static char test_psci_grn_run[4][GRANULE_SIZE] __aligned(GRANULE_SIZE);

static test_result_t test_psci_thread (void)
{
	unsigned int mpidr = read_mpidr_el1() & MPID_MASK;
	int recidx;
	for (recidx = 0; recidx < 4; recidx ++)
		if (test_psci_mpids[recidx] == mpidr)
			break;
	if (recidx >= 4)
		ERROR("test_psci_thread cannot find recidx. mpidr=0x%x\n", mpidr);
	char *grn_rec = test_psci_grn_rec[recidx];

	rmi_rec_run_t *rec_run = (rmi_rec_run_t *)(test_psci_grn_run[recidx]);
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	REC_ENTER(grn_rec, rec_run);
	if (rec_run->exit.reason == RMI_EXIT_PSCI && rec_run->exit.gprs[0] == SMC_PSCI_CPU_OFF)
		return TEST_RESULT_SUCCESS;
	ERROR("test_psci_thread: unexpected exit. reason=%llu, x0=0x%llx\n",
			rec_run->exit.reason, rec_run->exit.gprs[0]);
	return TEST_RESULT_FAIL;
}

test_result_t test_psci (void)
{
	const uint64_t CODE_ADDR = GRANULE_SIZE;
	const uint64_t BSS_ADDR = CODE_ADDR + GRANULE_SIZE;
	const uint64_t DATA_ADDR = BSS_ADDR + GRANULE_SIZE;
	const uint64_t STACK_ADDR = DATA_ADDR + GRANULE_SIZE; // stack: 0x4000 ~ 0x4fff
	unsigned int cpu_node, num_mpid;
	static char grn_rd[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt2[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_rtt3[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_code[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_bss[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_data[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_stack[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	static char grn_params[GRANULE_SIZE] __aligned(GRANULE_SIZE);
	u_register_t retrmm;

	if (get_armv9_2_feat_rme_support() == 0U)
		return TEST_RESULT_SKIPPED;

	test_psci_mpids[0] = read_mpidr_el1() & MPID_MASK;
	num_mpid = 1;
	for_each_cpu(cpu_node) {
		unsigned int target_mpid = tftf_get_mpidr_from_node(cpu_node) & MPID_MASK;
		if (target_mpid == test_psci_mpids[0])
			continue;
		test_psci_mpids[num_mpid ++] = target_mpid;
		if (num_mpid >= 4)
			break;
	}
	if (num_mpid != 4)
		return TEST_RESULT_SKIPPED;

	/* Look for the VM image tag */
	uint64_t vm_base_addr;
	for (vm_base_addr = (uint64_t)&__REALM_TEXT_START__; vm_base_addr < (uint64_t)&__REALM_TEXT_END__; vm_base_addr += 0x1000UL) {
		if (*(unsigned long *)vm_base_addr == 0x69637370474d4956)
			goto found;
	}
	tftf_testcase_printf("Cannot find psci image\n");
	return TEST_RESULT_FAIL;
found:
	//INFO("found psci vm image at 0x%lx\n", (unsigned long)vm_base_addr);

	DELEGATE(grn_rd);
	DELEGATE(test_psci_grn_rec[0]);
	DELEGATE(test_psci_grn_rec[1]);
	DELEGATE(test_psci_grn_rec[2]);
	DELEGATE(test_psci_grn_rec[3]);
	DELEGATE(grn_rtt2);
	DELEGATE(grn_rtt3);
	DELEGATE(grn_code);
	DELEGATE(grn_bss);
	DELEGATE(grn_data);
	DELEGATE(grn_stack);

	rmi_realm_params_t *rd_params = (rmi_realm_params_t *)grn_params;
	rd_params->par_base = 0;
	rd_params->par_size = 0x20000000UL;
	rd_params->rtt_base = (uint64_t)grn_rtt2;
	rd_params->measurement_algo = 0;
	rd_params->features_0 = 30; // 1GB space
	rd_params->rtt_level_start = 2;
	rd_params->rtt_num_start = 1;
	REALM_CREATE(grn_rd, grn_params);

	RTT_CREATE(grn_rtt3, grn_rd, 0, 3);
	memcpy(grn_params, (void *)vm_base_addr, GRANULE_SIZE);
	DATA_CREATE(grn_code, grn_rd, CODE_ADDR, grn_params);
	MAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_bss, grn_rd, BSS_ADDR);
	MAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_data, grn_rd, DATA_ADDR);
	MAP_PROTECTED(grn_rd, DATA_ADDR, 3);
	DATA_CREATE_UNKNOWN(grn_stack, grn_rd, STACK_ADDR);
	MAP_PROTECTED(grn_rd, STACK_ADDR, 3);

	rmi_rec_params_t *rec_params = (rmi_rec_params_t *)grn_params;
	rec_params->pc = CODE_ADDR + 8UL;
	rec_params->flags = 1;
	REC_CREATE(test_psci_grn_rec[0], grn_rd, 0, grn_params);

	rec_params->pc = 0;
	rec_params->flags = 0;
	REC_CREATE(test_psci_grn_rec[1], grn_rd, 1, grn_params);
	REC_CREATE(test_psci_grn_rec[2], grn_rd, 2, grn_params);
	REC_CREATE(test_psci_grn_rec[3], grn_rd, 3, grn_params);

	retrmm = realm_realm_activate((u_register_t)grn_rd);
	if (retrmm != 0UL) {
		tftf_testcase_printf("realm activate operation returns fail, %lx\n", retrmm);
		return TEST_RESULT_FAIL;
	}

	rmi_rec_run_t *rec_run = (rmi_rec_run_t *)grn_params;
	memset(rec_run, 0, sizeof(rmi_rec_run_t));
	while (true) {
		REC_ENTER(test_psci_grn_rec[0], rec_run);
		if (rec_run->exit.reason == RMI_EXIT_PSCI) {
			if (rec_run->exit.gprs[0] == SMC_PSCI_AFFINITY_INFO) {
				unsigned int mpidr = (unsigned int)rec_run->exit.gprs[1];
				assert(mpidr >= 1 && mpidr <= 3);
				retrmm = realm_psci_complete((u_register_t)(test_psci_grn_rec[0]), (u_register_t)(test_psci_grn_rec[mpidr]));
				if (retrmm != 0UL) {
					tftf_testcase_printf("realm_psci_complete 1 failed, %lx\n", retrmm);
					return TEST_RESULT_FAIL;
				}
			} else if (rec_run->exit.gprs[0] == SMC_PSCI_CPU_ON) {
				unsigned int mpidr = (unsigned int)rec_run->exit.gprs[1];
				assert(mpidr >= 1 && mpidr <= 3);
				retrmm = realm_psci_complete((u_register_t)(test_psci_grn_rec[0]), (u_register_t)(test_psci_grn_rec[mpidr]));
				if (retrmm != 0UL) {
					tftf_testcase_printf("realm_psci_complete 2 failed, %lx\n", retrmm);
					return TEST_RESULT_FAIL;
				}

				int ret = tftf_cpu_on(test_psci_mpids[mpidr], (uintptr_t)test_psci_thread, mpidr);
				if (ret != PSCI_E_SUCCESS) {
					tftf_testcase_printf("tftf_cpu_on failed. mpidr=%u, ret=%d\n", mpidr, ret);
					return TEST_RESULT_FAIL;
				}
			} else if (rec_run->exit.gprs[0] == SMC_PSCI_CPU_OFF) {
				break;
			} else {
				tftf_testcase_printf("unexpected PSCI fid 0x%llx\n", rec_run->exit.gprs[0]);
				return TEST_RESULT_FAIL;
			}
		} else if (rec_run->exit.reason == RMI_EXIT_SYNC) {
			tftf_testcase_printf("unexpected EXIT_SYNC. esr=0x%llx, x0=0x%llx\n",
					rec_run->exit.esr, rec_run->exit.gprs[0]);
			return TEST_RESULT_FAIL;
		} else {
			tftf_testcase_printf("unexpected exit reason %llu. esr=0x%llx, x0=0x%llx\n",
					rec_run->exit.reason, rec_run->exit.esr, rec_run->exit.gprs[0]);
			return TEST_RESULT_FAIL;
		}
	}

	REC_DESTROY(test_psci_grn_rec[0]);
	REC_DESTROY(test_psci_grn_rec[1]);
	REC_DESTROY(test_psci_grn_rec[2]);
	REC_DESTROY(test_psci_grn_rec[3]);
	UNMAP_PROTECTED(grn_rd, CODE_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, BSS_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, DATA_ADDR, 3);
	UNMAP_PROTECTED(grn_rd, STACK_ADDR, 3);
	DATA_DESTROY(grn_rd, CODE_ADDR);
	DATA_DESTROY(grn_rd, BSS_ADDR);
	DATA_DESTROY(grn_rd, DATA_ADDR);
	DATA_DESTROY(grn_rd, STACK_ADDR);
	RTT_DESTROY(grn_rtt3, grn_rd, 0, 3);
	REALM_DESTROY(grn_rd);
	UNDELEGATE(grn_rd);
	UNDELEGATE(test_psci_grn_rec[0]);
	UNDELEGATE(test_psci_grn_rec[1]);
	UNDELEGATE(test_psci_grn_rec[2]);
	UNDELEGATE(test_psci_grn_rec[3]);
	UNDELEGATE(grn_rtt2);
	UNDELEGATE(grn_rtt3);
	UNDELEGATE(grn_code);
	UNDELEGATE(grn_bss);
	UNDELEGATE(grn_data);
	UNDELEGATE(grn_stack);
	return TEST_RESULT_SUCCESS;
}
