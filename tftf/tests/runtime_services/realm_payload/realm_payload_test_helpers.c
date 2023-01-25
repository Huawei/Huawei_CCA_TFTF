/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <runtime_services/realm_payload/realm_payload_test.h>

u_register_t realm_version()
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_VERSION;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_granule_delegate(u_register_t addr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_GRANULE_DELEGATE;
	args.arg1 = addr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_granule_undelegate(u_register_t addr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_GRANULE_UNDELEGATE;
	args.arg1 = addr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_create(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t src)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_CREATE;
	args.arg1 = data;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = src;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_create_unknown(u_register_t data, u_register_t rd, u_register_t map_addr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_CREATE_UNKNOWN;
	args.arg1 = data;
	args.arg2 = rd;
	args.arg3 = map_addr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_destroy(u_register_t rd, u_register_t map_addr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_DESTROY;
	args.arg1 = rd;
	args.arg2 = map_addr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_dispose(u_register_t rd, u_register_t rec, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_DISPOSE;
	args.arg1 = rd;
	args.arg2 = rec;
	args.arg3 = map_addr;
	args.arg4 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_realm_activate(u_register_t rd)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REALM_ACTIVATE;
	args.arg1 = rd;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_realm_create(u_register_t rd, u_register_t params_ptr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REALM_CREATE;
	args.arg1 = rd;
	args.arg2 = params_ptr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_realm_destroy(u_register_t rd)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REALM_DESTROY;
	args.arg1 = rd;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rec_create(u_register_t rec, u_register_t rd, u_register_t mpidr, u_register_t params_ptr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REC_CREATE;
	args.arg1 = rec;
	args.arg2 = rd;
	args.arg3 = mpidr;
	args.arg4 = params_ptr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rec_destroy(u_register_t rec)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REC_DESTROY;
	args.arg1 = rec;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rec_enter(u_register_t rec, u_register_t run_ptr)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REC_ENTER;
	args.arg1 = rec;
	args.arg2 = run_ptr;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_create(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_CREATE;
	args.arg1 = rtt;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_destroy(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_DESTROY;
	args.arg1 = rtt;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_map_unprotected(u_register_t rd, u_register_t map_addr, u_register_t level, u_register_t rtte)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_MAP_UNPROTECTED;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	args.arg4 = rtte;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_map_protected(u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_MAP_PROTECTED;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

void realm_rtt_read_entry(u_register_t *result, u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_READ_ENTRY;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	ret = tftf_smc(&args);
	result[0] = ret.ret0;
	result[1] = ret.ret1;
	result[2] = ret.ret2;
	result[3] = ret.ret3;
}

u_register_t realm_rtt_unmap_unprotected(u_register_t rd, u_register_t map_addr, u_register_t level, u_register_t ns)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_UNMAP_UNPROTECTED;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	args.arg4 = ns;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_unmap_protected(u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_UNMAP_PROTECTED;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_psci_complete(u_register_t calling_rec, u_register_t target_rec)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_PSCI_COMPLETE;
	args.arg1 = calling_rec;
	args.arg2 = target_rec;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_features(u_register_t index)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_FEATURES;
	args.arg1 = index;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rtt_fold(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_RTT_FOLD;
	args.arg1 = rtt;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_rec_aux_count(u_register_t rd)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_REC_AUX_COUNT;
	args.arg1 = rd;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_create_level(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t src, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_CREATE_LEVEL;
	args.arg1 = data;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = src;
	args.arg5 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_create_unknown_level(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_CREATE_UNKNOWN_LEVEL;
	args.arg1 = data;
	args.arg2 = rd;
	args.arg3 = map_addr;
	args.arg4 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}

u_register_t realm_data_destroy_level(u_register_t rd, u_register_t map_addr, u_register_t level)
{
	smc_args args = { 0 };
	smc_ret_values ret;
	args.fid = RMI_RMM_DATA_DESTROY_LEVEL;
	args.arg1 = rd;
	args.arg2 = map_addr;
	args.arg3 = level;
	ret = tftf_smc(&args);
	return ret.ret0;
}
