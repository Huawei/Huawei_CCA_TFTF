/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <debug.h>

#include <cactus_message_loop.h>
#include <cactus_test_cmds.h>
#include <ffa_helpers.h>
#include <events.h>
#include <platform.h>

/**
 * Counter of the number of handled requests, for each CPU. The number of
 * requests can be accessed from another Cactus SP, or from the normal world
 * using a special test command.
 */
static uint32_t requests_counter[PLATFORM_CORE_COUNT];

/**
 * Begin and end of command handler table, respectively. Both symbols defined by
 * the linker.
 */
extern struct cactus_cmd_handler cactus_cmd_handler_begin[];
extern struct cactus_cmd_handler cactus_cmd_handler_end[];

#define PRINT_CMD(smc_ret)						\
	VERBOSE("cmd %lx; args: %lx, %lx, %lx, %lx\n",	 		\
		smc_ret.ret3, smc_ret.ret4, smc_ret.ret5, 		\
		smc_ret.ret6, smc_ret.ret7)

/**
 * Traverses command table from section ".cactus_handler", searches for a
 * registered command and invokes the respective handler.
 */
bool cactus_handle_cmd(smc_ret_values *cmd_args, smc_ret_values *ret,
		       struct mailbox_buffers *mb)
{
	uint64_t in_cmd;

	/* Get which core it is running from. */
	unsigned int core_pos = platform_get_core_pos(
						read_mpidr_el1() & MPID_MASK);

	if (cmd_args == NULL || ret == NULL) {
		ERROR("Invalid arguments passed to %s!\n", __func__);
		return false;
	}

	PRINT_CMD((*cmd_args));

	in_cmd = cactus_get_cmd(*cmd_args);

	for (struct cactus_cmd_handler *it_cmd = cactus_cmd_handler_begin;
	     it_cmd < cactus_cmd_handler_end;
	     it_cmd++) {
		if (it_cmd->id == in_cmd) {
			*ret = it_cmd->fn(cmd_args, mb);

			/*
			 * Increment the number of requests handled in current
			 * core.
			 */
			requests_counter[core_pos]++;

			return true;
		}
	}

	/* Handle special command. */
	if (in_cmd == CACTUS_GET_REQ_COUNT_CMD) {
		uint32_t requests_counter_resp;

		/* Read value from array. */
		requests_counter_resp = requests_counter[core_pos];
		VERBOSE("Requests Counter %u, core: %u\n", requests_counter_resp,
							   core_pos);

		*ret = cactus_success_resp(
			ffa_dir_msg_dest(*cmd_args),
			ffa_dir_msg_source(*cmd_args),
			requests_counter_resp);
		return true;
	}

	*ret = cactus_error_resp(ffa_dir_msg_dest(*cmd_args),
				 ffa_dir_msg_source(*cmd_args),
				 CACTUS_ERROR_UNHANDLED);
	return true;
}
