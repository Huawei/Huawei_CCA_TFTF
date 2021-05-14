/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cactus_message_loop.h"
#include "cactus_test_cmds.h"
#include <ffa_helpers.h>
#include <debug.h>


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

	if (cmd_args == NULL || ret == NULL) {
		ERROR("Invalid argumentos passed to %s!\n", __func__);
		return false;
	}

	PRINT_CMD((*cmd_args));

	in_cmd = cactus_get_cmd(*cmd_args);

	for (struct cactus_cmd_handler *it_cmd = cactus_cmd_handler_begin;
	     it_cmd < cactus_cmd_handler_end;
	     it_cmd++) {
		if (it_cmd->id == in_cmd) {
			*ret = it_cmd->fn(cmd_args, mb);
			return true;
		}
	}

	ERROR("Unhandled test command!\n");
	*ret = cactus_error_resp(ffa_dir_msg_dest(*cmd_args),
				 ffa_dir_msg_source(*cmd_args),
				 CACTUS_ERROR_UNHANDLED);
	return true;
}