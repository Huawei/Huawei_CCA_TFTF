/*
 * Copyright (c) 2013-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <asm_macros.S>

	.section        .text, "ax"

	.macro smccc_conduit _conduit

	/*
	 * According to the AAPCS64, x8 is the indirect result location
	 * register. It contains the address of the memory block that the caller
	 * has reserved to hold the result, i.e. the smc_ret_values structure
	 * in our case.
	 * x8 might be clobbered across the SMC call so save it on the stack.
	 * Although x8 contains an 8 byte value, we are allocating 16bytes on the stack
	 * to respect 16byte stack-alignment.
	 */
	str	x8, [sp, #-16]!

	/* "Conduit" arguments are already stored in x0-x7 */
	\_conduit	#0

	/* Pop x8 into a caller-saved register */
	ldr	x9, [sp], #16

	/*
	 * Return values are stored in x0-x7, put them in the 'smc_ret_values'
	 * return structure
	 */
	stp	x0, x1, [x9, #0]
	stp	x2, x3, [x9, #16]
	stp	x4, x5, [x9, #32]
	stp	x6, x7, [x9, #48]

	.endm

/* ---------------------------------------------------------------------------
 * smc_ret_values asm_tftf_smc64(uint32_t fid,
 *				 u_register_t arg1,
 *				 u_register_t arg2,
 *				 u_register_t arg3,
 *				 u_register_t arg4,
 *				 u_register_t arg5,
 *				 u_register_t arg6,
 *				 u_register_t arg7);
 * ---------------------------------------------------------------------------
 */
	.globl	asm_tftf_smc64

func asm_tftf_smc64
	smccc_conduit smc
	ret
endfunc asm_tftf_smc64

/* ---------------------------------------------------------------------------
 * hvc_ret_values asm_tftf_hvcc64(uint32_t fid,
 *				 u_register_t arg1,
 *				 u_register_t arg2,
 *				 u_register_t arg3,
 *				 u_register_t arg4,
 *				 u_register_t arg5,
 *				 u_register_t arg6,
 *				 u_register_t arg7);
 * ---------------------------------------------------------------------------
 */
	.globl	asm_tftf_hvc64

func asm_tftf_hvc64
	smccc_conduit hvc
	ret
endfunc asm_tftf_hvc64
