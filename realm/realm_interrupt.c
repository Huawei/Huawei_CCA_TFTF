/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch_helpers.h>
#include <debug.h>
#include <host_realm_pmu.h>

/* Realm interrupt handler */
void realm_interrupt_handler(void)
{
	/* Read INTID and acknowledge interrupt */
	unsigned long iar1_el1 = read_icv_iar1_el1();

	/* Deactivate interrupt */
	write_icv_eoir1_el1(iar1_el1);

	/* Clear PMU interrupt */
	if (iar1_el1 == PMU_VIRQ) {
		write_pmintenclr_el1(read_pmintenset_el1());
		isb();
	} else {
		panic();
	}
}
