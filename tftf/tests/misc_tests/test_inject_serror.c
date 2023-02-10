/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include <arch_helpers.h>
#include <debug.h>
#include <mmio.h>
#include <tftf_lib.h>
#include <xlat_tables_v2.h>

/*
 * Purpose of this test to ensure the crash dump for lower ELs in EL3 works fine.
 *
 * This test never returns, it ends up with a crash in EL3.
 *
 * This test maps a non-existent memory as Device memory and write to it.
 * Memory is mapped as device and cause an error on bus and trap as an SError.
 * This test is used in conjunction with HANDLE_EA_EL3_FIRST_NS feature
 * (trapping EA in lower ELs to EL3) in TF-A.
 * SError caused by this error will be trapped in EL3 and eventually cause a
 * panic along with printing Crash Dump for lower EL.
 */
test_result_t test_inject_serror(void)
{
	int rc;
	const uintptr_t test_address = 0x7FFFF000;

	rc = mmap_add_dynamic_region(test_address, test_address, PAGE_SIZE,
						MT_DEVICE | MT_RW | MT_NS);
	if (rc != 0) {
		tftf_testcase_printf("%d: mapping address %lu(%d) failed\n",
				      __LINE__, test_address, rc);
		return TEST_RESULT_FAIL;
	}

	/* Try writing to invalid address */
	mmio_write_32(test_address, 1);

	/* Should not come this far */
	return TEST_RESULT_FAIL;
}
