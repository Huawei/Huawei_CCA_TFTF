/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef REALM_TESTS_H
#define REALM_TESTS_H

bool test_pmuv3_cycle_works_realm(void);
bool test_pmuv3_event_works_realm(void);
bool test_pmuv3_rmm_preserves(void);
bool test_pmuv3_overflow_interrupt(void);

#endif /* REALM_TESTS_H */

