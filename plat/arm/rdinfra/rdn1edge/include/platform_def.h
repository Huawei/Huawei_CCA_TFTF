/*
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_DEF_H
#define PLATFORM_DEF_H

#include <sgi_base_platform_def.h>

#define SGI_CLUSTER_COUNT		2
#define SGI_MAX_CPUS_PER_CLUSTER	4
#define SGI_MAX_PE_PER_CPU		1

/* Base address of trusted watchdog (SP805) */
#define SP805_TWDOG_BASE		0x2A480000
#define IRQ_TWDOG_INTID			86

#endif /* PLATFORM_DEF_H */
