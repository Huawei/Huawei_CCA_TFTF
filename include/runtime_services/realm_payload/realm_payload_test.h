/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <smccc.h>
#include <tftf_lib.h>
#include "rmi.h"

#define RMI_FNUM_MIN_VALUE	U(0x150)
#define RMI_FNUM_MAX_VALUE	U(0x18F)

/* Get RMI fastcall std FID from function number */
#define RMI_FID(smc_cc, func_num)			\
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT)	|	\
	((smc_cc) << FUNCID_CC_SHIFT)		|	\
	(OEN_STD_START << FUNCID_OEN_SHIFT)	|	\
	((func_num) << FUNCID_NUM_SHIFT))

/*
 * SMC_RMM_INIT_COMPLETE is the only function in the RMI that originates from
 * the Realm world and is handled by the RMMD. The remaining functions are
 * always invoked by the Normal world, forwarded by RMMD and handled by the
 * RMM
 */
#define RMI_FNUM_VERSION               U(0x150)
#define RMI_FNUM_GRANULE_DELEGATE      U(0x151)
#define RMI_FNUM_GRANULE_UNDELEGATE    U(0x152)
#define RMI_FNUM_DATA_CREATE           U(0x153)
#define RMI_FNUM_DATA_CREATE_UNKNOWN   U(0x154)
#define RMI_FNUM_DATA_DESTROY          U(0x155)
#define RMI_FNUM_DATA_DISPOSE          U(0x156)
#define RMI_FNUM_REALM_ACTIVATE        U(0x157)
#define RMI_FNUM_REALM_CREATE          U(0x158)
#define RMI_FNUM_REALM_DESTROY         U(0x159)
#define RMI_FNUM_REC_CREATE            U(0x15A)
#define RMI_FNUM_REC_DESTROY           U(0x15B)
#define RMI_FNUM_REC_ENTER             U(0x15C)
#define RMI_FNUM_RTT_CREATE            U(0x15D)
#define RMI_FNUM_RTT_DESTROY           U(0x15E)
#define RMI_FNUM_RTT_MAP_UNPROTECTED   U(0x15F)
#define RMI_FNUM_RTT_MAP_PROTECTED     U(0x160)
#define RMI_FNUM_RTT_READ_ENTRY        U(0x161)
#define RMI_FNUM_RTT_UNMAP_UNPROTECTED U(0x162)
#define RMI_FNUM_RTT_UNMAP_PROTECTED   U(0x163)
#define RMI_FNUM_PSCI_COMPLETE         U(0x164)
#define RMI_FNUM_FEATURES              U(0x165)
#define RMI_FNUM_RTT_FOLD              U(0x166)
#define RMI_FNUM_REC_AUX_COUNT         U(0x167)
#define RMI_FNUM_DATA_CREATE_LEVEL     U(0x168)
#define RMI_FNUM_DATA_CREATE_UNKNOWN_LEVEL U(0x169)
#define RMI_FNUM_DATA_DESTROY_LEVEL    U(0x16A)
#define RMI_FNUM_REQ_COMPLETE          U(0x18F)

/********************************************************************************/


/* RMI SMC64 FIDs handled by the RMMD */
#define RMI_RMM_VERSION             RMI_FID(SMC_64, RMI_FNUM_VERSION)
#define RMI_RMM_GRANULE_DELEGATE        RMI_FID(SMC_64, RMI_FNUM_GRANULE_DELEGATE)
#define RMI_RMM_GRANULE_UNDELEGATE      RMI_FID(SMC_64, RMI_FNUM_GRANULE_UNDELEGATE)
#define RMI_RMM_DATA_CREATE             RMI_FID(SMC_64, RMI_FNUM_DATA_CREATE            )
#define RMI_RMM_DATA_CREATE_UNKNOWN     RMI_FID(SMC_64, RMI_FNUM_DATA_CREATE_UNKNOWN    )
#define RMI_RMM_DATA_DESTROY            RMI_FID(SMC_64, RMI_FNUM_DATA_DESTROY           )
#define RMI_RMM_DATA_DISPOSE            RMI_FID(SMC_64, RMI_FNUM_DATA_DISPOSE           )
#define RMI_RMM_REALM_ACTIVATE          RMI_FID(SMC_64, RMI_FNUM_REALM_ACTIVATE         )
#define RMI_RMM_REALM_CREATE            RMI_FID(SMC_64, RMI_FNUM_REALM_CREATE           )
#define RMI_RMM_REALM_DESTROY           RMI_FID(SMC_64, RMI_FNUM_REALM_DESTROY          )
#define RMI_RMM_REC_CREATE              RMI_FID(SMC_64, RMI_FNUM_REC_CREATE             )
#define RMI_RMM_REC_DESTROY             RMI_FID(SMC_64, RMI_FNUM_REC_DESTROY            )
#define RMI_RMM_REC_ENTER               RMI_FID(SMC_64, RMI_FNUM_REC_ENTER              )
#define RMI_RMM_RTT_CREATE              RMI_FID(SMC_64, RMI_FNUM_RTT_CREATE             )
#define RMI_RMM_RTT_DESTROY             RMI_FID(SMC_64, RMI_FNUM_RTT_DESTROY            )
#define RMI_RMM_RTT_MAP_UNPROTECTED     RMI_FID(SMC_64, RMI_FNUM_RTT_MAP_UNPROTECTED    )
#define RMI_RMM_RTT_MAP_PROTECTED       RMI_FID(SMC_64, RMI_FNUM_RTT_MAP_PROTECTED      )
#define RMI_RMM_RTT_READ_ENTRY          RMI_FID(SMC_64, RMI_FNUM_RTT_READ_ENTRY         )
#define RMI_RMM_RTT_UNMAP_UNPROTECTED   RMI_FID(SMC_64, RMI_FNUM_RTT_UNMAP_UNPROTECTED  )
#define RMI_RMM_RTT_UNMAP_PROTECTED     RMI_FID(SMC_64, RMI_FNUM_RTT_UNMAP_PROTECTED    )
#define RMI_RMM_PSCI_COMPLETE           RMI_FID(SMC_64, RMI_FNUM_PSCI_COMPLETE          )
#define RMI_RMM_FEATURES                RMI_FID(SMC_64, RMI_FNUM_FEATURES               )
#define RMI_RMM_RTT_FOLD                RMI_FID(SMC_64, RMI_FNUM_RTT_FOLD               )
#define RMI_RMM_REC_AUX_COUNT           RMI_FID(SMC_64, RMI_FNUM_REC_AUX_COUNT          )
#define RMI_RMM_DATA_CREATE_LEVEL       RMI_FID(SMC_64, RMI_FNUM_DATA_CREATE_LEVEL      )
#define RMI_RMM_DATA_CREATE_UNKNOWN_LEVEL RMI_FID(SMC_64, RMI_FNUM_DATA_CREATE_UNKNOWN_LEVEL)
#define RMI_RMM_DATA_DESTROY_LEVEL      RMI_FID(SMC_64, RMI_FNUM_DATA_DESTROY_LEVEL     )
#define RMI_RMM_REQ_COMPLETE            RMI_FID(SMC_64, RMI_FNUM_REQ_COMPLETE)

#define RMI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> 16)
#define RMI_ABI_VERSION_GET_MINOR(_version) ((_version) & 0xFFFF)

#define NUM_GRANULES			5
#define NUM_RANDOM_ITERATIONS		7
#define GRANULE_SIZE			4096

#define B_DELEGATED			0
#define B_UNDELEGATED			1

#define NUM_CPU_DED_SPM			PLATFORM_CORE_COUNT / 2

u_register_t realm_version();
u_register_t realm_granule_delegate(u_register_t addr);
u_register_t realm_granule_undelegate(u_register_t addr);
u_register_t realm_data_create(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t src);
u_register_t realm_data_create_unknown(u_register_t data, u_register_t rd, u_register_t map_addr);
u_register_t realm_data_destroy(u_register_t rd, u_register_t map_addr);
u_register_t realm_data_dispose(u_register_t rd, u_register_t rec, u_register_t map_addr, u_register_t level);
u_register_t realm_realm_activate(u_register_t rd);
u_register_t realm_realm_create(u_register_t rd, u_register_t params_ptr);
u_register_t realm_realm_destroy(u_register_t rd);
u_register_t realm_rec_create(u_register_t rec, u_register_t rd, u_register_t mpidr, u_register_t params_ptr);
u_register_t realm_rec_destroy(u_register_t rec);
u_register_t realm_rec_enter(u_register_t rec, u_register_t run_ptr);
u_register_t realm_rtt_create(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_rtt_destroy(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_rtt_map_unprotected(u_register_t rd, u_register_t map_addr, u_register_t level, u_register_t rtte);
u_register_t realm_rtt_map_protected(u_register_t rd, u_register_t map_addr, u_register_t level);
void realm_rtt_read_entry(u_register_t *result, u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_rtt_unmap_unprotected(u_register_t rd, u_register_t map_addr, u_register_t level, u_register_t ns);
u_register_t realm_rtt_unmap_protected(u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_psci_complete(u_register_t calling_rec, u_register_t target_rec);
u_register_t realm_features(u_register_t index);
u_register_t realm_rtt_fold(u_register_t rtt, u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_rec_aux_count(u_register_t rd);
u_register_t realm_data_create_level(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t src, u_register_t level);
u_register_t realm_data_create_unknown_level(u_register_t data, u_register_t rd, u_register_t map_addr, u_register_t level);
u_register_t realm_data_destroy_level(u_register_t rd, u_register_t map_addr, u_register_t level);
