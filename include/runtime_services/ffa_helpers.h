/*
 * Copyright (c) 2018-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FFA_HELPERS_H
#define FFA_HELPERS_H

#include <ffa_svc.h>
#include <tftf_lib.h>
#include <utils_def.h>

/* This error code must be different to the ones used by FFA */
#define FFA_TFTF_ERROR		-42

typedef unsigned short ffa_id_t;
typedef unsigned short ffa_vm_count_t;
typedef unsigned short ffa_vcpu_count_t;
typedef uint64_t ffa_memory_handle_t;
/** Flags to indicate properties of receivers during memory region retrieval. */
typedef uint8_t ffa_memory_receiver_flags_t;

struct ffa_uuid {
	const uint32_t uuid[4];
};

#ifndef __ASSEMBLY__

#include <cassert.h>
#include <stdint.h>

/**
 * FF-A Feature ID, to be used with interface FFA_FEATURES.
 * As defined in the FF-A v1.1 Beta specification, table 13.10, in section
 * 13.2.
 */

/** Query interrupt ID of Notification Pending Interrupt. */
#define FFA_FEATURE_NPI 0x1U

/** Query interrupt ID of Schedule Receiver Interrupt. */
#define FFA_FEATURE_SRI 0x2U

/** Query interrupt ID of the Managed Exit Interrupt. */
#define FFA_FEATURE_MEI 0x3U

/** Partition property: partition supports receipt of direct requests. */
#define FFA_PARTITION_DIRECT_REQ_RECV 0x1

/** Partition property: partition can send direct requests. */
#define FFA_PARTITION_DIRECT_REQ_SEND 0x2

/** Partition property: partition can send and receive indirect messages. */
#define FFA_PARTITION_INDIRECT_MSG 0x4

/** Partition property: partition can receive notifications. */
#define FFA_PARTITION_NOTIFICATION 0x8

/**
 * Partition info descriptor as defined in Table 13.34 of the v1.1 BETA0
 * FF-A Specification
 */
struct ffa_partition_info {
	/** The ID of the VM the information is about */
	ffa_id_t id;
	/** The number of execution contexts implemented by the partition */
	uint16_t exec_context;
	/** The Partition's properties, e.g. supported messaging methods */
	uint32_t properties;
	/** The uuid of the partition */
	struct ffa_uuid uuid;
};

static inline uint32_t ffa_func_id(smc_ret_values val)
{
	return (uint32_t) val.ret0;
}

static inline int32_t ffa_error_code(smc_ret_values val)
{
	return (int32_t) val.ret2;
}

static inline ffa_id_t ffa_endpoint_id(smc_ret_values val) {
	return (ffa_id_t) val.ret2 & 0xffff;
}

static inline uint32_t ffa_feature_intid(smc_ret_values val)
{
	return (uint32_t)val.ret2;
}

typedef uint64_t ffa_notification_bitmap_t;

#define FFA_NOTIFICATION(ID)		(UINT64_C(1) << ID)

#define MAX_FFA_NOTIFICATIONS		UINT32_C(64)

#define FFA_NOTIFICATIONS_FLAG_PER_VCPU	UINT32_C(0x1 << 0)

/** Flag to delay Schedule Receiver Interrupt. */
#define FFA_NOTIFICATIONS_FLAG_DELAY_SRI	UINT32_C(0x1 << 1)

#define FFA_NOTIFICATIONS_FLAGS_VCPU_ID(id) UINT32_C((id & 0xFFFF) << 16)

#define FFA_NOTIFICATIONS_FLAG_BITMAP_SP	UINT32_C(0x1 << 0)
#define FFA_NOTIFICATIONS_FLAG_BITMAP_VM	UINT32_C(0x1 << 1)
#define FFA_NOTIFICATIONS_FLAG_BITMAP_SPM	UINT32_C(0x1 << 2)
#define FFA_NOTIFICATIONS_FLAG_BITMAP_HYP	UINT32_C(0x1 << 3)

/**
 * The following is an SGI ID, that the SPMC configures as non-secure, as
 * suggested by the FF-A v1.1 specification, in section 9.4.1.
 */
#define FFA_SCHEDULE_RECEIVER_INTERRUPT_ID 8

#define FFA_NOTIFICATIONS_BITMAP(lo, hi)	\
	(ffa_notification_bitmap_t)(lo) | 	\
	(((ffa_notification_bitmap_t)hi << 32) & 0xFFFFFFFF00000000ULL)

#define FFA_NOTIFICATIONS_FLAGS_VCPU_ID(id) UINT32_C((id & 0xFFFF) << 16)

static inline ffa_notification_bitmap_t ffa_notifications_get_from_sp(smc_ret_values val)
{
	return FFA_NOTIFICATIONS_BITMAP(val.ret2, val.ret3);
}

static inline ffa_notification_bitmap_t ffa_notifications_get_from_vm(smc_ret_values val)
{
	return FFA_NOTIFICATIONS_BITMAP(val.ret4, val.ret5);
}

/*
 * FFA_NOTIFICATION_INFO_GET is a SMC64 interface.
 * The following macros are defined for SMC64 implementation.
 */
#define FFA_NOTIFICATIONS_INFO_GET_MAX_IDS		20U

#define FFA_NOTIFICATIONS_INFO_GET_FLAG_MORE_PENDING	UINT64_C(0x1)

#define FFA_NOTIFICATIONS_LISTS_COUNT_SHIFT		0x7U
#define FFA_NOTIFICATIONS_LISTS_COUNT_MASK		0x1FU
#define FFA_NOTIFICATIONS_LIST_SHIFT(l) 		(2 * (l - 1) + 12)
#define FFA_NOTIFICATIONS_LIST_SIZE_MASK 		0x3U

static inline uint32_t ffa_notifications_info_get_lists_count(
	smc_ret_values ret)
{
	return (uint32_t)(ret.ret2 >> FFA_NOTIFICATIONS_LISTS_COUNT_SHIFT)
	       & FFA_NOTIFICATIONS_LISTS_COUNT_MASK;
}

static inline uint32_t ffa_notifications_info_get_list_size(
	smc_ret_values ret, uint32_t list)
{
	return (uint32_t)(ret.ret2 >> FFA_NOTIFICATIONS_LIST_SHIFT(list)) &
	       FFA_NOTIFICATIONS_LIST_SIZE_MASK;
}

static inline bool ffa_notifications_info_get_more_pending(smc_ret_values ret)
{
	return (ret.ret2 & FFA_NOTIFICATIONS_INFO_GET_FLAG_MORE_PENDING) != 0U;
}

enum ffa_data_access {
	FFA_DATA_ACCESS_NOT_SPECIFIED,
	FFA_DATA_ACCESS_RO,
	FFA_DATA_ACCESS_RW,
	FFA_DATA_ACCESS_RESERVED,
};

enum ffa_instruction_access {
	FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
	FFA_INSTRUCTION_ACCESS_NX,
	FFA_INSTRUCTION_ACCESS_X,
	FFA_INSTRUCTION_ACCESS_RESERVED,
};

enum ffa_memory_type {
	FFA_MEMORY_NOT_SPECIFIED_MEM,
	FFA_MEMORY_DEVICE_MEM,
	FFA_MEMORY_NORMAL_MEM,
};

enum ffa_memory_cacheability {
	FFA_MEMORY_CACHE_RESERVED = 0x0,
	FFA_MEMORY_CACHE_NON_CACHEABLE = 0x1,
	FFA_MEMORY_CACHE_RESERVED_1 = 0x2,
	FFA_MEMORY_CACHE_WRITE_BACK = 0x3,
	FFA_MEMORY_DEV_NGNRNE = 0x0,
	FFA_MEMORY_DEV_NGNRE = 0x1,
	FFA_MEMORY_DEV_NGRE = 0x2,
	FFA_MEMORY_DEV_GRE = 0x3,
};

enum ffa_memory_shareability {
	FFA_MEMORY_SHARE_NON_SHAREABLE,
	FFA_MEMORY_SHARE_RESERVED,
	FFA_MEMORY_OUTER_SHAREABLE,
	FFA_MEMORY_INNER_SHAREABLE,
};

typedef uint8_t ffa_memory_access_permissions_t;

/**
 * This corresponds to table "Memory region attributes descriptor" of the FF-A
 * 1.0 specification.
 */
typedef uint8_t ffa_memory_attributes_t;

#define FFA_DATA_ACCESS_OFFSET (0x0U)
#define FFA_DATA_ACCESS_MASK ((0x3U) << FFA_DATA_ACCESS_OFFSET)

#define FFA_INSTRUCTION_ACCESS_OFFSET (0x2U)
#define FFA_INSTRUCTION_ACCESS_MASK ((0x3U) << FFA_INSTRUCTION_ACCESS_OFFSET)

#define FFA_MEMORY_TYPE_OFFSET (0x4U)
#define FFA_MEMORY_TYPE_MASK ((0x3U) << FFA_MEMORY_TYPE_OFFSET)

#define FFA_MEMORY_CACHEABILITY_OFFSET (0x2U)
#define FFA_MEMORY_CACHEABILITY_MASK ((0x3U) << FFA_MEMORY_CACHEABILITY_OFFSET)

#define FFA_MEMORY_SHAREABILITY_OFFSET (0x0U)
#define FFA_MEMORY_SHAREABILITY_MASK ((0x3U) << FFA_MEMORY_SHAREABILITY_OFFSET)

#define ATTR_FUNCTION_SET(name, container_type, offset, mask)                \
	static inline void ffa_set_##name##_attr(container_type *attr,       \
						 const enum ffa_##name perm) \
	{                                                                    \
		*attr = (*attr & ~(mask)) | ((perm << offset) & mask);       \
	}

#define ATTR_FUNCTION_GET(name, container_type, offset, mask)      \
	static inline enum ffa_##name ffa_get_##name##_attr(       \
		container_type attr)                               \
	{                                                          \
		return (enum ffa_##name)((attr & mask) >> offset); \
	}

ATTR_FUNCTION_SET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)
ATTR_FUNCTION_GET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)

ATTR_FUNCTION_SET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)
ATTR_FUNCTION_GET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)

ATTR_FUNCTION_SET(memory_type, ffa_memory_attributes_t, FFA_MEMORY_TYPE_OFFSET,
		  FFA_MEMORY_TYPE_MASK)
ATTR_FUNCTION_GET(memory_type, ffa_memory_attributes_t, FFA_MEMORY_TYPE_OFFSET,
		  FFA_MEMORY_TYPE_MASK)

ATTR_FUNCTION_SET(memory_cacheability, ffa_memory_attributes_t,
		  FFA_MEMORY_CACHEABILITY_OFFSET, FFA_MEMORY_CACHEABILITY_MASK)
ATTR_FUNCTION_GET(memory_cacheability, ffa_memory_attributes_t,
		  FFA_MEMORY_CACHEABILITY_OFFSET, FFA_MEMORY_CACHEABILITY_MASK)

ATTR_FUNCTION_SET(memory_shareability, ffa_memory_attributes_t,
		  FFA_MEMORY_SHAREABILITY_OFFSET, FFA_MEMORY_SHAREABILITY_MASK)
ATTR_FUNCTION_GET(memory_shareability, ffa_memory_attributes_t,
		  FFA_MEMORY_SHAREABILITY_OFFSET, FFA_MEMORY_SHAREABILITY_MASK)

#define FFA_MEMORY_HANDLE_ALLOCATOR_MASK \
	((ffa_memory_handle_t)(UINT64_C(1) << 63))
#define FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR \
	((ffa_memory_handle_t)(UINT64_C(1) << 63))
#define FFA_MEMORY_HANDLE_INVALID (~UINT64_C(0))

/**
 * A set of contiguous pages which is part of a memory region. This corresponds
 * to table "Constituent memory region descriptor" of the FFA 1.0 specification.
 */
struct ffa_memory_region_constituent {
	/**
	 * The base IPA of the constituent memory region, aligned to 4 kiB page
	 * size granularity.
	 */
	void *address;
	/** The number of 4 kiB pages in the constituent memory region. */
	uint32_t page_count;
	/** Reserved field, must be 0. */
	uint32_t reserved;
};

/**
 * A set of pages comprising a memory region. This corresponds to table
 * "Composite memory region descriptor" of the FFA 1.0 specification.
 */
struct ffa_composite_memory_region {
	/**
	 * The total number of 4 kiB pages included in this memory region. This
	 * must be equal to the sum of page counts specified in each
	 * `ffa_memory_region_constituent`.
	 */
	uint32_t page_count;
	/**
	 * The number of constituents (`ffa_memory_region_constituent`)
	 * included in this memory region range.
	 */
	uint32_t constituent_count;
	/** Reserved field, must be 0. */
	uint64_t reserved_0;
	/** An array of `constituent_count` memory region constituents. */
	struct ffa_memory_region_constituent constituents[];
};

/**
 * This corresponds to table "Memory access permissions descriptor" of the FFA
 * 1.0 specification.
 */
struct ffa_memory_region_attributes {
	/** The ID of the VM to which the memory is being given or shared. */
	ffa_id_t receiver;
	/**
	 * The permissions with which the memory region should be mapped in the
	 * receiver's page table.
	 */
	ffa_memory_access_permissions_t permissions;
	/**
	 * Flags used during FFA_MEM_RETRIEVE_REQ and FFA_MEM_RETRIEVE_RESP
	 * for memory regions with multiple borrowers.
	 */
	ffa_memory_receiver_flags_t flags;
};

/** Flags to control the behaviour of a memory sharing transaction. */
typedef uint32_t ffa_memory_region_flags_t;

/**
 * Clear memory region contents after unmapping it from the sender and before
 * mapping it for any receiver.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR 0x1U

/**
 * Whether the hypervisor may time slice the memory sharing or retrieval
 * operation.
 */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE 0x2U

/**
 * Whether the hypervisor should clear the memory region after the receiver
 * relinquishes it or is aborted.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH 0x4U

#define FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK ((0x3U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_UNSPECIFIED ((0x0U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE ((0x1U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND ((0x2U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_DONATE ((0x3U) << 3)

/** The maximum number of recipients a memory region may be sent to. */
#define MAX_MEM_SHARE_RECIPIENTS 1U

/**
 * This corresponds to table "Endpoint memory access descriptor" of the FFA 1.0
 * specification.
 */
struct ffa_memory_access {
	struct ffa_memory_region_attributes receiver_permissions;
	/**
	 * Offset in bytes from the start of the outer `ffa_memory_region` to
	 * an `ffa_composite_memory_region` struct.
	 */
	uint32_t composite_memory_region_offset;
	uint64_t reserved_0;
};

/**
 * Information about a set of pages which are being shared. This corresponds to
 * table "Lend, donate or share memory transaction descriptor" of the FFA
 * 1.0 specification. Note that it is also used for retrieve requests and
 * responses.
 */
struct ffa_memory_region {
	/**
	 * The ID of the VM which originally sent the memory region, i.e. the
	 * owner.
	 */
	ffa_id_t sender;
	ffa_memory_attributes_t attributes;
	/** Reserved field, must be 0. */
	uint8_t reserved_0;
	/** Flags to control behaviour of the transaction. */
	ffa_memory_region_flags_t flags;
	ffa_memory_handle_t handle;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint64_t tag;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/**
	 * The number of `ffa_memory_access` entries included in this
	 * transaction.
	 */
	uint32_t receiver_count;
	/**
	 * An array of `attribute_count` endpoint memory access descriptors.
	 * Each one specifies a memory region offset, an endpoint and the
	 * attributes with which this memory region should be mapped in that
	 * endpoint's page table.
	 */
	struct ffa_memory_access receivers[];
};

/**
 * Descriptor used for FFA_MEM_RELINQUISH requests. This corresponds to table
 * "Descriptor to relinquish a memory region" of the FFA 1.0 specification.
 */
struct ffa_mem_relinquish {
	ffa_memory_handle_t handle;
	ffa_memory_region_flags_t flags;
	uint32_t endpoint_count;
	ffa_id_t endpoints[];
};

static inline ffa_memory_handle_t ffa_assemble_handle(uint32_t h1, uint32_t h2)
{
	return (ffa_notification_bitmap_t)h1 |
	       (ffa_notification_bitmap_t)h2 << 32;
}

static inline ffa_memory_handle_t ffa_mem_success_handle(smc_ret_values r)
{
	return ffa_assemble_handle(r.ret2, r.ret3);
}

/**
 * Gets the `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_memory_region *
ffa_memory_region_get_composite(struct ffa_memory_region *memory_region,
				uint32_t receiver_index)
{
	uint32_t offset = memory_region->receivers[receiver_index]
				  .composite_memory_region_offset;

	if (offset == 0) {
		return NULL;
	}

	return (struct ffa_composite_memory_region *)((uint8_t *)memory_region +
						      offset);
}

static inline uint32_t ffa_mem_relinquish_init(
	struct ffa_mem_relinquish *relinquish_request,
	ffa_memory_handle_t handle, ffa_memory_region_flags_t flags,
	ffa_id_t sender)
{
	relinquish_request->handle = handle;
	relinquish_request->flags = flags;
	relinquish_request->endpoint_count = 1;
	relinquish_request->endpoints[0] = sender;
	return sizeof(struct ffa_mem_relinquish) + sizeof(ffa_id_t);
}

uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender, ffa_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);

uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_id_t sender, ffa_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *total_length,
	uint32_t *fragment_length);

static inline ffa_id_t ffa_dir_msg_dest(smc_ret_values val) {
	return (ffa_id_t)val.ret1 & U(0xFFFF);
}

static inline ffa_id_t ffa_dir_msg_source(smc_ret_values val) {
	return (ffa_id_t)(val.ret1 >> 16U);
}

smc_ret_values ffa_msg_send_direct_req64(ffa_id_t source_id,
					 ffa_id_t dest_id, uint64_t arg0,
					 uint64_t arg1, uint64_t arg2,
					 uint64_t arg3, uint64_t arg4);

smc_ret_values ffa_msg_send_direct_req32(ffa_id_t source_id,
					 ffa_id_t dest_id, uint32_t arg0,
					 uint32_t arg1, uint32_t arg2,
					 uint32_t arg3, uint32_t arg4);

smc_ret_values ffa_msg_send_direct_resp64(ffa_id_t source_id,
					  ffa_id_t dest_id, uint64_t arg0,
					  uint64_t arg1, uint64_t arg2,
					  uint64_t arg3, uint64_t arg4);

smc_ret_values ffa_msg_send_direct_resp32(ffa_id_t source_id,
					  ffa_id_t dest_id, uint32_t arg0,
					  uint32_t arg1, uint32_t arg2,
					  uint32_t arg3, uint32_t arg4);

smc_ret_values ffa_run(uint32_t dest_id, uint32_t vcpu_id);
smc_ret_values ffa_version(uint32_t input_version);
smc_ret_values ffa_id_get(void);
smc_ret_values ffa_spm_id_get(void);
smc_ret_values ffa_msg_wait(void);
smc_ret_values ffa_error(int32_t error_code);
smc_ret_values ffa_features(uint32_t feature);
smc_ret_values ffa_partition_info_get(const struct ffa_uuid uuid);
smc_ret_values ffa_rx_release(void);
smc_ret_values ffa_rxtx_map(uintptr_t send, uintptr_t recv, uint32_t pages);
smc_ret_values ffa_rxtx_unmap(void);
smc_ret_values ffa_mem_donate(uint32_t descriptor_length,
			      uint32_t fragment_length);
smc_ret_values ffa_mem_lend(uint32_t descriptor_length,
			    uint32_t fragment_length);
smc_ret_values ffa_mem_share(uint32_t descriptor_length,
			     uint32_t fragment_length);
smc_ret_values ffa_mem_retrieve_req(uint32_t descriptor_length,
			            uint32_t fragment_length);
smc_ret_values ffa_mem_relinquish(void);
smc_ret_values ffa_mem_reclaim(uint64_t handle, uint32_t flags);
smc_ret_values ffa_notification_bitmap_create(ffa_id_t vm_id,
					      ffa_vcpu_count_t vcpu_count);
smc_ret_values ffa_notification_bitmap_destroy(ffa_id_t vm_id);
smc_ret_values ffa_notification_bind(ffa_id_t sender, ffa_id_t receiver,
				     uint32_t flags,
				     ffa_notification_bitmap_t notifications);
smc_ret_values ffa_notification_unbind(ffa_id_t sender, ffa_id_t receiver,
				       ffa_notification_bitmap_t notifications);
smc_ret_values ffa_notification_set(ffa_id_t sender, ffa_id_t receiver,
				    uint32_t flags,
				    ffa_notification_bitmap_t bitmap);
smc_ret_values ffa_notification_get(ffa_id_t receiver, uint32_t vcpu_id,
				    uint32_t flags);
smc_ret_values ffa_notification_info_get(void);
#endif /* __ASSEMBLY__ */

#endif /* FFA_HELPERS_H */
