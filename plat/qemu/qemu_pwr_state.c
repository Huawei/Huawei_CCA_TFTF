#include <arch.h>
#include <platform.h>
#include <psci.h>
#include <stddef.h>

#define QEMU_RETENTION_STATE_ID 	1
#define QEMU_OFF_STATE_ID	2
typedef enum {
	QEMU_RETENTION_DEPTH = 1,
	QEMU_OFF_DEPTH,
}suspend_depth_t;

static const plat_state_prop_t core_state_prop[] = {
	{QEMU_RETENTION_DEPTH, QEMU_RETENTION_STATE_ID, PSTATE_TYPE_STANDBY},
	{QEMU_OFF_DEPTH, QEMU_OFF_STATE_ID, PSTATE_TYPE_POWERDOWN},
	{0},
};

static const plat_state_prop_t cluster_state_prop[] = {
	{QEMU_OFF_DEPTH, QEMU_OFF_STATE_ID, PSTATE_TYPE_POWERDOWN},
	{0},
};

const plat_state_prop_t *plat_get_state_prop(unsigned int level)
{
	switch (level) {
		case MPIDR_AFFLVL0:
			return core_state_prop;
		case MPIDR_AFFLVL1:
			return cluster_state_prop;
		default:
			return NULL;
	}
}
