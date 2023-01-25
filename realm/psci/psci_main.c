#include <stdint.h>
#include <lib/tftf_lib.h>
#include <runtime_services/psci.h>
#include <lib/spinlock.h>

extern void hot_entry1 (uintptr_t context_id);
extern void hot_entry2 (uintptr_t context_id);
extern void hot_entry3 (uintptr_t context_id);

static spinlock_t lock;
static volatile int shared_counter = 0;

uint64_t psci_thread (void)
{
	for (int i = 0; i < 100; i ++) {
		spin_lock(&lock);
		shared_counter ++;
		spin_unlock(&lock);
	}
	tftf_psci_cpu_off();
	/* unreachable */
	return 1;
}

uint64_t psci_main (void)
{
	unsigned int psci_version = tftf_get_psci_version();
	if (!psci_version)
		return 1;

	const uint32_t invalid_psci_func = 0xc400a011;
	int feature_info = tftf_get_psci_feature_info(invalid_psci_func);
	if (feature_info != PSCI_E_NOT_SUPPORTED)
		return 1;

	int affinity_info = tftf_psci_affinity_info(1, MPIDR_AFFLVL0);
	if (affinity_info != PSCI_STATE_OFF)
		return 1;

	tftf_psci_cpu_on(1, (uintptr_t)hot_entry1, 0);
	tftf_psci_cpu_on(2, (uintptr_t)hot_entry2, 0);
	tftf_psci_cpu_on(3, (uintptr_t)hot_entry3, 0);

	for (int i = 1; i <= 3; i ++) {
		while (tftf_psci_affinity_info(i, MPIDR_AFFLVL0) != PSCI_STATE_OFF)
			;
	}
	if (shared_counter == 3 * 100) {
		tftf_psci_cpu_off();
		/* unreachable */
		return 1;
	} else {
		return 1;
	}
}
