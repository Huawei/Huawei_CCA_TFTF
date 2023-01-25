#include <debug.h>
#include <assert.h>
#include <drivers/arm/arm_gic.h>
#include <drivers/arm/pl011.h>
#include <drivers/console.h>
#include <io_storage.h>
#include <platform.h>
#include <platform_def.h>
#include <tftf_lib.h>

static const mmap_region_t mmap[] = {
        MAP_REGION_FLAT(    \
                UART0_BASE,     \
                0x1000, \
                MT_DEVICE | MT_RW  | MT_NS),
        MAP_REGION_FLAT(        \
                GICD_BASE,      \
                0x1000000,      \
                MT_DEVICE | MT_RW  | MT_NS),
        MAP_REGION_FLAT(        \
                DRAM_BASE,      \
                TFTF_NVM_SIZE,  \
                MT_MEMORY | MT_RW | MT_NS),
	{0}
};

static const struct {
        unsigned int cluster_id;
        unsigned int cpu_id;
} plat_cores[] = {
        /* Cluster0: 8 cores*/
        { 0, 0 },
        { 0, 1 },
        { 0, 2 },
        { 0, 3 },
        { 0, 4 },
        { 0, 5 },
        { 0, 6 },
        { 0, 7 },
};

static unsigned char qemu_power_domain_tree_desc[] = {
	PLATFORM_CLUSTER_COUNT,
	PLATFORM_CLUSTER0_CORE_COUNT,
};

void qemu_platform_setup(void)
{
        arm_gic_init(GICC_BASE, GICD_BASE, GICR_BASE);

        arm_gic_setup_global();
        arm_gic_setup_local();
}

const unsigned char *tftf_plat_get_pwr_domain_tree_desc(void)
{
	return qemu_power_domain_tree_desc;
}

uint64_t tftf_plat_get_mpidr(unsigned int core_pos)
{
	unsigned int mpid;

	assert(core_pos < PLATFORM_CORE_COUNT);

	mpid = make_mpid(plat_cores[core_pos].cluster_id,
			plat_cores[core_pos].cpu_id);
	return mpid;
}

void tftf_early_platform_setup(void)
{
	/* tftf use normal world uart console */
        console_init(UART0_BASE, UART0_CLK_IN_HZ,
                     PLAT_QEMU_CONSOLE_BAUDRATE);
}

void tftf_plat_arch_setup(void)
{
        tftf_plat_configure_mmu();
}

void tftf_platform_setup(void)
{
        qemu_platform_setup();
}

const mmap_region_t *tftf_platform_get_mmap(void)
{
	return mmap;
}
