#ifndef _PLATFORM_DEF_H__
#define _PLATFORM_DEF_H__

#include <arch.h>

#define PLATFORM_LINKER_FORMAT          "elf64-littleaarch64"
#define PLATFORM_LINKER_ARCH            aarch64

#define PLATFORM_STACK_SIZE 0x1000

#if ARM_ARCH_MAJOR == 7
#define PLATFORM_MAX_CPUS_PER_CLUSTER	U(4)
#define PLATFORM_CLUSTER_COUNT		U(1)
#define PLATFORM_CLUSTER0_CORE_COUNT	PLATFORM_MAX_CPUS_PER_CLUSTER
#define PLATFORM_CLUSTER1_CORE_COUNT	U(0)
#else
#define PLATFORM_MAX_CPUS_PER_CLUSTER	U(4)
/*
 * Define the number of cores per cluster used in calculating core position.
 * The cluster number is shifted by this value and added to the core ID,
 * so its value represents log2(cores/cluster).
 * Default is 2**(2) = 4 cores per cluster.
 */
#define PLATFORM_CPU_PER_CLUSTER_SHIFT	U(2)

#define PLATFORM_CLUSTER_COUNT		U(2)
#define PLATFORM_CLUSTER0_CORE_COUNT	PLATFORM_MAX_CPUS_PER_CLUSTER
#define PLATFORM_CLUSTER1_CORE_COUNT	PLATFORM_MAX_CPUS_PER_CLUSTER
#endif
#define PLATFORM_CORE_COUNT		(PLATFORM_CLUSTER0_CORE_COUNT + \
					 PLATFORM_CLUSTER1_CORE_COUNT)

#define QEMU_PRIMARY_CPU		U(0)

#define PLATFORM_NUM_AFFS			(PLATFORM_CLUSTER_COUNT + PLATFORM_CORE_COUNT)
#define PLATFORM_MAX_AFFLVL			MPIDR_AFFLVL1
#define PLAT_MAX_PWR_LEVEL		PLATFORM_MAX_AFFLVL

#define PLAT_MAX_RET_STATE		U(1)
#define PLAT_MAX_OFF_STATE		U(2)

/* Local power state for power domains in Run state. */
#define PLAT_LOCAL_STATE_RUN		U(0)
/* Local power state for retention. Valid only for CPU power domains */
#define PLAT_LOCAL_STATE_RET		U(1)
/*
 * Local power state for OFF/power-down. Valid for CPU and cluster power
 * domains.
 */
#define PLAT_LOCAL_STATE_OFF		2

/*
 * Macros used to parse state information from State-ID if it is using the
 * recommended encoding for State-ID.
 */
#define PLAT_LOCAL_PSTATE_WIDTH		4
#define PLAT_LOCAL_PSTATE_MASK		((1 << PLAT_LOCAL_PSTATE_WIDTH) - 1)


/*******************************************************************************
 * Run-time address of the TFTF image.
 * It has to match the location where the Trusted Firmware-A loads the BL33
 * image.
 ******************************************************************************/
#define TFTF_BASE                       0x60000000

/*
 * Some data must be aligned on the biggest cache line size in the platform.
 * This is known only to the platform as it might have a combination of
 * integrated and external caches.
 */
#define CACHE_WRITEBACK_SHIFT           6
#define CACHE_WRITEBACK_GRANULE         (1 << CACHE_WRITEBACK_SHIFT)

#define GICD_BASE   0x8000000
#define GICC_BASE   0x8010000
#define GICR_BASE   0x80A0000

/*
 * PL011 related constants
 */
#define UART0_BASE                      0x09000000
#define UART1_BASE                      0x09040000
#define UART0_CLK_IN_HZ                 1
#define UART1_CLK_IN_HZ                 1

#define PLAT_QEMU_BOOT_UART_BASE        UART0_BASE
#define PLAT_QEMU_BOOT_UART_CLK_IN_HZ   UART0_CLK_IN_HZ

#define PLAT_QEMU_CRASH_UART_BASE       UART1_BASE
#define PLAT_QEMU_CRASH_UART_CLK_IN_HZ  UART1_CLK_IN_HZ

#define PLAT_QEMU_CONSOLE_BAUDRATE      115200

/*******************************************************************************
 * Non-Secure Software Generated Interupts IDs
 ******************************************************************************/
#define IRQ_NS_SGI_0                    0
#define IRQ_NS_SGI_1                    1
#define IRQ_NS_SGI_2                    2
#define IRQ_NS_SGI_3                    3
#define IRQ_NS_SGI_4                    4
#define IRQ_NS_SGI_5                    5
#define IRQ_NS_SGI_6                    6
#define IRQ_NS_SGI_7                    7

#define PLAT_MAX_SPI_OFFSET_ID		176

#define PLAT_PHY_ADDR_SPACE_SIZE        (1ULL << 32)
#define PLAT_VIRT_ADDR_SPACE_SIZE       (1ULL << 32)
#define MAX_MMAP_REGIONS                11
#define MAX_XLAT_TABLES                 6
#define MAX_IO_DEVICES                  4
#define MAX_IO_HANDLES                  4

#define DRAM_BASE			0x40000000
#define DRAM_SIZE			0x80000000

#define TFTF_NVM_OFFSET			0
#define TFTF_NVM_SIZE			(TFTF_BASE - DRAM_BASE - TFTF_NVM_OFFSET)

/* Times(in ms) used by test code for completion of different events */
#define PLAT_SUSPEND_ENTRY_TIME         15
#define PLAT_SUSPEND_ENTRY_EXIT_TIME    30

/* this is qemu pl031 rtc info, we don't use timer in realm test now */
#define SYS_CNT_BASE1			0x09010000
#define IRQ_CNTPSIRQ1			2

#if DEBUG
#define PCPU_DV_MEM_STACK_SIZE		0x600
#else
#define PCPU_DV_MEM_STACK_SIZE		0x500
#endif

#endif
