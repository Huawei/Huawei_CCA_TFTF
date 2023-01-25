#include <arch.h>
#include <asm_macros.S>
#include <platform_def.h>

        .global platform_get_core_pos
        .global plat_crash_console_init
        .global plat_crash_console_flush
        .global plat_crash_console_putc

func platform_get_core_pos
	and x1, x0, #MPIDR_CPU_MASK
	and x0, x0, #MPIDR_CLUSTER_MASK
	add x0, x1, x0, LSR #(MPIDR_AFFINITY_BITS - \
				PLATFORM_CPU_PER_CLUSTER_SHIFT)
	ret
endfunc platform_get_core_pos

	/* ---------------------------------------------
         * int plat_crash_console_init(void)
         * Function to initialize the crash console
         * without a C Runtime to print crash report.
         * Clobber list : x0, x1, x2
         * ---------------------------------------------
         */
func plat_crash_console_init
        mov_imm x0, PLAT_QEMU_CRASH_UART_BASE
        mov_imm x1, PLAT_QEMU_CRASH_UART_CLK_IN_HZ
        mov_imm x2, PLAT_QEMU_CONSOLE_BAUDRATE
        b       console_core_init
endfunc plat_crash_console_init

        /* ---------------------------------------------
         * int plat_crash_console_putc(int c)
         * Function to print a character on the crash
         * console without a C Runtime.
         * Clobber list : x1, x2
         * ---------------------------------------------
         */
func plat_crash_console_putc
        mov_imm x1, PLAT_QEMU_CRASH_UART_BASE
        b       console_core_putc
endfunc plat_crash_console_putc

        /* ---------------------------------------------
         * void plat_crash_console_flush(int c)
         * Function to force a write of all buffered
         * data that hasn't been output.
         * Out : void.
         * Clobber list : x0, x1
         * ---------------------------------------------
         */
func plat_crash_console_flush
        mov_imm x0, PLAT_QEMU_CRASH_UART_BASE
        b       console_core_flush
endfunc plat_crash_console_flush
