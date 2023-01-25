#include <platform_def.h>

#define PAGE_SIZE U(4096)

OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)
ENTRY(realm_psci_entry)

SECTIONS
{
	. = PAGE_SIZE;

    ASSERT(. == ALIGN(PAGE_SIZE),
           "TEXT_START address is not aligned to PAGE_SIZE.")

    .text : {
        __TEXT_START__ = .;
        *psci_entry.o(.text*)
        *(.text*)
        __TEXT_END__ = .;
    }

    .rodata : {
        __RODATA_START__ = .;
        *(.rodata*)
        __RODATA_END__ = .;
    }

    .data : {
        __DATA_START__ = .;
        *(.data*)
        __DATA_END__ = .;
    }

    .bss (NOLOAD) : {
        . = ALIGN(PAGE_SIZE);
        __BSS_START__ = .;
        *(SORT_BY_ALIGNMENT(.bss*))
        *(COMMON)
        . = NEXT(PAGE_SIZE);
        __BSS_END__ = .;
    }
}
