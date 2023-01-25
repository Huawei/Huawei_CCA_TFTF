#include <platform_def.h>

#define PAGE_SIZE U(4096)

OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)
ENTRY(realm_testbin_entry)

SECTIONS
{
	. = PAGE_SIZE;

    ASSERT(. == ALIGN(PAGE_SIZE),
           "TEXT_START address is not aligned to PAGE_SIZE.")

    .text : {
        __TEXT_START__ = .;
        *testbin_entry.o(.text*)
        *(.text*)
        *(.vectors)
        . = NEXT(PAGE_SIZE);
        __TEXT_END__ = .;
    }

    .rodata : {
        . = ALIGN(PAGE_SIZE);
        __RODATA_START__ = .;
        *(.rodata*)
        . = NEXT(PAGE_SIZE);
        __RODATA_END__ = .;
    }

    .data : {
        . = ALIGN(PAGE_SIZE);
        __DATA_START__ = .;
        *(.data*)
        . = NEXT(PAGE_SIZE);
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
