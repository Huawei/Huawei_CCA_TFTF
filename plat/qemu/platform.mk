# If not specified as build arguments, set default to 10 MB
TFTF_MAX_IMAGE_SIZE:=10485760

USE_NVM		:= 	0

$(eval $(call add_define,TFTF_DEFINES,TFTF_MAX_IMAGE_SIZE))

PLAT_INCLUDES	:=	-Iplat/qemu/include/

PLAT_SOURCES	:=	plat/qemu/qemu_setup.c		\
			plat/qemu/qemu_pwr_state.c		\
			plat/qemu/aarch64/plat_helpers.S		\
			drivers/arm/pl011/${ARCH}/pl011_console.S	\
			drivers/arm/gic/gic_common.c			\
			drivers/arm/gic/gic_v2.c			\
			drivers/arm/gic/gic_v3.c			\
			drivers/arm/gic/arm_gic_v2v3.c			\
			drivers/arm/timer/system_timer.c		\
			drivers/arm/timer/private_timer.c		\
			drivers/console/console.c			\
			plat/arm/common/arm_timers.c

TFTF_CFLAGS		+= -Wno-maybe-uninitialized
