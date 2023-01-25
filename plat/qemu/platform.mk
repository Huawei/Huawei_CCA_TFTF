USE_NVM		:= 	0

QEMU_PATH	:=	plat/qemu

PLAT_INCLUDES	:=	-I${QEMU_PATH}/include/

PLAT_SOURCES	:=	${QEMU_PATH}/qemu_setup.c		\
			${QEMU_PATH}/qemu_pwr_state.c		\
			${QEMU_PATH}/aarch64/plat_helpers.S		\
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
