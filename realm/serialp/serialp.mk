REALM_SERIALP_INCLUDES := \
	-Iinclude \
	-Iinclude/common				\
	-Iinclude/common/${ARCH}			\
	-Iinclude/lib					\
	-Iinclude/lib/${ARCH}				\
	-Iinclude/lib/sprt				\
	-Iinclude/lib/utils				\
	-Iinclude/lib/xlat_tables			\
	-Iinclude/runtime_services			\
	-Iinclude/plat/common \
	-Itftf/framework/include

REALM_SERIALP_SOURCES += \
	realm/serialp/serialp_main.c \
	realm/serialp/serialp_entry.S \
	realm/serialp/console.c \
	lib/smc/aarch64/hvc.c \
	lib/smc/aarch64/asm_smc.S \
	tftf/framework/debug.c

REALM_SERIALP_LINKERFILE  :=  realm/serialp/serialp.ld.S

REALM_SERIALP_DEFINES := -DUSE_NVM=1
$(eval $(call add_define,REALM_SERIALP_DEFINES,ARM_ARCH_MAJOR))
$(eval $(call add_define,REALM_SERIALP_DEFINES,ARM_ARCH_MINOR))
$(eval $(call add_define,REALM_SERIALP_DEFINES,DEBUG))
$(eval $(call add_define,REALM_SERIALP_DEFINES,ENABLE_ASSERTIONS))
$(eval $(call add_define,REALM_SERIALP_DEFINES,ENABLE_BTI))
$(eval $(call add_define,REALM_SERIALP_DEFINES,ENABLE_PAUTH))
$(eval $(call add_define,REALM_SERIALP_DEFINES,FWU_BL_TEST))
$(eval $(call add_define,REALM_SERIALP_DEFINES,LOG_LEVEL))
$(eval $(call add_define,REALM_SERIALP_DEFINES,PLAT_${PLAT}))
