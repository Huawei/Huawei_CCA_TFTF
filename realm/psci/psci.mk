REALM_PSCI_INCLUDES := \
	-Iinclude \
	-Iinclude/common				\
	-Iinclude/common/${ARCH}			\
	-Iinclude/lib					\
	-Iinclude/lib/${ARCH}				\
	-Iinclude/lib/sprt				\
	-Iinclude/lib/utils				\
	-Iinclude/lib/xlat_tables			\
	-Iinclude/runtime_services			\
	-Iinclude/plat/common			\
	-Itftf/framework/include

REALM_PSCI_SOURCES += \
	realm/psci/psci_main.c \
	realm/psci/psci_entry.S \
	lib/psci/psci.c \
	lib/smc/aarch64/smc.c \
	lib/smc/aarch64/asm_smc.S \
	lib/locks/aarch64/spinlock.S

REALM_PSCI_LINKERFILE  :=  realm/psci/psci.ld.S

REALM_PSCI_DEFINES := -DUSE_NVM=1
$(eval $(call add_define,REALM_PSCI_DEFINES,ARM_ARCH_MAJOR))
$(eval $(call add_define,REALM_PSCI_DEFINES,ARM_ARCH_MINOR))
$(eval $(call add_define,REALM_PSCI_DEFINES,DEBUG))
$(eval $(call add_define,REALM_PSCI_DEFINES,ENABLE_ASSERTIONS))
$(eval $(call add_define,REALM_PSCI_DEFINES,ENABLE_BTI))
$(eval $(call add_define,REALM_PSCI_DEFINES,ENABLE_PAUTH))
$(eval $(call add_define,REALM_PSCI_DEFINES,FWU_BL_TEST))
$(eval $(call add_define,REALM_PSCI_DEFINES,LOG_LEVEL))
$(eval $(call add_define,REALM_PSCI_DEFINES,PLAT_${PLAT}))
