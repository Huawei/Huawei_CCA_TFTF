REALM_TESTBIN_INCLUDES := \
	-Iinclude \
	-Iinclude/common				\
	-Iinclude/common/${ARCH}			\
	-Iinclude/lib					\
	-Iinclude/lib/${ARCH}				\
	-Iinclude/lib/sprt				\
	-Iinclude/lib/utils				\
	-Iinclude/lib/xlat_tables			\
	-Iinclude/runtime_services			\
	-Iinclude/plat/common

REALM_TESTBIN_SOURCES += \
	realm/testbin/testbin_main.c \
	realm/testbin/testbin_entry.S

REALM_TESTBIN_LINKERFILE  :=  realm/testbin/testbin.ld.S

REALM_TESTBIN_DEFINES := -DUSE_NVM=1
$(eval $(call add_define,REALM_TESTBIN_DEFINES,ARM_ARCH_MAJOR))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,ARM_ARCH_MINOR))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,DEBUG))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,ENABLE_ASSERTIONS))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,ENABLE_BTI))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,ENABLE_PAUTH))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,FWU_BL_TEST))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,LOG_LEVEL))
$(eval $(call add_define,REALM_TESTBIN_DEFINES,PLAT_${PLAT}))
