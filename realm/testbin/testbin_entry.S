.section ".text"

# tag: VIMGtbin
.quad 0x6e696274474d4956

.globl realm_testbin_entry
realm_testbin_entry:
	adrp x3, realm_testbin_entry
	add x3, x3, #0x3000
	mov sp, x3
1:
	bl testbin_main
	hvc #0
	b 1b
