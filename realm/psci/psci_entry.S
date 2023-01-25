.section ".text"

# tag: VIMGpsci
.quad 0x69637370474d4956

.globl realm_psci_entry
realm_psci_entry:
	mov x3, #0x4000
	add sp, x3, #0x400
1:
	bl psci_main
	hvc #0
	b 1b

.globl hot_entry1
hot_entry1:
	mov x3, #0x4000
	add sp, x3, #0x800
2:
	bl psci_thread
	hvc #0
	b 2b

.globl hot_entry2
hot_entry2:
	mov x3, #0x4000
	add sp, x3, #0xc00
	b 2b

.globl hot_entry3
hot_entry3:
	mov x3, #0x4000
	add sp, x3, #0xfe0
	b 2b
