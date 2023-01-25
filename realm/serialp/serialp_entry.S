.section ".text"

	/* VM tag: VIMGserl */
	.quad 0x6c726573474d4956

.globl serialp_entry
serialp_entry:
	adrp x3, serialp_entry
	add x3, x3, #0x3000
	mov sp, x3
1:
	bl serialp_main
	mov x1, x0
	mov x0, #0
	hvc #0
	b 1b
