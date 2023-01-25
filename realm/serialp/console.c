#include <drivers/console.h>
#include <lib/tftf_lib.h>

static int putc_hypcall(int c)
{
	hvc_args args = {
		.fid = 1,
		.arg1 = c
	};

	(void)tftf_hvc(&args);
	return c;
}

int console_putc(int c)
{
	return putc_hypcall(c);
}

int console_flush(void)
{
	return 0;
}
