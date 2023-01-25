#include <stdint.h>

static uint64_t bssvar = 0;

static int fibo (int n)
{
	if (n == 0)
		return 0;
	if (n == 1)
		return 1;
	return fibo(n-1) + fibo(n-2);
}

uint64_t testbin_main (uint64_t arg1, uint64_t arg2)
{
	bssvar ++;
	return fibo(bssvar + (int)arg1 + (int)arg2);
}
