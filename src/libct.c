#include <stdio.h>
#include <stdlib.h>
#include "linux-kernel.h"
#include "uapi/libct.h"

int libct_init(void)
{
	if (linux_get_ns_mask())
		return -1;

	return 0;
}

void libct_exit(void)
{
}
