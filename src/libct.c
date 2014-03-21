#include <stdbool.h>
#include "linux-kernel.h"
#include "libct.h"

int libct_init_local(void)
{
	static bool done = false;

	if (done)
		return 0;

	if (linux_get_ns_mask())
		return -1;

	done = true;
	return 0;
}
