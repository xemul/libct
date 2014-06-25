#include <sys/mount.h>
#include <stdlib.h>

#include "util.h"

int bind_mount(char *src, char *dst)
{
	return mount(src, dst, NULL, MS_BIND, NULL);
}
