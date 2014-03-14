#include <sys/types.h>
#include <dirent.h>
#include <sched.h>
#include <string.h>
#include "linux-kernel.h"

unsigned long kernel_ns_mask;

int linux_get_ns_mask(void)
{
	DIR *d;

	d = opendir("/proc/self/ns");
	if (d) {
		struct dirent *de;

		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, "."))
				continue;
			if (!strcmp(de->d_name, ".."))
				continue;

			if (!strcmp(de->d_name, "ipc"))
				kernel_ns_mask |= CLONE_NEWIPC;
			else if (!strcmp(de->d_name, "net"))
				kernel_ns_mask |= CLONE_NEWNET;
			else if (!strcmp(de->d_name, "mnt"))
				kernel_ns_mask |= CLONE_NEWNS;
			else if (!strcmp(de->d_name, "pid"))
				kernel_ns_mask |= CLONE_NEWPID;
			else if (!strcmp(de->d_name, "uts"))
				kernel_ns_mask |= CLONE_NEWUTS;
		}
	}

	closedir(d);
	return 0;
}
