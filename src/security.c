#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <grp.h>

#include <sys/prctl.h>

#include <linux/capability.h>

#include "uapi/libct.h"

#include "linux-kernel.h"
#include "security.h"
#include "list.h"
#include "ct.h"

static int apply_bset(unsigned long mask)
{
	int i, last_cap;

	last_cap = linux_get_last_capability();
	if (last_cap < 0)
		return -1;

	for (i = 0; i <= last_cap; i++) {
		if (mask & (1ULL << i))
			continue;

		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) == -1)
			return -1;
	}

	return 0;
}

extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capset(cap_user_header_t header, const cap_user_data_t data);

static int apply_all_caps(unsigned long mask)
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct data[2]; /* as of .._VERSION_3 */

	memset(&header, 0, sizeof(header));
	capget(&header, data);
	switch (header.version) {
		case _LINUX_CAPABILITY_VERSION_1:
		case _LINUX_CAPABILITY_VERSION_2:
		case _LINUX_CAPABILITY_VERSION_3:
			break;
		default:
			return -1;
	}

	header.pid = getpid();
	data[0].effective = mask;
	data[0].permitted = mask;
	data[0].inheritable = mask;

	return capset(&header, data);
}

int apply_creds(struct process_desc *p)
{
	if (setgroups(p->ngroups, p->groups))
		return -1;

	if (setgid(p->gid) || setuid(p->uid))
		return -1;

	if (!p->cap_mask)
		return 0;

	if (p->cap_mask & CAPS_BSET)
		if (apply_bset(p->cap_bset) < 0)
			return -1;

	if (p->cap_mask & CAPS_ALLCAPS)
		if (apply_all_caps(p->cap_caps) < 0)
			return -1;

	return 0;
}
