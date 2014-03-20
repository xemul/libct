#include <stdio.h>
#include "uapi/libct.h"
#include "list.h"
#include "ct.h"
#include "cgroups.h"
#include "xmalloc.h"

int libct_container_add_controller(ct_handler_t h, enum ct_controller ctype)
{
	struct container *ct = cth2ct(h);
	struct controller *ctl;

	if (ctype >= CT_NR_CONTROLLERS)
		return -1;

	ctl = xmalloc(sizeof(*ctl));
	if (!ctl)
		return -1;

	ctl->ctype = ctype;
	list_add_tail(&ctl->ct_l, &ct->cgroups);
	return 0;
}

static void destroy_controller(struct controller *ctl)
{
	list_del(&ctl->ct_l);
	xfree(ctl);
}

void cgroups_destroy(struct container *ct)
{
	struct controller *ctl, *n;

	list_for_each_entry_safe(ctl, n, &ct->cgroups, ct_l)
		destroy_controller(ctl);
}
