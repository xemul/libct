#include <stdio.h>
#include "list.h"
#include "uapi/libct.h"
#include "ct.h"
#include "net.h"

void free_netconf(struct container *ct)
{
}

int local_net_add(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -1;

	if (ntype == CT_NET_NONE) {
		free_netconf(ct);
		return 0;
	}

	return -1;
}

int libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_add(ct, ntype, arg);
}

const struct ct_net_ops *net_get_ops(enum ct_net_type ntype)
{
	return NULL;
}
