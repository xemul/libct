#include <stdio.h>
#include "list.h"
#include "uapi/libct.h"
#include "ct.h"
#include "net.h"
#include "xmalloc.h"
#include "protobuf/rpc.pb-c.h"

/*
 * Generic Linux networking management
 * XXX -- copu libnetlink.c from criu/ip and implement proper
 * rtnl requests here.
 */

/*
 * Move network device @name into task's @pid net namespace
 */

int net_nic_move(char *name, int pid)
{
	/* FIXME -- implement */
	return -1;
}

/*
 * VETH creation/removal
 */

int veth_pair_create(struct ct_net_veth_arg *va)
{
	return -1;
}

void veth_pair_destroy(struct ct_net_veth_arg *va)
{
}

/*
 * Library API implementation
 */

void free_netconf(struct container *ct)
{
	struct ct_net *cn, *n;

	list_for_each_entry_safe(cn, n, &ct->ct_nets, l) {
		list_del(&cn->l);
		cn->ops->destroy(cn);
	}
}

int net_start(struct container *ct)
{
	struct ct_net *cn;

	list_for_each_entry(cn, &ct->ct_nets, l) {
		if (cn->ops->start(ct, cn))
			goto err;
	}

	return 0;

err:
	list_for_each_entry_continue_reverse(cn, &ct->ct_nets, l)
		cn->ops->stop(ct, cn);
	return -1;
}

void net_stop(struct container *ct)
{
	struct ct_net *cn;

	list_for_each_entry(cn, &ct->ct_nets, l)
		cn->ops->stop(ct, cn);
}

int local_net_add(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	struct container *ct = cth2ct(h);
	const struct ct_net_ops *nops;
	struct ct_net *cn;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -1;

	if (ntype == CT_NET_NONE) {
		free_netconf(ct);
		return 0;
	}

	nops = net_get_ops(ntype);
	if (!nops)
		return -1;

	cn = nops->create(arg);
	if (!cn)
		return -1;

	cn->ops = nops;
	list_add_tail(&cn->l, &ct->ct_nets);
	return 0;
}

int libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_add(ct, ntype, arg);
}

/*
 * CT_NET_HOSTNIC management
 */

struct ct_net_host_nic {
	struct ct_net n;
	char *name;
};

static inline struct ct_net_host_nic *cn2hn(struct ct_net *n)
{
	return container_of(n, struct ct_net_host_nic, n);
}

static struct ct_net *host_nic_create(void *arg)
{
	struct ct_net_host_nic *cn;

	cn = xmalloc(sizeof(*cn));
	if (!cn)
		return NULL;

	cn->name = xstrdup(arg);
	return &cn->n;
}

static void host_nic_destroy(struct ct_net *n)
{
	struct ct_net_host_nic *cn = cn2hn(n);

	xfree(cn->name);
	xfree(cn);
}

static int host_nic_start(struct container *ct, struct ct_net *n)
{
	return net_nic_move(cn2hn(n)->name, ct->root_pid);
}

static void host_nic_stop(struct container *ct, struct ct_net *n)
{
	/* 
	 * Nothing to do here. On container stop it's NICs will
	 * just jump out of it.
	 *
	 * FIXME -- CT owner might have changed NIC name. Handle
	 * it by checking the NIC's index.
	 */
}

static void host_nic_pack(void *arg, NetaddReq *req)
{
	req->nicname = arg;
}

static void *host_nic_unpack(NetaddReq *req)
{
	return xstrdup(req->nicname);
}

static const struct ct_net_ops host_nic_ops = {
	.create = host_nic_create,
	.destroy = host_nic_destroy,
	.start = host_nic_start,
	.stop = host_nic_stop,
	.pb_pack = host_nic_pack,
	.pb_unpack = host_nic_unpack,
};

/*
 * CT_NET_VETH management
 */

struct ct_net_veth {
	struct ct_net n;
	struct ct_net_veth_arg v;
};

static struct ct_net_veth *cn2vn(struct ct_net *n)
{
	return container_of(n, struct ct_net_veth, n);
}

static struct ct_net *veth_create(void *arg)
{
	struct ct_net_veth_arg *va = arg;
	struct ct_net_veth *vn;

	vn = xmalloc(sizeof(*vn));
	if (!vn)
		return NULL;

	vn->v.host_name = xstrdup(va->host_name);
	vn->v.ct_name = xstrdup(va->ct_name);

	return &vn->n;
}

static void veth_destroy(struct ct_net *n)
{
	struct ct_net_veth *vn = cn2vn(n);

	xfree(vn->v.host_name);
	xfree(vn->v.ct_name);
	xfree(vn);
}

static int veth_start(struct container *ct, struct ct_net *n)
{
	struct ct_net_veth *vn = cn2vn(n);

	/*
	 * FIXME -- the ct_name may be busy on host. Need to
	 * create peer right in the target netns (IFLA_NET_NS_FD)
	 */

	if (veth_pair_create(&vn->v))
		return -1;

	if (net_nic_move(vn->v.ct_name, ct->root_pid)) {
		veth_pair_destroy(&vn->v);
		return -1;
	}

	return 0;
}

static void veth_stop(struct container *ct, struct ct_net *n)
{
	struct ct_net_veth *vn = cn2vn(n);

	/* 
	 * FIXME -- don't destroy veth here, keep it across
	 * container's restarts. This needs checks in the
	 * veth_pair_create() for existance.
	 */

	veth_pair_destroy(&vn->v);
}

static void veth_pack(void *arg, NetaddReq *req)
{
	struct ct_net_veth_arg *va = arg;

	req->nicname = va->host_name;
	req->peername = va->ct_name;
}

static void *veth_unpack(NetaddReq *req)
{
	struct ct_net_veth_arg *va;

	va = xmalloc(sizeof(*va));
	va->host_name = req->nicname;
	va->ct_name = req->peername;

	return va;
}

static const struct ct_net_ops veth_nic_ops = {
	.create = veth_create,
	.destroy = veth_destroy,
	.start = veth_start,
	.stop = veth_stop,
	.pb_pack = veth_pack,
	.pb_unpack = veth_unpack,
};

const struct ct_net_ops *net_get_ops(enum ct_net_type ntype)
{
	switch (ntype) {
	case CT_NET_HOSTNIC:
		return &host_nic_ops;
	case CT_NET_VETH:
		return &veth_nic_ops;
	case CT_NET_NONE:
		break;
	}

	return NULL;
}
