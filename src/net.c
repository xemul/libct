#include <stdio.h>
#include <sched.h>

#include "uapi/libct.h"

#include "libnetlink.h"
#include "xmalloc.h"
#include "list.h"
#include "net.h"
#include "ct.h"

#include "protobuf/rpc.pb-c.h"

/*
 * Generic Linux networking management
 */

/*
 * Move network device @name into task's @pid net namespace
 */

static int net_nic_move(char *name, int pid)
{
	struct nlmsghdr *h;
	struct ifinfomsg *ifi;
	int nlfd, err;

	/*
	 * FIXME -- one nlconn per container/session
	 */

	err = nlfd = netlink_open(NETLINK_ROUTE);
	if (nlfd < 0)
		goto err_o;

	err = -1;
	h = nlmsg_alloc(sizeof(struct ifinfomsg));
	if (!h)
		goto err_a;

	h->nlmsg_type = RTM_NEWLINK;
	h->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	ifi = (struct ifinfomsg *)(h + 1);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = 0;
	if (nla_put_u32(h, IFLA_NET_NS_PID, pid))
		goto err;
	if (nla_put_string(h, IFLA_IFNAME, name))
		goto err;

	err = netlink_talk(nlfd, h, h);
err:
	nlmsg_free(h);
err_a:
	netlink_close(nlfd);
err_o:
	return err;
}

/*
 * VETH creation/removal
 */

#ifndef VETH_INFO_MAX
enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX   (__VETH_INFO_MAX - 1)
};
#endif

static int veth_pair_create(struct ct_net_veth_arg *va, int ct_pid)
{
	struct nlmsghdr *h;
	struct ifinfomsg *ifi;
	struct rtattr *linfo, *data, *peer;
	int nlfd, err;

	/*
	 * FIXME -- one nlconn per container/session
	 */

	err = nlfd = netlink_open(NETLINK_ROUTE);
	if (nlfd < 0)
		goto err_o;

	err = -1;
	h = nlmsg_alloc(sizeof(struct ifinfomsg));
	if (!h)
		goto err_a;

	h->nlmsg_type = RTM_NEWLINK;
	h->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	ifi = (struct ifinfomsg *)(h + 1);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = 0;
	if (nla_put_string(h, IFLA_IFNAME, va->host_name))
		goto err;

	linfo = nla_put_nested(h, IFLA_LINKINFO);
	if (!linfo)
		goto err;

	if (nla_put_string(h, IFLA_INFO_KIND, "veth"))
		goto err;

	data = nla_put_nested(h, IFLA_INFO_DATA);
	if (!data)
		goto err;

	peer = nla_put_nested(h, VETH_INFO_PEER);
	if (!peer)
		goto err;

	h->nlmsg_len += sizeof(struct ifinfomsg);

	if (nla_put_string(h, IFLA_IFNAME, va->ct_name))
		goto err;

	if (nla_put_u32(h, IFLA_NET_NS_PID, ct_pid))
		goto err;

	nla_commit_nested(h, peer);
	nla_commit_nested(h, data);
	nla_commit_nested(h, linfo);

	err = netlink_talk(nlfd, h, h);
err:
	nlmsg_free(h);
err_a:
	netlink_close(nlfd);
err_o:
	return err;
}

/*
 * Library API implementation
 */

void net_release(struct container *ct)
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
		return LCTERR_BADCTSTATE;

	if (!(ct->nsmask & CLONE_NEWNET))
		return LCTERR_NONS;

	if (ntype == CT_NET_NONE)
		return 0;

	nops = net_get_ops(ntype);
	if (!nops)
		return LCTERR_BADTYPE;

	cn = nops->create(arg);
	if (!cn)
		return LCTERR_BADARG;

	cn->ops = nops;
	list_add_tail(&cn->l, &ct->ct_nets);
	return 0;
}

int local_net_del(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	struct container *ct = cth2ct(h);
	const struct ct_net_ops *nops;
	struct ct_net *cn;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return LCTERR_BADCTSTATE;

	if (ntype == CT_NET_NONE)
		return 0;

	nops = net_get_ops(ntype);
	if (!nops)
		return LCTERR_BADTYPE;

	list_for_each_entry(cn, &ct->ct_nets, l) {
		if (!cn->ops->match(cn, arg))
			continue;

		list_del(&cn->l);
		cn->ops->destroy(cn);
		return 0;
	}

	return LCTERR_NOTFOUND;
}

int libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_add(ct, ntype, arg);
}

int libct_net_del(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_del(ct, ntype, arg);
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

	if (arg) {
		cn = xmalloc(sizeof(*cn));
		if (cn) {
			cn->name = xstrdup(arg);
			if (cn->name)
				return &cn->n;
		}
		xfree(cn);
	}
	return NULL;
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
	if (req->nicname)
		return xstrdup(req->nicname);
	return NULL;
}

static int host_nic_match(struct ct_net *n, void *arg)
{
	struct ct_net_host_nic *cn = cn2hn(n);
	return !strcmp(cn->name, arg);
}

static const struct ct_net_ops host_nic_ops = {
	.create		= host_nic_create,
	.destroy	= host_nic_destroy,
	.start		= host_nic_start,
	.stop		= host_nic_stop,
	.pb_pack	= host_nic_pack,
	.pb_unpack	= host_nic_unpack,
	.match		= host_nic_match,
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

static void veth_free(struct ct_net_veth *vn)
{
	xfree(vn->v.host_name);
	xfree(vn->v.ct_name);
	xfree(vn);
}

static struct ct_net *veth_create(void *arg)
{
	struct ct_net_veth_arg *va = arg;
	struct ct_net_veth *vn;

	if (!arg || !va->host_name || !va->ct_name)
		return NULL;

	vn = xmalloc(sizeof(*vn));
	if (!vn)
		return NULL;

	vn->v.host_name = xstrdup(va->host_name);
	vn->v.ct_name = xstrdup(va->ct_name);
	if (!vn->v.host_name || !vn->v.ct_name) {
		veth_free(vn);
		return NULL;
	}

	return &vn->n;
}

static void veth_destroy(struct ct_net *n)
{
	veth_free(cn2vn(n));
}

static int veth_start(struct container *ct, struct ct_net *n)
{
	struct ct_net_veth *vn = cn2vn(n);

	if (veth_pair_create(&vn->v, ct->root_pid))
		return -1;

	return 0;
}

static void veth_stop(struct container *ct, struct ct_net *n)
{
	/* 
	 * FIXME -- don't destroy veth here, keep it across
	 * container's restarts. This needs checks in the
	 * veth_pair_create() for existance.
	 */
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
	if (va) {
		va->host_name = req->nicname;
		va->ct_name = req->peername;
	}

	return va;
}

static int veth_match(struct ct_net *n, void *arg)
{
	struct ct_net_veth *vn = cn2vn(n);
	struct ct_net_veth_arg *va = arg;

	/* Matching hostname should be enough */
	return !strcmp(vn->v.host_name, va->host_name);
}

static const struct ct_net_ops veth_nic_ops = {
	.create		= veth_create,
	.destroy	= veth_destroy,
	.start		= veth_start,
	.stop		= veth_stop,
	.pb_pack	= veth_pack,
	.pb_unpack	= veth_unpack,
	.match		= veth_match,
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
