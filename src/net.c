#include <stdio.h>
#include <sched.h>

#include <netinet/ether.h>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>

#include "uapi/libct.h"

#include "xmalloc.h"
#include "list.h"
#include "net.h"
#include "ct.h"

/*
 * Generic Linux networking management
 */

static struct nl_sock *net_sock_open()
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc();
	if (sk == NULL)
		return NULL;

	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		nl_socket_free(sk);
		pr_perror("Unable to connect socket: %s", nl_geterror(err));
		return NULL;
	}

	return sk;
}

static void net_sock_close(struct nl_sock *sk)
{
	if (sk == NULL)
		return;

	nl_close(sk);
	nl_socket_free(sk);

	return;
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
		return -LCTERR_BADCTSTATE;

	if (!(ct->nsmask & CLONE_NEWNET))
		return -LCTERR_NONS;

	if (ntype == CT_NET_NONE)
		return 0;

	nops = net_get_ops(ntype);
	if (!nops)
		return -LCTERR_BADTYPE;

	cn = nops->create(arg);
	if (!cn)
		return -LCTERR_BADARG;

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
		return -LCTERR_BADCTSTATE;

	if (ntype == CT_NET_NONE)
		return 0;

	nops = net_get_ops(ntype);
	if (!nops)
		return -LCTERR_BADTYPE;

	list_for_each_entry(cn, &ct->ct_nets, l) {
		if (!cn->ops->match(cn, arg))
			continue;

		list_del(&cn->l);
		cn->ops->destroy(cn);
		return 0;
	}

	return -LCTERR_NOTFOUND;
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
	struct rtnl_link *orig = NULL, *link = NULL;
	char *name = cn2hn(n)->name;
	struct nl_sock *sk;
	int err = -1;

	sk = net_sock_open();
	if (sk == NULL)
		return -1;

	link = rtnl_link_alloc();
	if (link == NULL)
		goto free;
	rtnl_link_set_ns_pid(link, ct->root_pid);

	orig = rtnl_link_alloc();
	if (orig == NULL)
		goto free;

	rtnl_link_set_name(orig, name);
	rtnl_link_set_name(link, name);

	if ((err = rtnl_link_change(sk, orig, link, 0)) < 0) {
                pr_err("Unable to change link: %s", nl_geterror(err));
                goto free;
        }

free:
	rtnl_link_put(link);
	rtnl_link_put(orig);
	net_sock_close(sk);
	return err;
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
	struct rtnl_link *link = NULL, *peer;
	struct nl_sock *sk;
	int err = -1;

	sk = net_sock_open();
	if (sk == NULL)
		return -1;

	link = rtnl_link_veth_alloc();
	if (link == NULL)
		goto err;

	rtnl_link_set_name(link, vn->v.ct_name);
	rtnl_link_set_ns_pid(link, ct->root_pid);

	peer = rtnl_link_veth_get_peer(link);
	rtnl_link_set_name(peer, vn->v.host_name);
	rtnl_link_put(peer);

	err = rtnl_link_add(sk, link, NLM_F_CREATE);
	if (err < 0) {
                pr_err("Unable to add link: %s\n", nl_geterror(err));
                goto err;
        }

err:
	rtnl_link_put(link);
	net_sock_close(sk);
	return err;
}

static void veth_stop(struct container *ct, struct ct_net *n)
{
	/* 
	 * FIXME -- don't destroy veth here, keep it across
	 * container's restarts. This needs checks in the
	 * veth_pair_create() for existance.
	 */
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
