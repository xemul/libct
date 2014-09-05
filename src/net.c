#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>

#include <netinet/ether.h>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include "uapi/libct.h"

#include "namespaces.h"
#include "xmalloc.h"
#include "util.h"
#include "list.h"
#include "util.h"
#include "err.h"
#include "net.h"
#include "ct.h"

/*
 * Generic Linux networking management
 */

struct nl_sock *net_sock_open()
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc();
	if (sk == NULL)
		return NULL;

	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		nl_socket_free(sk);
		pr_err("Unable to connect socket: %s", nl_geterror(err));
		return NULL;
	}

	return sk;
}

void net_sock_close(struct nl_sock *sk)
{
	if (sk == NULL)
		return;

	nl_close(sk);
	nl_socket_free(sk);

	return;
}

struct nl_cache *net_get_link_cache(struct nl_sock *sk)
{
	struct nl_cache *cache;
	int err;

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err) {
		pr_err("Unable to alloc link cache: %s", nl_geterror(err));
		return NULL;
	}

	return cache;
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

	net_route_release(ct);
}

int net_start(struct container *ct)
{
	struct ct_net *cn;

	list_for_each_entry(cn, &ct->ct_nets, l) {
		if (cn->ops->start(ct, cn))
			goto err;
	}

	if (net_route_setup(ct))
		goto err;

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

static int __net_add_ip_addr(struct nl_sock *sk, ct_net_t n, char *saddr)
{
	struct rtnl_addr *addr;
	struct nl_addr *l;
	int err, ret = -1;

	err = nl_addr_parse(saddr, AF_UNSPEC, &l);
	if (err) {
		pr_err("Unable to parse address: %s\n", nl_geterror(err));
		return -1;
	}

	addr = rtnl_addr_alloc();
	if (addr == NULL)
		goto err;

	rtnl_addr_set_local(addr, l);
	rtnl_addr_set_ifindex(addr, n->ifidx);
	err = rtnl_addr_add(sk, addr, 0);
	if (err) {
		pr_err("Unable to add %s: %s\n", saddr, nl_geterror(err));
		goto err;
	}

	ret = 0;
err:
	nl_addr_put(l);
	rtnl_addr_put(addr);
	return ret;
}

static int net_add_ip_addrs(struct nl_sock *sk, ct_net_t n)
{
	struct ct_net_ip_addr *addr;

	list_for_each_entry(addr, &n->ip_addrs, l) {
		if (__net_add_ip_addr(sk, n, addr->addr))
			goto err;
	}

	return 0;
err:
	// FIXME rollback
	return -1;
}

static int __net_link_apply(char *name, ct_net_t n)
{
	struct rtnl_link *link = NULL, *orig = NULL;
	struct nl_cache *cache = NULL;
	struct nl_sock *sk;
	int err = -1;

	sk = net_sock_open();
	if (sk == NULL)
		return -1;

	cache = net_get_link_cache(sk);
	if (sk == NULL)
		goto free;

	orig = rtnl_link_get_by_name(cache, name);
	if (orig == NULL)
		goto free;

	link = rtnl_link_alloc();
	if (link == NULL)
		goto free;

	rtnl_link_set_name(link, n->name);

	if (n->addr) {
		struct nl_addr* addr;

		addr = nl_addr_build(AF_LLC, ether_aton(n->addr), ETH_ALEN);
		if (addr == NULL)
			goto free;
		rtnl_link_set_addr(link, addr);
	}

	if (n->master) {
		int idx;

		idx = rtnl_link_name2i(cache, n->master);
		if (idx == 0)
			goto free;

		rtnl_link_set_master(link, idx);
	}

	if (n->mtu)
		rtnl_link_set_mtu(link, n->mtu);

	rtnl_link_set_flags(link, IFF_UP);

	err = rtnl_link_change(sk, orig, link, 0);
	if (err) {
		pr_err("Unable to change link %s: %s", n->name, nl_geterror(err));
		goto free;
	}

	err = -1;
	if (nl_cache_refill(sk, cache))
		goto free;

	n->ifidx = rtnl_link_name2i(cache, n->name);
	if ( n->ifidx == 0)
		goto free;

	if (net_add_ip_addrs(sk, n))
		goto free;
	err = 0;
free:
	rtnl_link_put(link);
	rtnl_link_put(orig);
	nl_cache_put(cache);
	net_sock_close(sk);
	return err;
}

static int net_link_apply(char *name, ct_net_t n, int pid)
{
	int rst, ret;

	if (pid > 0 && switch_ns(pid, &net_ns, &rst))
		return -1;

	ret = __net_link_apply(name, n);

	if (pid > 0)
		restore_ns(rst, &net_ns);

	return ret;
}

ct_net_t local_net_add(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	struct container *ct = cth2ct(h);
	const struct ct_net_ops *nops;
	struct ct_net *cn;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return ERR_PTR(-LCTERR_BADCTSTATE);

	if (!(ct->nsmask & CLONE_NEWNET))
		return ERR_PTR(-LCTERR_NONS);

	if (ntype == CT_NET_NONE)
		return 0;

	nops = net_get_ops(ntype);
	if (!nops)
		return ERR_PTR(-LCTERR_BADTYPE);

	cn = nops->create(arg, nops);
	if (!cn)
		return ERR_PTR(-LCTERR_BADARG);

	list_add_tail(&cn->l, &ct->ct_nets);
	return cn;
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

int local_net_dev_set_mac_addr(ct_net_t n, char *addr)
{
	return set_string(&n->addr, addr);
}

int local_net_dev_set_master(ct_net_t n, char *master)
{
	return set_string(&n->master, master);
}

int local_net_dev_add_ip_addr(ct_net_t n, char *addr)
{
	struct ct_net_ip_addr *a;

	a = xzalloc(sizeof(*a));
	if (a == NULL)
		return -1;

	a->addr = xstrdup(addr);
	if (a->addr == NULL) {
		xfree(a);
		return -1;
	}

	list_add(&a->l, &n->ip_addrs);

	return 0;
}

int local_net_dev_set_mtu(ct_net_t n, int mtu)
{
	n->mtu = mtu;

	return 0;
}

ct_net_t libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_add(ct, ntype, arg);
}

int libct_net_del(ct_handler_t ct, enum ct_net_type ntype, void *arg)
{
	return ct->ops->net_del(ct, ntype, arg);
}

int libct_net_dev_set_mac_addr(ct_net_t n, char *addr)
{
	return n->ops->set_mac_addr(n, addr);
}

int libct_net_dev_set_master(ct_net_t n, char *master)
{
	return n->ops->set_master(n, master);
}

int libct_net_dev_add_ip_addr(ct_net_t n, char *addr)
{
	return n->ops->add_ip_addr(n, addr);
}

int libct_net_dev_set_mtu(ct_net_t n, int mtu)
{
	return n->ops->set_mtu(n, mtu);
}

static void ct_net_init(ct_net_t n, const struct ct_net_ops *ops)
{
	INIT_LIST_HEAD(&n->ip_addrs);
	n->name = NULL;
	n->ops = ops;
}

static void ct_net_clean(ct_net_t n)
{
	struct ct_net_ip_addr *addr, *t;

	xfree(n->name);
	xfree(n->addr);
	xfree(n->master);

	list_for_each_entry_safe(addr, t, &n->ip_addrs, l) {
		xfree(addr->addr);
		xfree(addr);
	}
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

static struct ct_net *host_nic_create(void *arg, const struct ct_net_ops *ops)
{
	struct ct_net_host_nic *cn;

	if (!arg)
		return NULL;

	cn = xzalloc(sizeof(*cn));
	if (cn == NULL)
		return NULL;

	cn->name = xstrdup(arg);
	if (cn->name == NULL) {
		xfree(cn);
		return NULL;
	}

	ct_net_init(&cn->n, ops);

	cn->n.name = xstrdup(arg);
	if (cn->n.name == NULL) {
		ct_net_clean(&cn->n);
		xfree(cn);
		return NULL;
	}

	return &cn->n;
}

static void host_nic_destroy(struct ct_net *n)
{
	struct ct_net_host_nic *cn = cn2hn(n);

	ct_net_clean(&cn->n);
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
	rtnl_link_set_name(link, n->name);

	if ((err = rtnl_link_change(sk, orig, link, 0)) < 0) {
		pr_err("Unable to change link: %s", nl_geterror(err));
		goto free;
	}

	if (net_link_apply(n->name, n, ct->root_pid))
		return -1;
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
	.set_mac_addr	= local_net_dev_set_mac_addr,
	.set_master	= local_net_dev_set_master,
	.add_ip_addr	= local_net_dev_add_ip_addr,
	.set_mtu	= local_net_dev_set_mtu,
};

/*
 * CT_NET_VETH management
 */

struct ct_net_veth {
	struct ct_net n;
	struct ct_net peer;
};

static struct ct_net_veth *cn2vn(struct ct_net *n)
{
	return container_of(n, struct ct_net_veth, n);
}

static void veth_free(struct ct_net_veth *vn)
{
	ct_net_clean(&vn->n);
	ct_net_clean(&vn->peer);
	xfree(vn);
}

static struct ct_net *veth_create(void *arg, const struct ct_net_ops *ops)
{
	struct ct_net_veth_arg *va = arg;
	struct ct_net_veth *vn;

	if (!arg || !va->host_name || !va->ct_name)
		return NULL;

	vn = xzalloc(sizeof(*vn));
	if (!vn)
		return NULL;

	ct_net_init(&vn->n, ops);
	ct_net_init(&vn->peer, ops);

	vn->peer.name = xstrdup(va->host_name);
	vn->n.name = xstrdup(va->ct_name);
	if (!vn->peer.name || !vn->n.name) {
		xfree(vn->peer.name);
		xfree(vn->n.name);
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
	int err, ret = -1;
	char name[IFNAMSIZ];

	snprintf(name, sizeof(name), "libct-%x", getpid());

	sk = net_sock_open();
	if (sk == NULL)
		return -1;

	link = rtnl_link_veth_alloc();
	if (link == NULL)
		goto err;

	rtnl_link_set_name(link, name);
	rtnl_link_set_ns_pid(link, ct->root_pid);

	peer = rtnl_link_veth_get_peer(link);
	rtnl_link_set_name(peer, vn->peer.name);
	rtnl_link_put(peer);

	err = rtnl_link_add(sk, link, NLM_F_CREATE);
	if (err < 0) {
		pr_err("Unable to add link: %s\n", nl_geterror(err));
		goto err;
	}

	if (net_link_apply(name, n, ct->root_pid))
		goto err;
	if (net_link_apply(vn->peer.name, &vn->peer, -1))
		goto err; /* FIXME rollback */

	ret = 0;
err:
	rtnl_link_put(link);
	net_sock_close(sk);
	return ret;
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
	return !strcmp(vn->peer.name, va->host_name);
}

static const struct ct_net_ops veth_nic_ops = {
	.create		= veth_create,
	.destroy	= veth_destroy,
	.start		= veth_start,
	.stop		= veth_stop,
	.match		= veth_match,
	.set_mac_addr	= local_net_dev_set_mac_addr,
	.set_master	= local_net_dev_set_master,
	.add_ip_addr	= local_net_dev_add_ip_addr,
	.set_mtu	= local_net_dev_set_mtu,
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

ct_net_t libct_net_dev_get_peer(ct_net_t n)
{
	struct ct_net_veth *vn = cn2vn(n);

	return &vn->peer;
}
