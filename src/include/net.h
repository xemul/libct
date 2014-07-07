#ifndef __LIBCT_NET_H__
#define __LIBCT_NET_H__

#include "uapi/libct.h"

#include "list.h"

struct _NetaddReq;
struct container;

extern ct_net_t local_net_add(ct_handler_t h, enum ct_net_type, void *arg);
extern int local_net_del(ct_handler_t h, enum ct_net_type, void *arg);
extern void net_release(struct container *ct);
extern int net_start(struct container *ct);
extern void net_stop(struct container *ct);

struct ct_net_ops {
	struct ct_net *(*create)(void *arg, struct ct_net_ops const *ops);
	int (*start)(struct container *ct, struct ct_net *n);
	void (*stop)(struct container *ct, struct ct_net *n);
	void (*destroy)(struct ct_net *n);
	int (*match)(struct ct_net *n, void *arg);
	int (*set_mac_addr)(struct ct_net *n, char *addr);
	int (*set_master)(struct ct_net *n, char *master);
	int (*add_ip_addr)(ct_net_t n, char *addr);
};

struct ct_net_ip_addr {
	char *addr;
	struct list_head l;
};

struct ct_net {
	int ifidx;
	char *name;
	char *addr;
	char *master;

	struct list_head ip_addrs;

	struct list_head	l;
	const struct ct_net_ops	*ops;
};

extern const struct ct_net_ops *net_get_ops(enum ct_net_type);

#endif /* __LIBCT_NET_H__ */
