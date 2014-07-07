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
	struct ct_net *(*create)(void *arg);
	int (*start)(struct container *ct, struct ct_net *n);
	void (*stop)(struct container *ct, struct ct_net *n);
	void (*destroy)(struct ct_net *n);
	int (*match)(struct ct_net *n, void *arg);
	void (*pb_pack)(void *arg, struct _NetaddReq *req);
	void *(*pb_unpack)(struct _NetaddReq *req);
};

struct ct_net {
	char *name;

	struct list_head	l;
	const struct ct_net_ops	*ops;
};

extern const struct ct_net_ops *net_get_ops(enum ct_net_type);

#endif /* __LIBCT_NET_H__ */
