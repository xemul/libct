#ifndef __LIBCT_NET_H__
#define __LIBCT_NET_H__
struct _NetaddReq;
struct ct_net;

int local_net_add(ct_handler_t h, enum ct_net_type, void *);
void free_netconf(struct container *ct);
int net_start(struct container *ct);
void net_stop(struct container *ct);

struct ct_net_ops {
	int (*start)(struct container *, struct ct_net *);
	void (*stop)(struct container *, struct ct_net *);
	void (*destroy)(struct ct_net *);
	void (*pb_pack)(void *arg, struct _NetaddReq *);
	void *(*pb_unpack)(struct _NetaddReq *);
};

const struct ct_net_ops *net_get_ops(enum ct_net_type);
#endif
