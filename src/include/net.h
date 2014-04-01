#ifndef __LIBCT_NET_H__
#define __LIBCT_NET_H__
struct _NetaddReq;

int local_net_add(ct_handler_t h, enum ct_net_type, void *);
void free_netconf(struct container *ct);

struct ct_net_ops {
	void (*pb_pack)(void *arg, struct _NetaddReq *);
	void *(*pb_unpack)(struct _NetaddReq *);
};

const struct ct_net_ops *net_get_ops(enum ct_net_type);
#endif
