#ifndef __CT_LIBNL_H__
#define __CT_LIBNL_H__

#include <unistd.h>

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static inline int netlink_open(int protocol)
{
	return socket(AF_NETLINK, SOCK_RAW, protocol);
}

static inline void netlink_close(int nlfd)
{
	close(nlfd);
}

extern struct nlmsghdr *nlmsg_alloc(int base_size);
extern void nlmsg_free(struct nlmsghdr *h);

extern int nla_put(struct nlmsghdr *h, int attr, const void *data, size_t len);
extern int nla_put_string(struct nlmsghdr *h, int attr, const char *string);
extern int nla_put_u32(struct nlmsghdr *h, int attr, int value);

#define NLMSG_TAIL(m) ((struct rtattr *) (((void *) (m)) + NLMSG_ALIGN((m)->nlmsg_len)))

static inline struct rtattr *nla_put_nested(struct nlmsghdr *h, int attr)
{
	struct rtattr *a;

	a = NLMSG_TAIL(h);
	if (nla_put(h, attr, NULL, 0))
		return NULL;

	return a;
}

static inline void nla_commit_nested(struct nlmsghdr *h, struct rtattr *a)
{
	a->rta_len = (void *)NLMSG_TAIL(h) - (void *)a;
}

extern int netlink_talk(int nlfd, struct nlmsghdr *request, struct nlmsghdr *answer);

#endif /* __CT_LIBNL_H__ */
