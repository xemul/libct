#ifndef __CT_LIBNL_H__
#define __CT_LIBNL_H__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

static inline int netlink_open(int protocol)
{
	return socket(AF_NETLINK, SOCK_RAW, protocol);
}

static inline void netlink_close(int nlfd)
{
	close(nlfd);
}

struct nlmsghdr *nlmsg_alloc(int base_size);
void nlmsg_free(struct nlmsghdr *h);

int nla_put(struct nlmsghdr *h, int attr, const void *data, size_t len);
int nla_put_string(struct nlmsghdr *h, int attr, const char *string);
int nla_put_u32(struct nlmsghdr *h, int attr, int value);

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

int netlink_talk(int nlfd, struct nlmsghdr *request, struct nlmsghdr *answer);
#endif
