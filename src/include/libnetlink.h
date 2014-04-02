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

int nla_put_string(struct nlmsghdr *h, int attr, const char *string);
int nla_put_u32(struct nlmsghdr *h, int attr, int value);

int netlink_talk(int nlfd, struct nlmsghdr *request, struct nlmsghdr *answer);
#endif
