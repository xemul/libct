/*
 * Netlink stuff. Taken and combined from LXC, CRIU and iproute2 projects
 */

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include "xmalloc.h"
#include "libnetlink.h"

#ifndef NLMSG_ERROR
#define NLMSG_ERROR 0x2
#endif
#define NLMSG_MIN_SIZE	1024
#define NLMSG_TAIL(m) ((struct rtattr *) (((void *) (m)) + NLMSG_ALIGN((m)->nlmsg_len)))

struct nlmsghdr *nlmsg_alloc(int base_size)
{
	struct nlmsghdr *h;
	size_t len;
	
	len = NLMSG_ALIGN(NLMSG_MIN_SIZE) + NLMSG_ALIGN(sizeof(struct nlmsghdr *));
	h = xmalloc(len);
	if (h) {
		memset(h, 0, len);
		h->nlmsg_len = NLMSG_LENGTH(base_size);
	}

	return h;
}

void nlmsg_free(struct nlmsghdr *h)
{
	xfree(h);
}

static int nla_put(struct nlmsghdr *h, int attr, const void *data, size_t len)
{
	struct rtattr *rta;
	size_t rtalen = RTA_LENGTH(len);

	rta = NLMSG_TAIL(h);
	rta->rta_type = attr;
	rta->rta_len = rtalen;
	memcpy(RTA_DATA(rta), data, len);
	h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(rtalen);

	return 0;
}

int nla_put_string(struct nlmsghdr *h, int attr, const char *string)
{
	return nla_put(h, attr, string, strlen(string) + 1);
}

int nla_put_u32(struct nlmsghdr *h, int attr, int value)
{
	return nla_put(h, attr, &value, sizeof(value));
}

static int nl_send(int nlfd, struct nlmsghdr *h)
{
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = h,
		.iov_len = h->nlmsg_len,
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int ret;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	ret = sendmsg(nlfd, &msg, 0);
	if (ret < 0)
		return -errno;

	return ret;
}

static int nl_rcv(int nlfd, struct nlmsghdr *h)
{
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = h,
		.iov_len = h->nlmsg_len,
	};

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int ret;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

again:
	ret = recvmsg(nlfd, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;
		return -errno;
	}

	if (!ret)
		return 0;
	if (msg.msg_flags & MSG_TRUNC && ret == h->nlmsg_len)
		return -EMSGSIZE;

	return ret;
}

int netlink_talk(int nlfd, struct nlmsghdr *request, struct nlmsghdr *answer)
{
	int ret;

	ret = nl_send(nlfd, request);
	if (ret < 0)
		return ret;

	ret = nl_rcv(nlfd, answer);
	if (ret < 0)
		return ret;

	if (answer->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(answer);
		return err->error;
	}

	return 0;
}
