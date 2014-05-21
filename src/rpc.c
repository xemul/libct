#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "xmalloc.h"
#include "session.h"
#include "list.h"
#include "log.h"
#include "rpc.h"

#include "protobuf/rpc.pb-c.h"

#define MAX_MSG		4096

/* Buffer for keeping serialized messages */
static unsigned char dbuf[MAX_MSG];

#define MAX_FDS 3
static int dfds[MAX_FDS];

int do_send_resp(int sk, RpcRequest *req, int err, RpcResponce *resp)
{
	size_t len;

	resp->req_id = req->req_id;

	if (err) {
		resp->success	= false;
		resp->has_error	= true;
		resp->error	= err;
	} else
		resp->success = true;

	/* FIXME -- boundaries check */
	len = rpc_responce__pack(resp, dbuf);
	if (send(sk, dbuf, len, 0) != len)
		return -1;
	else
		return 0;
}

int send_resp(int sk, RpcRequest *req, int err)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	return do_send_resp(sk, req, err, &resp);
}

static int do_recv_req(int sk, unsigned char *buf, size_t count, int *fds, int *nr_fds)
{
	char control[1024];
	struct msghdr	msg;
	struct cmsghdr	*cmsg;
	struct iovec	iov;
	int i, nr = 0, ret;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base   = buf;
	iov.iov_len    = count;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	ret = recvmsg(sk, &msg, 0);
	if (ret < 0) {
		pr_perror("Unable to receive data");
		return -1;
	}
	if (ret == 0)
		return 0;

	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg != NULL) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type  == SCM_RIGHTS) {
			nr = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

			if (nr > *nr_fds)
				return -1;

			for (i = 0; i < nr; i++)
				fds[i] = *((int *) CMSG_DATA(cmsg) + i);

			break;
		}
                cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	*nr_fds = nr;

	return ret;
}

int recv_req(int sk, RpcRequest **req, int **fds, int *nr_fds)
{
	int ret;

	*nr_fds = MAX_FDS;

	ret = do_recv_req(sk, dbuf, MAX_MSG, dfds, nr_fds);
	if (ret <= 0)
		return ret;

	*req = rpc_request__unpack(NULL, ret, dbuf);
	if (!*req)
		return -1;

	*fds = dfds;

	return ret;
}
