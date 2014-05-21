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
