#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "rpc.h"

#include "protobuf/rpc.pb-c.h"

#define MAX_MSG		4096

/* Buffer for keeping serialized messages */
static unsigned char dbuf[MAX_MSG];

int send_err_resp(int sk, int err)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	size_t len;

	resp.success	= false;
	resp.has_error	= true;
	resp.error	= err;

	len = rpc_responce__pack(&resp, dbuf);
	if (len > 0)
		return send(sk, dbuf, len, 0);

	return 0;
}

int do_send_resp(int sk, int err, RpcResponce *resp)
{
	size_t len;

	if (err)
		return send_err_resp(sk, err);

	resp->success = true;
	/* FIXME -- boundaries check */
	len = rpc_responce__pack(resp, dbuf);
	if (send(sk, dbuf, len, 0) != len)
		return -1;
	else
		return 0;
}

int send_resp(int sk, int err)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	return do_send_resp(sk, err, &resp);
}

