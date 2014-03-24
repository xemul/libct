#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include "uapi/libct.h"
#include "session.h"
#include "compiler.h"
#include "list.h"
#include "xmalloc.h"
#include "ct.h"
#include "protobuf/rpc.pb-c.h"

#define MAX_MSG_ONSTACK	512

struct pbunix_session {
	int sk;
	struct libct_session s;
};

static inline struct pbunix_session *s2us(libct_session_t s)
{
	return container_of(s, struct pbunix_session, s);
}

static RpcResponce *pbunix_req(struct pbunix_session *us, RpcRequest *req)
{
	int len, ret;
	unsigned char *data, dbuf[MAX_MSG_ONSTACK];
	RpcResponce *resp = NULL;

	len = rpc_request__get_packed_size(req);
	if (len > MAX_MSG_ONSTACK) {
		data = xmalloc(len);
		if (!data)
			goto out_nd;
	} else
		data = dbuf;

	ret = rpc_request__pack(req, data);
	if (ret != len)
		goto out;

	ret = send(us->sk, data, len, 0);
	if (ret != len)
		goto out;

	len = recv(us->sk, dbuf, MAX_MSG_ONSTACK, 0);
	if (len < 0)
		goto out;

	resp = rpc_responce__unpack(NULL, len, dbuf);
	if (!resp->success) {
		rpc_responce__free_unpacked(resp, NULL);
		resp = NULL;
	}
out:
	if (data != dbuf)
		xfree(data);
out_nd:
	return resp;
}

struct container_proxy {
	struct ct_handler h;
	unsigned long rid;
	struct pbunix_session *ses;
};

static inline struct container_proxy *ch2c(ct_handler_t h)
{
	return container_of(h, struct container_proxy, h);
}

static void send_destroy_req(ct_handler_t h)
{
	struct container_proxy *cp;
	RpcRequest req = RPC_REQUEST__INIT;
	RpcResponce *resp;

	cp = ch2c(h);

	req.req = REQ_TYPE__CT_DESTROY;
	req.has_ct_rid = true;
	req.ct_rid = cp->rid;

	resp = pbunix_req(cp->ses, &req);
	if (resp)
		rpc_responce__free_unpacked(resp, NULL);

	xfree(cp);
}

static const struct container_ops pbunix_ct_ops = {
	.destroy = send_destroy_req,
};

static ct_handler_t send_create_req(libct_session_t s)
{
	struct pbunix_session *us;
	struct container_proxy *cp;
	RpcRequest req = RPC_REQUEST__INIT;
	CreateReq cr = CREATE_REQ__INIT;
	RpcResponce *resp;

	us = s2us(s);

	cp = xmalloc(sizeof(*cp));
	if (!cp)
		return NULL;

	req.req = REQ_TYPE__CT_CREATE;
	req.create = &cr;

	resp = pbunix_req(us, &req);
	if (!resp) {
		xfree(cp);
		return NULL;
	}

	cp->h.ops = &pbunix_ct_ops;
	cp->rid = resp->create->rid;
	cp->ses = us;

	rpc_responce__free_unpacked(resp, NULL);

	return &cp->h;
}

static void close_pbunix_session(libct_session_t s)
{
	struct pbunix_session *us;

	us = s2us(s);
	close(us->sk);
	xfree(us);
}

static const struct backend_ops pbunix_session_ops = {
	.create_ct = send_create_req,
	.close = close_pbunix_session,
};

libct_session_t libct_session_open_pbunix(char *sk_path)
{
	struct pbunix_session *us;
	struct sockaddr_un addr;
	socklen_t alen;

	us = xmalloc(sizeof(*us));
	if (us == NULL)
		return NULL;

	us->sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (us->sk == -1)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sk_path, sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	if (connect(us->sk, (struct sockaddr *)&addr, alen))
		goto err;

	us->s.ops = &pbunix_session_ops;
	return &us->s;

err:
	xfree(us);
	return NULL;
}
