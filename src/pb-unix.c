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

static int pbunix_req_ct(ct_handler_t h, RpcRequest *req, RpcResponce **respp)
{
	RpcResponce *resp;

	resp = pbunix_req(ch2c(h)->ses, req);
	if (!resp)
		return -1;
	if (!respp)
		rpc_responce__free_unpacked(resp, NULL);
	else
		*respp = resp;
	return 0;
}

static inline void pack_ct_req(RpcRequest *req, int t, ct_handler_t h)
{
	struct container_proxy *cp;

	cp = ch2c(h);
	req->req = t;
	req->has_ct_rid = true;
	req->ct_rid = cp->rid;
}

static void send_destroy_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_DESTROY, h);
	pbunix_req_ct(h, &req, NULL);
	/* FIXME what if it fails? */
	xfree(ch2c(h));
}

static enum ct_state send_get_state_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	RpcResponce *resp;
	enum ct_state st = CT_ERROR;

	pack_ct_req(&req, REQ_TYPE__CT_GET_STATE, h);
	if (!pbunix_req_ct(h, &req, &resp)) {
		st = resp->state->state;
		rpc_responce__free_unpacked(resp, NULL);
	}

	return st;
}

static int send_spawn_req(ct_handler_t h, char *path, char **argv)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SpawnReq sr = SPAWN_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_SPAWN, h);
	req.spawn = &sr;

	sr.path = path;
	for (sr.n_args = 0; argv[sr.n_args]; sr.n_args++)
		;
	sr.args = argv;

	return pbunix_req_ct(h, &req, NULL);
}

static int send_kill_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	pack_ct_req(&req, REQ_TYPE__CT_KILL, h);
	return pbunix_req_ct(h, &req, NULL);
}

static int send_wait_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	pack_ct_req(&req, REQ_TYPE__CT_WAIT, h);
	return pbunix_req_ct(h, &req, NULL);
}

static int send_nsmask_req(ct_handler_t h, unsigned long nsmask)
{
	RpcRequest req = RPC_REQUEST__INIT;
	NsmaskReq nm = NSMASK_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_SETNSMASK, h);
	req.nsmask = &nm;
	nm.mask = nsmask;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_addcntl_req(ct_handler_t h, enum ct_controller ctype)
{
	RpcRequest req = RPC_REQUEST__INIT;
	AddcntlReq ac = ADDCNTL_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_ADD_CNTL, h);
	req.addcntl = &ac;
	ac.ctype = ctype;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_setroot_req(ct_handler_t h, char *root)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetrootReq sr = SETROOT_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__FS_SETROOT, h);
	req.setroot = &sr;
	sr.root = root;
	return pbunix_req_ct(h, &req, NULL);
}

static const struct container_ops pbunix_ct_ops = {
	.get_state = send_get_state_req,
	.spawn_execv = send_spawn_req,
	.destroy = send_destroy_req,
	.kill = send_kill_req,
	.wait = send_wait_req,
	.set_nsmask = send_nsmask_req,
	.add_controller = send_addcntl_req,
	.fs_set_root = send_setroot_req,
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
