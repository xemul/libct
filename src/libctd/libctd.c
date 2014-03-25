/*
 * Daemon that gets requests from remote library backend
 * and forwards them to local session.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include "uapi/libct.h"
#include "list.h"
#include "xmalloc.h"
#include "../protobuf/rpc.pb-c.h"

#define MAX_MSG_ONSTACK	2048
#define BADCTRID_ERR	-42

struct container_srv {
	struct list_head l;
	unsigned long rid;
	ct_handler_t hnd;
};

static LIST_HEAD(ct_srvs);
static unsigned long rids = 1;

static struct container_srv *find_ct_by_rid(unsigned long rid)
{
	struct container_srv *cs;

	list_for_each_entry(cs, &ct_srvs, l)
		if (cs->rid == rid)
			return cs;

	return NULL;
}

static int send_err_resp(int sk, int err)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	unsigned char dbuf[MAX_MSG_ONSTACK];
	int len;

	resp.success = false;
	len = rpc_responce__pack(&resp, dbuf);
	if (len > 0)
		send(sk, dbuf, len, 0);

	return 0;
}

static int send_resp(int sk, RpcResponce *resp)
{
	unsigned char dbuf[MAX_MSG_ONSTACK];
	int len;

	resp->success = true;

	/* FIXME -- boundaries check */
	len = rpc_responce__pack(resp, dbuf);
	if (send(sk, dbuf, len, 0) != len)
		return -1;
	else
		return 0;
}

static int serve_ct_create(int sk, libct_session_t ses, CreateReq *req)
{
	struct container_srv *cs;
	RpcResponce resp = RPC_RESPONCE__INIT;
	CreateResp cr = CREATE_RESP__INIT;

	cs = xmalloc(sizeof(*cs));
	if (!cs)
		goto err0;

	cs->hnd = libct_container_create(ses);
	if (!cs->hnd) {
		xfree(cs);
		goto err1;
	}

	cs->rid = rids++;

	resp.create = &cr;
	cr.rid = cs->rid;

	if (send_resp(sk, &resp))
		goto err2;

	list_add_tail(&cs->l, &ct_srvs);
	return 0;

err2:
	libct_container_destroy(cs->hnd);
err1:
	xfree(cs);
err0:
	return send_err_resp(sk, -1);
}

static int serve_ct_destroy(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;

	list_del(&cs->l);
	libct_container_destroy(cs->hnd);
	xfree(cs);

	return send_resp(sk, &resp);
}

static int serve_get_state(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	StateResp gs = STATE_RESP__INIT;

	resp.state = &gs;
	gs.state = libct_container_state(cs->hnd);

	return send_resp(sk, &resp);
}

static int serve_spawn(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->spawn)
		ret = libct_container_spawn_execv(cs->hnd, req->spawn->path, req->spawn->args);
	if (ret)
		return send_err_resp(sk, ret);

	return send_resp(sk, &resp);
}

static int serve_kill(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret;

	ret = libct_container_kill(cs->hnd);
	if (ret)
		return send_err_resp(sk, -1);

	return send_resp(sk, &resp);
}

static int serve_wait(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret;

	ret = libct_container_wait(cs->hnd);
	if (ret)
		return send_err_resp(sk, -1);

	return send_resp(sk, &resp);
}

static int serve_setnsmask(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->nsmask)
		ret = libct_container_set_nsmask(cs->hnd, req->nsmask->mask);
	if (ret)
		return send_err_resp(sk, ret);

	return send_resp(sk, &resp);
}

static int serve_addcntl(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->addcntl)
		ret = libct_container_add_controller(cs->hnd, req->addcntl->ctype);
	if (ret)
		return send_err_resp(sk, ret);

	return send_resp(sk, &resp);
}

static int serve_req(int sk, libct_session_t ses, RpcRequest *req)
{
	struct container_srv *cs = NULL;

	if (req->req == REQ_TYPE__CT_CREATE)
		return serve_ct_create(sk, ses, req->create);

	if (req->has_ct_rid)
		cs = find_ct_by_rid(req->ct_rid);
	if (!cs)
		return send_err_resp(sk, BADCTRID_ERR);

	switch (req->req) {
	case REQ_TYPE__CT_DESTROY:
		return serve_ct_destroy(sk, cs, req);
	case REQ_TYPE__CT_GET_STATE:
		return serve_get_state(sk, cs, req);
	case REQ_TYPE__CT_SPAWN:
		return serve_spawn(sk, cs, req);
	case REQ_TYPE__CT_KILL:
		return serve_kill(sk, cs, req);
	case REQ_TYPE__CT_WAIT:
		return serve_wait(sk, cs, req);
	case REQ_TYPE__CT_SETNSMASK:
		return serve_setnsmask(sk, cs, req);
	case REQ_TYPE__CT_ADD_CNTL:
		return serve_addcntl(sk, cs, req);
	default:
		break;
	}

	return -1;
}

static int serve(int sk)
{
	RpcRequest *req;
	int ret;
	unsigned char dbuf[MAX_MSG_ONSTACK];
	libct_session_t ses;

	ses = libct_session_open_local();
	if (!ses)
		return -1;

	while (1) {
		ret = recv(sk, dbuf, MAX_MSG_ONSTACK, 0);
		if (ret <= 0)
			break;

		req = rpc_request__unpack(NULL, ret, dbuf);
		if (!req) {
			ret = -1;
			break;
		}

		ret = serve_req(sk, ses, req);
		rpc_request__free_unpacked(req, NULL);

		if (ret < 0)
			break;
	}

	libct_session_close(ses);
	return ret;
}

int main(int argc, char **argv)
{
	int sk;
	struct sockaddr_un addr;
	socklen_t alen;

	sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (sk == -1)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	unlink(addr.sun_path);
	if (bind(sk, (struct sockaddr *)&addr, alen))
		goto err;

	if (listen(sk, 16))
		goto err;

	signal(SIGCHLD, SIG_IGN); /* auto-kill zombies */

	while (1) {
		int ask;

		alen = sizeof(addr);
		ask = accept(sk, (struct sockaddr *)&addr, &alen);
		if (ask < 0)
			continue;

		if (fork() == 0) {
			int ret;

			ret = serve(ask);
			if (ret < 0)
				ret = -ret;

			close(ask);
			exit(ret);
		}

		close(ask);
	}

err:
	return 1;
}
