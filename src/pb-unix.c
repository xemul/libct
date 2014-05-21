#include <unistd.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "uapi/libct.h"

#include "compiler.h"
#include "session.h"
#include "cgroups.h"
#include "xmalloc.h"
#include "list.h"
#include "util.h"
#include "net.h"
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

static RpcResponse *pbunix_req(struct pbunix_session *us, RpcRequest *req)
{
	int len, ret;
	unsigned char *data, dbuf[MAX_MSG_ONSTACK];
	RpcResponse *resp = NULL;

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

	resp = rpc_response__unpack(NULL, len, dbuf);
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

static inline void pack_ct_req(RpcRequest *req, int t, ct_handler_t h)
{
	struct container_proxy *cp;

	cp = ch2c(h);
	req->req = t;
	req->has_ct_rid = true;
	req->ct_rid = cp->rid;
}

static RpcResponse *do_pbunix_req_ct(ct_handler_t h, RpcRequest *req, int type)
{
	pack_ct_req(req, type, h);
	return pbunix_req(ch2c(h)->ses, req);
}

static inline int resp_error(RpcResponse *resp)
{
	return resp->success ? 0 : (resp->has_error ? resp->error : LCTERR_RPCUNKNOWN);
}

static inline int pbunix_req_ct(ct_handler_t h, RpcRequest *req, int type)
{
	int ret;
	RpcResponse *resp;

	resp = do_pbunix_req_ct(h, req, type);
	if (!resp)
		return LCTERR_RPCCOMM;

	ret = resp_error(resp);
	rpc_response__free_unpacked(resp, NULL);
	return ret;
}

static void detach_proxy(ct_handler_t h)
{
	xfree(ch2c(h));
}

static void send_destroy_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;

	pbunix_req_ct(h, &req, REQ_TYPE__CT_DESTROY);
	/* FIXME what if it fails? */
	detach_proxy(h);
}

static enum ct_state send_get_state_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	RpcResponse *resp;
	enum ct_state st = CT_ERROR;

	resp = do_pbunix_req_ct(h, &req, REQ_TYPE__CT_GET_STATE);
	if (resp) {
		if (!resp_error(resp) && resp->state)
			st = resp->state->state;
		rpc_response__free_unpacked(resp, NULL);
	}

	return st;
}

static int send_execve_req(ct_handler_t h, int type, char *path, char **argv, char **env)
{
	RpcRequest req = RPC_REQUEST__INIT;
	ExecvReq er = EXECV_REQ__INIT;

	req.execv = &er;

	er.path = path;
	for (er.n_args = 0; argv[er.n_args]; er.n_args++)
		;
	er.args = argv;

	if (env) {
		for (er.n_env = 0; env[er.n_env]; er.n_env++)
			;
		er.env = env;
	}

	return pbunix_req_ct(h, &req, type);
}

static int send_spawn_req(ct_handler_t h, char *path, char **argv, char **env, int *fds)
{
	return send_execve_req(h, REQ_TYPE__CT_SPAWN, path, argv, env);
}

static int send_enter_req(ct_handler_t h, char *path, char **argv, char **env)
{
	return send_execve_req(h, REQ_TYPE__CT_ENTER, path, argv, env);
}

static int send_kill_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	return pbunix_req_ct(h, &req, REQ_TYPE__CT_KILL);
}

static int send_wait_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	return pbunix_req_ct(h, &req, REQ_TYPE__CT_WAIT);
}

static int send_nsmask_req(ct_handler_t h, unsigned long nsmask)
{
	RpcRequest req = RPC_REQUEST__INIT;
	NsmaskReq nm = NSMASK_REQ__INIT;

	req.nsmask = &nm;
	nm.mask = nsmask;
	return pbunix_req_ct(h, &req, REQ_TYPE__CT_SETNSMASK);
}

static int send_addcntl_req(ct_handler_t h, enum ct_controller ctype)
{
	RpcRequest req = RPC_REQUEST__INIT;
	AddcntlReq ac = ADDCNTL_REQ__INIT;

	req.addcntl = &ac;
	ac.ctype = ctype;
	return pbunix_req_ct(h, &req, REQ_TYPE__CT_ADD_CNTL);
}

static int send_cfgcntl_req(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	RpcRequest req = RPC_REQUEST__INIT;
	CfgcntlReq cr = CFGCNTL_REQ__INIT;

	req.cfgcntl = &cr;
	cr.ctype = ctype;
	cr.param = param;
	cr.value = value;
	return pbunix_req_ct(h, &req, REQ_TYPE__CT_CFG_CNTL);
}

static int send_setroot_req(ct_handler_t h, char *root)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetrootReq sr = SETROOT_REQ__INIT;

	req.setroot = &sr;
	sr.root = root;
	return pbunix_req_ct(h, &req, REQ_TYPE__FS_SETROOT);
}

static int send_setpriv_req(ct_handler_t h, enum ct_fs_type type, void *arg)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetprivReq sp = SETPRIV_REQ__INIT;
	const struct ct_fs_ops *ops;

	ops = fstype_get_ops(type);
	if (!ops)
		return LCTERR_BADTYPE;

	req.setpriv = &sp;
	sp.type = type;
	ops->pb_pack(arg, &sp);
	return pbunix_req_ct(h, &req, REQ_TYPE__FS_SETPRIVATE);
}

static int send_set_option_req(ct_handler_t h, int opt, va_list parms)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetoptionReq so = SETOPTION_REQ__INIT;

	req.setopt = &so;
	so.opt = opt;

	switch (opt) {
	default:
		return LCTERR_BADTYPE;

	case LIBCT_OPT_AUTO_PROC_MOUNT:
	case LIBCT_OPT_KILLABLE:
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		so.cg_path = xvaopt(parms, char *, DEFAULT_CGROUPS_PATH);
		break;
	}

	return pbunix_req_ct(h, &req, REQ_TYPE__CT_SET_OPTION);
}

static int send_net_req(ct_handler_t h, enum ct_net_type ntype, void *arg, int rtype)
{
	RpcRequest req = RPC_REQUEST__INIT;
	NetaddReq na = NETADD_REQ__INIT;
	const struct ct_net_ops *nops;

	req.netadd = &na;
	na.type = ntype;

	if (ntype != CT_NET_NONE) {
		nops = net_get_ops(ntype);
		if (!nops)
			return LCTERR_BADTYPE;

		nops->pb_pack(arg, &na);
	}

	return pbunix_req_ct(h, &req, rtype);
}

static int send_netadd_req(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	return send_net_req(h, ntype, arg, REQ_TYPE__CT_NET_ADD);
}

static int send_netdel_req(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	return send_net_req(h, ntype, arg, REQ_TYPE__CT_NET_DEL);
}

static int send_add_mount_req(ct_handler_t h, char *src, char *dst, int flags)
{
	RpcRequest req = RPC_REQUEST__INIT;
	MountReq mr = MOUNT_REQ__INIT;

	req.mnt = &mr;
	mr.src = src;
	mr.dst = dst;
	mr.has_flags = true;
	mr.flags = flags;

	return pbunix_req_ct(h, &req, REQ_TYPE__FS_ADD_MOUNT);
}

static int send_del_mount_req(ct_handler_t h, char *dst)
{
	RpcRequest req = RPC_REQUEST__INIT;
	MountReq mr = MOUNT_REQ__INIT;

	req.mnt = &mr;
	mr.dst = dst;

	return pbunix_req_ct(h, &req, REQ_TYPE__FS_DEL_MOUNT);
}

static int send_uname_req(ct_handler_t h, char *host, char *dom)
{
	RpcRequest req = RPC_REQUEST__INIT;
	UnameReq ur = UNAME_REQ__INIT;

	req.uname = &ur;
	ur.host = host;
	ur.domain = dom;

	return pbunix_req_ct(h, &req, REQ_TYPE__CT_UNAME);
}

static int send_caps_req(ct_handler_t h, unsigned long mask, unsigned int apply_to)
{
	RpcRequest req = RPC_REQUEST__INIT;
	CapsReq cr = CAPS_REQ__INIT;

	req.caps = &cr;
	cr.apply_to = apply_to;
	cr.mask = mask;

	return pbunix_req_ct(h, &req, REQ_TYPE__CT_SET_CAPS);
}

static const struct container_ops pbunix_ct_ops = {
	.get_state		= send_get_state_req,
	.spawn_execve		= send_spawn_req,
	.enter_execve		= send_enter_req,
	.destroy		= send_destroy_req,
	.detach			= detach_proxy,
	.kill			= send_kill_req,
	.wait			= send_wait_req,
	.set_nsmask		= send_nsmask_req,
	.add_controller		= send_addcntl_req,
	.config_controller	= send_cfgcntl_req,
	.fs_set_root		= send_setroot_req,
	.fs_set_private		= send_setpriv_req,
	.fs_add_mount		= send_add_mount_req,
	.fs_del_mount		= send_del_mount_req,
	.set_option		= send_set_option_req,
	.net_add		= send_netadd_req,
	.net_del		= send_netdel_req,
	.uname			= send_uname_req,
	.set_caps		= send_caps_req,
};

static ct_handler_t send_create_open_req(libct_session_t s, char *name, int type)
{
	struct pbunix_session *us;
	struct container_proxy *cp = NULL;
	RpcRequest req = RPC_REQUEST__INIT;
	CreateReq cr = CREATE_REQ__INIT;
	RpcResponse *resp;

	us = s2us(s);

	cp = xmalloc(sizeof(*cp));
	if (!cp)
		goto err1;

	ct_handler_init(&cp->h);
	req.req = type;
	req.create = &cr;
	cr.name = name;

	resp = pbunix_req(us, &req);
	if (!resp)
		goto err2;
	if (resp_error(resp))
		goto err3;

	if (type == REQ_TYPE__CT_OPEN) {
		struct container_proxy *r;

		list_for_each_entry(r, &us->s.s_cts, h.s_lh) {
			if (r->rid != resp->create->rid)
				continue;

			/*
			 * We've found existing container_proxy.
			 * This can happen when we create a handle
			 * and open it without closing the session.
			 */

			xfree(cp);
			cp = r;
			goto found;
		}
	}

	cp->h.ops = &pbunix_ct_ops;
	cp->rid = resp->create->rid;
	cp->ses = us;
found:
	rpc_response__free_unpacked(resp, NULL);
	return &cp->h;

err3:
	rpc_response__free_unpacked(resp, NULL);
err2:
	xfree(cp);
err1:
	return NULL;
}

static ct_handler_t send_create_req(libct_session_t s, char *name)
{
	return send_create_open_req(s, name, REQ_TYPE__CT_CREATE);
}

static ct_handler_t send_openct_req(libct_session_t s, char *name)
{
	return send_create_open_req(s, name, REQ_TYPE__CT_OPEN);
}

static void close_pbunix_session(libct_session_t s)
{
	struct pbunix_session *us;

	us = s2us(s);
	close(us->sk);
	xfree(us);
}

static const struct backend_ops pbunix_session_ops = {
	.type		= BACKEND_UNIX,
	.create_ct	= send_create_req,
	.open_ct	= send_openct_req,
	.close		= close_pbunix_session,
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

	INIT_LIST_HEAD(&us->s.s_cts);
	INIT_LIST_HEAD(&us->s.async_list);
	us->s.ops = &pbunix_session_ops;
	return &us->s;

err:
	xfree(us);
	return NULL;
}
