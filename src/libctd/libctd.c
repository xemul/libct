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
#include <getopt.h>
#include "uapi/libct.h"
#include "list.h"
#include "xmalloc.h"
#include "ct.h"
#include "fs.h"
#include "net.h"
#include "../protobuf/rpc.pb-c.h"

#define MAX_MSG		4096
#define BADCTRID_ERR	-42

/* Buffer for keeping serialized messages */
static unsigned char dbuf[MAX_MSG];

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
	int len;

	resp.success = false;
	len = rpc_responce__pack(&resp, dbuf);
	if (len > 0)
		send(sk, dbuf, len, 0);

	return 0;
}

static int send_resp(int sk, int err, RpcResponce *resp)
{
	int len;

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

static int serve_ct_create(int sk, libct_session_t ses, CreateReq *req)
{
	struct container_srv *cs;
	RpcResponce resp = RPC_RESPONCE__INIT;
	CreateResp cr = CREATE_RESP__INIT;

	cs = xmalloc(sizeof(*cs));
	if (!cs)
		goto err0;

	cs->hnd = libct_container_create(ses, req->name);
	if (!cs->hnd)
		goto err1;

	cs->rid = rids++;
	resp.create = &cr;
	cr.rid = cs->rid;
	if (send_resp(sk, 0, &resp))
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

	return send_resp(sk, 0, &resp);
}

static int serve_get_state(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	StateResp gs = STATE_RESP__INIT;

	resp.state = &gs;
	gs.state = libct_container_state(cs->hnd);

	return send_resp(sk, 0, &resp);
}

static int serve_spawn(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->execv) {
		ExecvReq *er = req->execv;
		char **argv;
		int i;

		argv = xmalloc((er->n_args + 1) * sizeof(char *));
		if (!argv)
			goto out;

		for (i = 0; i < er->n_args; i++)
			argv[i] = er->args[i];
		argv[i] = NULL;

		ret = libct_container_spawn_execv(cs->hnd, er->path, argv);
		xfree(argv);
	}
out:
	return send_resp(sk, ret, &resp);
}

static int serve_enter(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->execv)
		ret = libct_container_enter_execv(cs->hnd, req->execv->path, req->execv->args);

	return send_resp(sk, ret, &resp);
}

static int serve_kill(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret;

	ret = libct_container_kill(cs->hnd);
	return send_resp(sk, ret, &resp);
}

static int serve_wait(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret;

	ret = libct_container_wait(cs->hnd);
	return send_resp(sk, ret, &resp);
}

static int serve_setnsmask(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->nsmask)
		ret = libct_container_set_nsmask(cs->hnd, req->nsmask->mask);
	return send_resp(sk, ret, &resp);
}

static int serve_addcntl(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->addcntl)
		ret = libct_controller_add(cs->hnd, req->addcntl->ctype);
	return send_resp(sk, ret, &resp);
}

static int serve_cfgcntl(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->cfgcntl)
		ret = libct_controller_configure(cs->hnd, req->cfgcntl->ctype,
				req->cfgcntl->param, req->cfgcntl->value);
	return send_resp(sk, ret, &resp);
}

static int serve_setroot(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->setroot)
		ret = libct_fs_set_root(cs->hnd, req->setroot->root);
	return send_resp(sk, ret, &resp);
}

static int serve_setpriv(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->setpriv) {
		const struct ct_fs_ops *ops;

		ops = fstype_get_ops(req->setpriv->type);
		if (ops) {
			void *arg;

			arg = ops->pb_unpack(req->setpriv);
			ret = libct_fs_set_private(cs->hnd, req->setpriv->type, arg);
			xfree(arg);
		}
	}

	return send_resp(sk, ret, &resp);
}

static int serve_addmount(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->addmnt)
		ret = libct_fs_add_mount(cs->hnd, req->addmnt->src, req->addmnt->dst);

	return send_resp(sk, ret, &resp);
}

static int serve_set_option(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1, opt = -1;

	if (req->setopt)
		opt = req->setopt->opt;

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = libct_container_set_option(cs->hnd, opt);
		break;
	}

	return send_resp(sk, ret, &resp);
}

static int serve_net_add(int sk, struct container_srv *cs, RpcRequest *req)
{
	RpcResponce resp = RPC_RESPONCE__INIT;
	int ret = -1;

	if (req->netadd) {
		const struct ct_net_ops *nops;
		void *arg = NULL;

		if (req->netadd->type != CT_NET_NONE) {
			nops = net_get_ops(req->netadd->type);
			if (nops) {
				ret = 0;
				arg = nops->pb_unpack(req->netadd);
			}
		}

		if (!ret)
			ret = libct_net_add(cs->hnd, req->netadd->type, arg);

		xfree(arg);
	}

	return send_resp(sk, ret, &resp);
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
	case REQ_TYPE__CT_ENTER:
		return serve_enter(sk, cs, req);
	case REQ_TYPE__CT_KILL:
		return serve_kill(sk, cs, req);
	case REQ_TYPE__CT_WAIT:
		return serve_wait(sk, cs, req);
	case REQ_TYPE__CT_SETNSMASK:
		return serve_setnsmask(sk, cs, req);
	case REQ_TYPE__CT_ADD_CNTL:
		return serve_addcntl(sk, cs, req);
	case REQ_TYPE__CT_CFG_CNTL:
		return serve_cfgcntl(sk, cs, req);
	case REQ_TYPE__FS_SETROOT:
		return serve_setroot(sk, cs, req);
	case REQ_TYPE__FS_SETPRIVATE:
		return serve_setpriv(sk, cs, req);
	case REQ_TYPE__FS_ADD_MOUNT:
		return serve_addmount(sk, cs, req);
	case REQ_TYPE__CT_SET_OPTION:
		return serve_set_option(sk, cs, req);
	case REQ_TYPE__CT_NET_ADD:
		return serve_net_add(sk, cs, req);
	default:
		break;
	}

	return -1;
}

static int serve(int sk)
{
	RpcRequest *req;
	int ret;
	libct_session_t ses;

	ses = libct_session_open_local();
	if (!ses)
		return -1;

	while (1) {
		ret = recv(sk, dbuf, MAX_MSG, 0);
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

/*
 * CLI options
 */

static char *opt_sk_path = NULL;
static bool opt_daemon = false;
static char *opt_pid_file = NULL;

static int parse_options(int argc, char **argv)
{
	static const char so[] = "ds:P:h";
	static struct option lo[] = {
		{ "daemon", no_argument, 0, 'd' },
		{ "socket", required_argument, 0, 's' },
		{ "pidfile", required_argument, 0, 'P' },
		{ "help", no_argument, 0, 'h' },
		{ }
	};
	int opt, idx;

	do {
		opt = getopt_long(argc, argv, so, lo, &idx);
		switch (opt) {
		case -1:
			break;
		case 'h':
			goto usage;
		case 'd':
			opt_daemon = true;
			break;
		case 's':
			opt_sk_path = optarg;
			break;
		case 'P':
			opt_pid_file = optarg;
			break;
		default:
			goto bad_usage;
		}
	} while (opt != -1);

	if (!opt_sk_path) {
		printf("Specify socket to work with\n");
		goto bad_usage;
	}

	return 0;

usage:
	printf("Usage: libctd [-d|--daemon] [-s|--socket <path>]\n");
	printf("\t-d|--daemon           daemonize after start\n");
	printf("\t-s|--socket <path>    path to socket to listen on\n");
	printf("\t-P|--pidfile <path>	write daemon pid to this file\n");
	printf("\n");
	printf("\t-h|--help             print this text\n");
bad_usage:
	return -1;
}

int main(int argc, char **argv)
{
	int sk;
	struct sockaddr_un addr;
	socklen_t alen;

	if (parse_options(argc, argv))
		goto err;

	sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (sk == -1)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, opt_sk_path, sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	unlink(addr.sun_path);
	if (bind(sk, (struct sockaddr *)&addr, alen))
		goto err;

	if (listen(sk, 16))
		goto err;

	if (opt_daemon)
		daemon(1, 0);

	if (opt_pid_file) {
		FILE *pf;

		pf = fopen(opt_pid_file, "w");
		if (!pf)
			goto err;

		fprintf(pf, "%d", getpid());
		fclose(pf);
	}

	signal(SIGCHLD, SIG_IGN); /* auto-kill zombies */

	while (1) {
		int ask;

		alen = sizeof(addr);
		ask = accept(sk, (struct sockaddr *)&addr, &alen);
		if (ask < 0)
			continue;

		if (fork() == 0) {
			int ret;

			close(sk);

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
