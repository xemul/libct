/*
 * Daemon that gets requests from remote library backend
 * and forwards them to local session.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

#include "uapi/libct.h"

#include "session.h"
#include "xmalloc.h"
#include "list.h"
#include "net.h"
#include "fs.h"
#include "ct.h"
#include "rpc.h"
#include "async.h"

#include "protobuf/rpc.pb-c.h"

typedef struct {
	struct list_head	list;
	unsigned long		rid;
	ct_handler_t		ct;
} ct_server_t;

static LIST_HEAD(ct_servers);
static unsigned long rids = 1;

static ct_server_t *find_ct_by_rid(unsigned long rid)
{
	ct_server_t *cs;

	list_for_each_entry(cs, &ct_servers, list) {
		if (cs->rid == rid)
			return cs;
	}

	return NULL;
}

static ct_server_t *find_ct_by_name(char *name)
{
	ct_server_t *cs;

	list_for_each_entry(cs, &ct_servers, list) {
		if (!strcmp(name, local_ct_name(cs->ct)))
			return cs;
	}

	return NULL;
}

static ct_server_t *__ct_server_create(ct_handler_t ct)
{
	ct_server_t *cs;

	cs = xmalloc(sizeof(*cs));
	if (!cs)
		return NULL;

	cs->ct = ct;
	cs->rid = rids++;
	list_add_tail(&cs->list, &ct_servers);
	return cs;
}

static void __ct_server_destroy(ct_server_t *cs)
{
	if (cs) {
		if (cs->ct)
			libct_container_destroy(cs->ct);
		list_del(&cs->list);
		xfree(cs);
	}
}

static int serve_ct_create(int sk, libct_session_t ses, RpcRequest *req)
{
	RpcResponse resp = RPC_RESPONSE__INIT;
	CreateResp cr = CREATE_RESP__INIT;
	ct_server_t *cs;

	if (req->create == NULL)
		return send_resp(sk, req, LCTERR_BADARG);

	cs = __ct_server_create(NULL);
	if (!cs)
		goto err;

	cs->ct = libct_container_create(ses, req->create->name);
	if (!cs->ct)
		goto err;

	resp.create = &cr;
	cr.rid = cs->rid;
	if (do_send_resp(sk, req, 0, &resp))
		goto err;
	return 0;
err:
	__ct_server_destroy(cs);
	return send_resp(sk, req, -1);
}

static int serve_ct_open(int sk, libct_session_t ses, RpcRequest *req)
{
	RpcResponse resp = RPC_RESPONSE__INIT;
	CreateResp cr = CREATE_RESP__INIT;
	ct_server_t *cs;

	if (req->create == NULL)
		return send_resp(sk, req, LCTERR_BADARG);

	cs = find_ct_by_name(req->create->name);
	if (!cs)
		return send_resp(sk, req, LCTERR_BADCTRNAME);

	resp.create = &cr;
	cr.rid = cs->rid;
	return do_send_resp(sk, req, 0, &resp);
}

static int serve_ct_destroy(int sk, ct_server_t *cs, RpcRequest *req)
{
	__ct_server_destroy(cs);
	return send_resp(sk, req, 0);
}

static int serve_get_state(int sk, ct_server_t *cs, RpcRequest *req)
{
	RpcResponse resp = RPC_RESPONSE__INIT;
	StateResp gs = STATE_RESP__INIT;

	resp.state = &gs;
	gs.state = libct_container_state(cs->ct);

	return do_send_resp(sk, req, 0, &resp);
}

static int extract_arguments(ExecvReq *er, char ***pargv, char ***penv)
{
	char **argv, **env = NULL;
	int i;

	argv = xmalloc((er->n_args + 1) * sizeof(char *));
	if (!argv)
		return -1;

	for (i = 0; i < er->n_args; i++)
		argv[i] = er->args[i];
	argv[i] = NULL;

	if (er->n_env) {
		env = xmalloc((er->n_env + 1) * sizeof(char *));
		if (!env) {
			xfree(argv);
			return -1;
		}

		for (i = 0; i < er->n_env; i++)
			env[i] = er->env[i];
		env[i] = NULL;
	}

	*pargv = argv;
	*penv = env;

	return 0;
}

static int serve_spawn(int sk, ct_server_t *cs, RpcRequest *req, int *fds, int nr_fds)
{
	ExecvReq *er = req->execv;
	char **argv, **env = NULL;
	int ret = -1;

	if (!req->execv)
		goto out;

	if (req->execv->pipes && nr_fds != 3) {
		ret = LCTERR_BADARG;
		goto out;
	}

	if (extract_arguments(er, &argv, &env))
		goto out;

	ret = libct_container_spawn_execvefds(cs->ct, er->path, argv, env,
						req->execv->pipes ? fds : NULL);
	xfree(argv);
	xfree(env);
out:
	return send_resp(sk, req, ret);
}

static int serve_enter(int sk, ct_server_t *cs, RpcRequest *req)
{
	ExecvReq *er = req->execv;
	int ret = -1;

	if (!er)
		return send_resp(sk, req, ret);

	if (er->n_env)
		ret = libct_container_enter_execve(cs->ct, er->path,
						   er->args, er->env);
	else
		ret = libct_container_enter_execv(cs->ct, er->path,
						  er->args);
	return send_resp(sk, req, ret);
}

static int serve_kill(int sk, ct_server_t *cs, RpcRequest *req)
{
	return send_resp(sk, req, libct_container_kill(cs->ct));
}

struct srv_async_args {
	int		sk;
	RpcRequest	*req;
	ct_handler_t	h;
};

static void rpc_wait_callback_destroy(libct_session_t s, void *req_args)
{
	struct srv_async_args *srv_args = req_args;

	rpc_request__free_unpacked(srv_args->req, NULL);
	xfree(srv_args);
}

static int rpc_wait_callback(libct_session_t s, void *req_args, int type, void *args)
{
	struct srv_async_args *srv_args = req_args;
	ct_handler_t h = args;

	if (type != CT_STATE)
		return 0;
	if (h != srv_args->h)
		return 0;

	send_resp(srv_args->sk, srv_args->req, 0);

	rpc_wait_callback_destroy(s, req_args);

	return 1;
}

static int serve_wait(int sk, libct_session_t ses, ct_server_t *cs, RpcRequest *req)
{
	struct srv_async_args *srv_args = NULL;

	srv_args = xmalloc(sizeof(struct srv_async_args));
	if (srv_args == NULL)
		goto err;

	srv_args->sk = sk;
	srv_args->h = cs->ct;
	srv_args->req = req;

	if (async_req_add(ses, rpc_wait_callback,
				rpc_wait_callback_destroy, srv_args) < 0)
		goto err;

	return 1;
err:
	xfree(srv_args);
	send_resp(sk,  srv_args->req, -1);
	return -1;
}

static int serve_setnsmask(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->nsmask)
		ret = libct_container_set_nsmask(cs->ct, req->nsmask->mask);
	return send_resp(sk, req, ret);
}

static int serve_addcntl(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->addcntl)
		ret = libct_controller_add(cs->ct, req->addcntl->ctype);
	return send_resp(sk, req, ret);
}

static int serve_cfgcntl(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->cfgcntl)
		ret = libct_controller_configure(cs->ct, req->cfgcntl->ctype,
						 req->cfgcntl->param,
						 req->cfgcntl->value);
	return send_resp(sk, req, ret);
}

static int serve_setroot(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->setroot)
		ret = libct_fs_set_root(cs->ct, req->setroot->root);
	return send_resp(sk, req, ret);
}

static int serve_setpriv(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->setpriv) {
		const struct ct_fs_ops *ops;

		ret = LCTERR_BADTYPE;
		ops = fstype_get_ops(req->setpriv->type);
		if (ops) {
			void *arg;

			ret = LCTERR_BADARG;
			arg = ops->pb_unpack(req->setpriv);
			if (arg)
				ret = libct_fs_set_private(cs->ct, req->setpriv->type, arg);
			xfree(arg);
		}
	}

	return send_resp(sk, req, ret);
}

static int serve_addmount(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->mnt)
		ret = libct_fs_add_mount(cs->ct, req->mnt->src,
					 req->mnt->dst, req->mnt->flags);

	return send_resp(sk, req, ret);
}

static int serve_delmount(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->mnt)
		ret = libct_fs_del_mount(cs->ct, req->mnt->dst);

	return send_resp(sk, req, ret);
}

static int serve_set_option(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1, opt = -1;

	if (req->setopt)
		opt = req->setopt->opt;

	switch (opt) {
	default:
		return LCTERR_BADTYPE;

	case LIBCT_OPT_AUTO_PROC_MOUNT:
	case LIBCT_OPT_KILLABLE:
		ret = libct_container_set_option(cs->ct, opt);
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		ret = libct_container_set_option(cs->ct, opt,
						 req->setopt->cg_path);
		break;
	}

	return send_resp(sk, req, ret);
}

static int serve_net_req(int sk, ct_server_t *cs, RpcRequest *req, bool add)
{
	int ret = -1;

	if (req->netadd) {
		const struct ct_net_ops *nops;
		void *arg = NULL;

		ret = LCTERR_BADTYPE;
		if (req->netadd->type != CT_NET_NONE) {
			ret = LCTERR_BADARG;
			nops = net_get_ops(req->netadd->type);
			if (nops) {
				arg = nops->pb_unpack(req->netadd);
				if (arg)
					ret = 0;
			}
		}

		if (!ret) {
			if (add)
				ret = libct_net_add(cs->ct, req->netadd->type, arg);
			else
				ret = libct_net_del(cs->ct, req->netadd->type, arg);
		}

		xfree(arg);
	}

	return send_resp(sk, req, ret);
}

static int serve_net_add(int sk, ct_server_t *cs, RpcRequest *req)
{
	return serve_net_req(sk, cs, req, true);
}

static int serve_net_del(int sk, ct_server_t *cs, RpcRequest *req)
{
	return serve_net_req(sk, cs, req, false);
}

static int serve_uname(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->uname)
		ret = libct_container_uname(cs->ct, req->uname->host, req->uname->domain);

	return send_resp(sk, req, ret);
}

static int serve_caps(int sk, ct_server_t *cs, RpcRequest *req)
{
	int ret = -1;

	if (req->caps)
		ret = libct_container_set_caps(cs->ct,
					       (unsigned long)req->caps->mask,
					       (unsigned int)req->caps->apply_to);
	return send_resp(sk, req, ret);
}

static int serve_req(int sk, libct_session_t ses, RpcRequest *req, int *fds, int nr_fds)
{
	ct_server_t *cs = NULL;

	if (req->req == REQ_TYPE__CT_CREATE)
		return serve_ct_create(sk, ses, req);
	else if (req->req == REQ_TYPE__CT_OPEN)
		return serve_ct_open(sk, ses, req);

	if (req->has_ct_rid)
		cs = find_ct_by_rid(req->ct_rid);
	if (!cs)
		return send_resp(sk, req, LCTERR_BADCTRID);

	switch (req->req) {
	case REQ_TYPE__CT_DESTROY:
		return serve_ct_destroy(sk, cs, req);
	case REQ_TYPE__CT_GET_STATE:
		return serve_get_state(sk, cs, req);
	case REQ_TYPE__CT_SPAWN:
		return serve_spawn(sk, cs, req, fds, nr_fds);
	case REQ_TYPE__CT_ENTER:
		return serve_enter(sk, cs, req);
	case REQ_TYPE__CT_KILL:
		return serve_kill(sk, cs, req);
	case REQ_TYPE__CT_WAIT:
		return serve_wait(sk, ses, cs, req);
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
	case REQ_TYPE__FS_DEL_MOUNT:
		return serve_delmount(sk, cs, req);
	case REQ_TYPE__CT_SET_OPTION:
		return serve_set_option(sk, cs, req);
	case REQ_TYPE__CT_NET_ADD:
		return serve_net_add(sk, cs, req);
	case REQ_TYPE__CT_NET_DEL:
		return serve_net_del(sk, cs, req);
	case REQ_TYPE__CT_UNAME:
		return serve_uname(sk, cs, req);
	case REQ_TYPE__CT_SET_CAPS:
		return serve_caps(sk, cs, req);
	default:
		break;
	}

	return -1;
}

static int serve(int sk, libct_session_t ses)
{
	RpcRequest *req;
	int *fds, nr_fds;
	int ret, i;

	ret = recv_req(sk, &req, &fds, &nr_fds);
	if (ret <= 0)
		return -1;

	ret = serve_req(sk, ses, req, fds, nr_fds);

	for (i = 0; i < nr_fds; i++)
		close(fds[i]);

	if (ret != 1)
		rpc_request__free_unpacked(req, NULL);

	return ret;
}

int libct_session_export(libct_session_t s)
{
	struct local_session *l = s2ls(s);
	struct epoll_event ev;
	int efd, ret = -1, sig_fd;
	sigset_t mask;

	if (s->ops->type != BACKEND_LOCAL || l->server_sk < 0)
		return -1;

	efd = epoll_create1(0);
	if (efd < 0)
		return -1;

	ev.events = EPOLLIN;
	ev.data.fd = l->server_sk;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, l->server_sk, &ev) < 0)
		goto err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (sig_fd < 0) {
		pr_perror("signalfd");
		goto err;
	}

	ev.events = EPOLLIN;
	ev.data.fd = sig_fd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sig_fd, &ev) < 0)
		goto err;

	while (1) {
		int n;

		n = epoll_wait(efd, &ev, 1, -1);
		if (n <= 0)
			 break;

		if (ev.data.fd == l->server_sk) {
			/*
			 * New connection
			 */

			struct sockaddr_un addr;
			socklen_t alen = sizeof(addr);
			int ask;

			ask = accept(l->server_sk, (struct sockaddr *)&addr, &alen);
			if (ask < 0)
				continue;

			if (fcntl(ask, F_SETFD, fcntl(ask, F_GETFD) | FD_CLOEXEC) == -1) {
				pr_perror("Unable to set FD_CLOEXEC");
				return -1;
			}

			ev.events = EPOLLIN;
			ev.data.fd = ask;
			if (epoll_ctl(efd, EPOLL_CTL_ADD, ask, &ev) < 0)
				close(ask);

			continue;
		} else if (ev.data.fd == sig_fd) {
			struct signalfd_siginfo info;

			if (read(sig_fd, &info, sizeof(info)) != sizeof(info)) {
				pr_perror("read from signalfd");
				goto err;
			}
			pr_debug("signalfd: pid %d\n", info.ssi_pid);

			while (1) {
				siginfo_t info = { .si_pid = 0 };

				ret = waitid(P_ALL, -1, &info, WNOHANG | WNOWAIT | WEXITED);
				if (ret < 0 && errno == ECHILD)
					break;
				if (ret < 0) {
					pr_perror("waitid failed");
					goto err;
				}

				/* there are no children in a waitable state */
				if (info.si_pid == 0)
					break;

				pr_debug("The %d process exited\n", info.si_pid);

				l->s.ops->update_ct_state(&l->s, info.si_pid);
			}

			continue;
		}

		/*
		 * Request on existing socket
		 *
		 * Note, that requests are served one-by-one, thus
		 * allowing for several connections to work on the
		 * same container without problems. Simultaneous
		 * requests serving is not yet possible, due to library
		 * being non-thread-safe in local session (FIXME?)
		 */

		if (serve(ev.data.fd, s) < 0) {
			epoll_ctl(efd, EPOLL_CTL_DEL, ev.data.fd, NULL);
			close(ev.data.fd);
		}
	}
	ret = 0;

err:
	close(efd);
	return ret;
}

int libct_session_export_prepare(libct_session_t s, char *sk_path)
{
	struct local_session *l = s2ls(s);
	struct sockaddr_un addr;
	ct_handler_t ct;
	socklen_t alen;
	int sk;

	if (s->ops->type != BACKEND_LOCAL || !sk_path)
		return -1;

	sk = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sk_path, sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	unlink(addr.sun_path);
	if (bind(sk, (struct sockaddr *)&addr, alen))
		goto err;

	if (listen(sk, 16))
		goto err;

	/*
	 * Before going to loop, create container server
	 * for each container thus session would be able
	 * to handle request per-container.
	 */
	list_for_each_entry(ct, &s->s_cts, s_lh) {
		ct_server_t *cs;

		cs = __ct_server_create(ct);
		if (!cs)
			goto rollback;
	}

	l->server_sk = sk;
	return 0;

rollback:
	list_for_each_entry(ct, &s->s_cts, s_lh) {
		ct_server_t *cs;

		cs = find_ct_by_name(local_ct_name(ct));
		if (cs) {
			cs->ct = NULL;
			__ct_server_destroy(cs);
		}
	}
err:
	close(sk);
	return -1;
}
