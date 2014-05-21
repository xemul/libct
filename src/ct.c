#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <sys/wait.h>
#include <sys/mount.h>

#include "uapi/libct.h"
#include "asm/page.h"

#include "linux-kernel.h"
#include "namespaces.h"
#include "xmalloc.h"
#include "session.h"
#include "cgroups.h"
#include "security.h"
#include "list.h"
#include "util.h"
#include "net.h"
#include "ct.h"
#include "fs.h"

static enum ct_state local_get_state(ct_handler_t h)
{
	return cth2ct(h)->state;
}

static void local_ct_destroy(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	cgroups_free(ct);
	fs_free(ct);
	net_release(ct);
	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(ct);
}

static int local_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return LCTERR_BADCTSTATE;

	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return LCTERR_NONS;

	if (!(nsmask & CLONE_NEWNS))
		net_release(ct);
	if (!(nsmask & CLONE_NEWUTS)) {
		xfree(ct->hostname);
		ct->hostname = NULL;
		xfree(ct->domainname);
		ct->domainname = NULL;
	}

	ct->nsmask = nsmask;
	return 0;
}

struct ct_clone_arg {
	char stack[PAGE_SIZE] __attribute__((aligned (8)));
	char stack_ptr[0];
	int (*cb)(void *);
	void *arg;
	struct container *ct;
	int child_wait_pipe[2];
	int parent_wait_pipe[2];
};

static inline int spawn_wait(int *pipe)
{
	int ret = -1;
	read(pipe[0], &ret, sizeof(ret));
	close(pipe[0]);
	return ret;
}

static inline void spawn_wake(int *pipe, int ret)
{
	write(pipe[1], &ret, sizeof(ret));
	close(pipe[1]);
}

static int re_mount_proc(struct container *ct)
{
	if (!ct->root_path) {
		if (mount("none", "/proc", "none", MS_PRIVATE|MS_REC, NULL))
			return -1;

		umount2("/proc", MNT_DETACH);
	}

	return mount("proc", "/proc", "proc", 0, NULL);
}

static int try_mount_proc(struct container *ct)
{
	/* Not requested by user */
	if (!(ct->flags & CT_AUTO_PROC))
		return 0;

	/* Container w/o pidns can work on existing proc */
	if (!(ct->nsmask & CLONE_NEWPID))
		return 0;

	/* Container with shared FS has no place for new proc */
	if (!fs_private(ct))
		return -1;

	return re_mount_proc(ct);
}

extern int pivot_root(const char *new_root, const char *put_old);

static int set_current_root(char *path)
{
	if (chroot(path))
		return -1;
	if (chdir("/"))
		return -1;
	return 0;
}

static int set_ct_root(struct container *ct)
{
	char put_root[] = "libct-root.XXXXXX";

	if (!(ct->nsmask & CLONE_NEWNS))
		return set_current_root(ct->root_path);

	/*
	 * We're in new mount namespace. No need in
	 * just going into chroot, do pivot root, that
	 * gives us the ability to umount old tree.
	 */

	if (chdir(ct->root_path))
		return -1;

	if (mkdtemp(put_root) == NULL)
		return -1;

	if (pivot_root(".", put_root)) {
		rmdir(put_root);
		return -1;
	}

	if (umount2(put_root, MNT_DETACH))
		return -1;

	rmdir(put_root);
	return 0;
}

static int uname_set(struct container *ct)
{
	int ret = 0;

	if (ct->hostname)
		ret |= sethostname(ct->hostname, strlen(ct->hostname));

	if (ct->domainname)
		ret |= setdomainname(ct->domainname, strlen(ct->domainname));

	return ret;
}

static int ct_clone(void *arg)
{
	int ret = -1;
	struct ct_clone_arg *ca = arg;
	struct container *ct = ca->ct;

	close(ca->child_wait_pipe[1]);
	close(ca->parent_wait_pipe[0]);

	if (setsid() < 0) {
		pr_perror("Unable to create a new session");
		return -1;
	}

	if (ct->nsmask & CLONE_NEWNS) {
		/*
		 * Remount / as slave, so that it doesn't
		 * propagate its changes to our container.
		 */
		ret = LCTERR_CANTMOUNT;
		if (mount("none", "/", "none", MS_SLAVE|MS_REC, NULL))
			goto err;
	}

	if (try_mount_cg(ct))
		goto err;

	ret = cgroups_attach(ct);
	if (ret < 0)
		goto err_um;

	if (ct->root_path) {
		/*
		 * Mount external in child, since it may live
		 * in sub mount namespace. If it doesn't do
		 * it here anyway, just umount by hands in the
		 * fs_umount().
		 */
		ret = fs_mount_ext(ct);
		if (ret < 0)
			goto err;

		ret = set_ct_root(ct);
		if (ret < 0)
			goto err_um;
	}

	ret = uname_set(ct);
	if (ret < 0)
		goto err_um;

	ret = try_mount_proc(ct);
	if (ret < 0)
		goto err_um;

	ret = apply_caps(ct);
	if (ret < 0)
		goto err_um;

	ret = spawn_wait(ca->child_wait_pipe);
	if (ret)
		goto err_um;

	spawn_wake(ca->parent_wait_pipe, 0);

	return ca->cb(ca->arg);

err_um:
	if (ct->root_path)
		fs_umount_ext(ct);
err:
	spawn_wake(ca->parent_wait_pipe, ret);
	exit(ret);
}

static int local_spawn_cb(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int ret = -1, pid, aux;
	struct ct_clone_arg ca;

	if (ct->state != CT_STOPPED)
		return LCTERR_BADCTSTATE;

	ret = fs_mount(ct);
	if (ret)
		return ret;

	if ((ct->flags & CT_KILLABLE) && !(ct->nsmask & CLONE_NEWPID)) {
		if (add_service_controller(ct))
			goto err_cg;
	}

	ret = cgroups_create(ct);
	if (ret)
		goto err_cg;

	ret = -1;
	if (pipe(ca.child_wait_pipe))
		goto err_pipe;
	if (pipe(ca.parent_wait_pipe))
		goto err_pipe2;

	ca.cb = cb;
	ca.arg = arg;
	ca.ct = ct;
	pid = clone(ct_clone, &ca.stack_ptr, ct->nsmask | SIGCHLD, &ca);
	if (pid < 0)
		goto err_clone;

	close(ca.child_wait_pipe[0]);
	close(ca.parent_wait_pipe[1]);
	ct->root_pid = pid;

	if (net_start(ct))
		goto err_net;

	spawn_wake(ca.child_wait_pipe, 0);
	aux = spawn_wait(ca.parent_wait_pipe);
	if (aux != 0) {
		ret = aux;
		goto err_ch;
	}

	ct->state = CT_RUNNING;
	return 0;

err_ch:
	net_stop(ct);
err_net:
	spawn_wake(ca.child_wait_pipe, -1);
	waitpid(pid, NULL, 0);
err_clone:
	close(ca.parent_wait_pipe[0]);
	close(ca.parent_wait_pipe[1]);
err_pipe2:
	close(ca.child_wait_pipe[0]);
	close(ca.child_wait_pipe[1]);
err_pipe:
	cgroups_destroy(ct);
err_cg:
	fs_umount(ct);
	return ret;
}

struct execv_args {
	char *path;
	char **argv;
	char **env;
	int *fds;
};

static int ct_execv(void *a)
{
	struct execv_args *ea = a;
	int ret, i;

	if (ea->fds) {
		ret  = dup2(ea->fds[0], 0);
		if (ret >= 0)
			ret = dup2(ea->fds[1], 1);
		if (ret >= 0)
			ret = dup2(ea->fds[2], 2);
		if (ret < 0) {
			pr_perror("Unable to duplicate file descriptors");
			goto err;
		}
		for (i = 0; i < 3; i++)
			close(ea->fds[i]);
	}

	/* This gets control in the container's new root (if any) */
	if (ea->env)
		execve(ea->path, ea->argv, ea->env);
	else
		execv(ea->path, ea->argv);
err:
	return -1;
}

static int local_spawn_execve(ct_handler_t ct, char *path, char **argv, char **env, int *fds)
{
	struct execv_args ea;

	ea.path = path;
	ea.argv = argv;
	ea.env = env;
	ea.fds = fds;

	return local_spawn_cb(ct, ct_execv, &ea);
}

static int local_enter_cb(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int aux = -1, pid;

	if (ct->state != CT_RUNNING)
		return LCTERR_BADCTSTATE;

	if (ct->nsmask & CLONE_NEWPID) {
		if (switch_ns(ct->root_pid, &pid_ns, &aux))
			return -1;
	}

	pid = fork();
	if (pid == 0) {
		struct ns_desc *ns;

		for (aux = 0; namespaces[aux]; aux++) {
			ns = namespaces[aux];

			if (ns->cflag == CLONE_NEWPID)
				continue;
			if (!(ns->cflag & ct->nsmask))
				continue;

			if (switch_ns(ct->root_pid, ns, NULL))
				exit(-1);
		}

		if (cgroups_attach(ct))
			exit(-1);

		if (ct->root_path && !(ct->nsmask & CLONE_NEWNS)) {
			char nroot[128];

			/*
			 * Otherwise switched by setns()
			 */

			snprintf(nroot, sizeof(nroot), "/proc/%d/root", ct->root_pid);
			if (set_current_root(nroot))
				exit(-1);
		}

		if (apply_caps(ct))
			exit(-1);

		aux = cb(arg);
		exit(aux);
	}

	if (aux >= 0)
		restore_ns(aux, &pid_ns);

	return pid;
}

static int local_enter_execve(ct_handler_t h, char *path, char **argv, char **env)
{
	struct execv_args ea = {};

	ea.path	= path;
	ea.argv	= argv;
	ea.env	= env;

	return local_enter_cb(h, ct_execv, &ea);
}

static int local_ct_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_RUNNING)
		return LCTERR_BADCTSTATE;
	if (ct->nsmask & CLONE_NEWPID)
		return kill(ct->root_pid, SIGKILL);
	if (ct->flags & CT_KILLABLE)
		return service_ctl_killall(ct);
	return -1;
}

static int local_ct_wait(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	int ret, status;

	if (ct->state != CT_RUNNING)
		return LCTERR_BADCTSTATE;

	ret = waitpid(ct->root_pid, &status, 0);
	if (ret < 0)
		return -1;

	fs_umount(ct);
	cgroups_destroy(ct); /* FIXME -- can be held accross restarts */
	net_stop(ct);

	ct->state = CT_STOPPED;
	return 0;
}

static int local_set_option(ct_handler_t h, int opt, va_list parms)
{
	int ret = LCTERR_BADTYPE;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		ret = 0;
		ct->cgroup_sub = xstrdup(xvaopt(parms, char *,
					DEFAULT_CGROUPS_PATH));
		if (!ct->cgroup_sub)
			ret = -1;
		break;
	case LIBCT_OPT_KILLABLE:
		ret = cgroups_create_service();
		if (!ret)
			ct->flags |= CT_KILLABLE;
	}

	return ret;
}

static int local_uname(ct_handler_t h, char *host, char *dom)
{
	struct container *ct = cth2ct(h);

	if (!(ct->nsmask & CLONE_NEWUTS))
		return LCTERR_NONS;
	if (ct->state != CT_STOPPED)
		return LCTERR_BADCTSTATE; /* FIXME */

	if (host) {
		host = xstrdup(host);
		if (!host)
			return -1;
	}
	xfree(ct->hostname);
	ct->hostname = host;

	if (dom) {
		dom = xstrdup(dom);
		if (!dom)
			return -1;
	}
	xfree(ct->domainname);
	ct->domainname = dom;

	return 0;
}

static int local_set_caps(ct_handler_t h, unsigned long mask, unsigned int apply_to)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return LCTERR_BADCTSTATE;

	if (apply_to & CAPS_BSET) {
		ct->cap_mask |= CAPS_BSET;
		ct->cap_bset = mask;
	}

	if (apply_to & CAPS_ALLCAPS) {
		ct->cap_mask |= CAPS_ALLCAPS;
		ct->cap_caps = mask;
	}

	return 0;
}

char *local_ct_name(ct_handler_t h)
{
	return cth2ct(h)->name;
}

static const struct container_ops local_ct_ops = {
	.spawn_cb		= local_spawn_cb,
	.spawn_execve		= local_spawn_execve,
	.enter_cb		= local_enter_cb,
	.enter_execve		= local_enter_execve,
	.kill			= local_ct_kill,
	.wait			= local_ct_wait,
	.destroy		= local_ct_destroy,
	.detach			= local_ct_destroy,
	.set_nsmask		= local_set_nsmask,
	.add_controller		= local_add_controller,
	.config_controller	= local_config_controller,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_del_mount		= local_del_mount,
	.get_state		= local_get_state,
	.set_option		= local_set_option,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.uname			= local_uname,
	.set_caps		= local_set_caps,
};

ct_handler_t ct_create(char *name)
{
	struct container *ct;

	ct = xzalloc(sizeof(*ct));
	if (ct) {
		ct_handler_init(&ct->h);
		ct->h.ops = &local_ct_ops;
		ct->state = CT_STOPPED;
		ct->name = xstrdup(name);
		INIT_LIST_HEAD(&ct->cgroups);
		INIT_LIST_HEAD(&ct->cg_configs);
		INIT_LIST_HEAD(&ct->ct_nets);
		INIT_LIST_HEAD(&ct->fs_mnts);

		return &ct->h;
	}

	return NULL;
}

