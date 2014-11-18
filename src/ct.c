#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <grp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
#include "vz.h"

static enum ct_state local_get_state(ct_handler_t h)
{
	return cth2ct(h)->state;
}

static void local_ct_uid_gid_free(struct container *ct)
{
	struct _uid_gid_map *map, *t;

	list_for_each_entry_safe(map, t, &ct->uid_map, node)
		xfree(map);
	list_for_each_entry_safe(map, t, &ct->gid_map, node)
		xfree(map);
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
	local_ct_uid_gid_free(ct);
	xfree(ct);
}

static int local_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return -LCTERR_NONS;

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
	struct process_desc *p;
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
	if (!(ct->nsmask & CLONE_NEWPID) && !ct->root_path)
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

	if (mount(ct->root_path, ct->root_path, NULL, MS_BIND | MS_REC, NULL) == -1)
		return -1;

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
	struct process_desc *p = ca->p;

	close(ca->child_wait_pipe[1]);
	close(ca->parent_wait_pipe[0]);

	ret = spawn_wait(ca->child_wait_pipe);
	if (ret)
		goto err_um;

	if (ct->nsmask & CLONE_NEWUSER) {
		if (setuid(0) || setgid(0) || setgroups(0, NULL))
			goto err;
	}

	if (prctl(PR_SET_PDEATHSIG, p->pdeathsig))
		goto err;

	if (!(ct->flags & CT_NOSETSID) && setsid() == -1)
		goto err;

	if (ct->tty_fd >= 0 && ioctl(ct->tty_fd, TIOCSCTTY, 0) == -1)
		goto err;

	if (ct->nsmask & CLONE_NEWNS) {
		/*
		 * Remount / as slave, so that it doesn't
		 * propagate its changes to our container.
		 */
		ret = -LCTERR_CANTMOUNT;
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

		ret = fs_create_devnodes(ct);
		if (ret < 0)
			goto err;
	}

	ret = uname_set(ct);
	if (ret < 0)
		goto err_um;

	ret = try_mount_proc(ct);
	if (ret < 0)
		goto err_um;

	ret = apply_creds(p);
	if (ret < 0)
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

static int write_id_mappings(pid_t pid, struct list_head *list, char *id_map)
{
	int size = 0, off = 0, exit_code, fd = -1;
	struct _uid_gid_map *map;
	char *buf = NULL, *_buf;
	char fname[PATH_MAX];

	list_for_each_entry(map, list, node) {
		if (size - off < 34) {
			size += PAGE_SIZE;
			_buf = xrealloc(buf, size);
			if (_buf == NULL)
				goto err;
			buf = _buf;
		}
		off += snprintf(buf + off, size - off, "%u %u %u\n",
				map->first, map->lower_first, map->count);

	}

	snprintf(fname, sizeof(fname), "/proc/%d/%s", pid, id_map);
	fd = open(fname, O_WRONLY);
	if (fd < 0)
		goto err;
	if (write(fd, buf, off) != off)
		goto err;

	exit_code = 0;
err:
	xfree(buf);
	if (fd > 0)
		close(fd);
	return exit_code;
}

static int local_spawn_cb(ct_handler_t h, ct_process_desc_t ph, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	struct process_desc *p = prh2pr(ph);
	int ret = -1, pid, aux;
	struct ct_clone_arg ca;

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

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
	ca.p = p;
	pid = clone(ct_clone, &ca.stack_ptr, ct->nsmask | SIGCHLD, &ca);
	if (pid < 0)
		goto err_clone;

	close(ca.child_wait_pipe[0]);
	close(ca.parent_wait_pipe[1]);
	ct->root_pid = pid;

	if (ct->nsmask & CLONE_NEWUSER) {
		if (write_id_mappings(pid, &ct->uid_map, "uid_map"))
			goto err_net;

		if (write_id_mappings(pid, &ct->gid_map, "gid_map"))
			goto err_net;
	}

	if (net_start(ct))
		goto err_net;

	spawn_wake(ca.child_wait_pipe, 0);
	aux = spawn_wait(ca.parent_wait_pipe);
	if (aux != 0) {
		ret = aux;
		goto err_ch;
	}

	ct->state = CT_RUNNING;
	return pid;

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

static int ct_execv(void *a)
{
	struct execv_args *ea = a;
	int ret, i;
	sigset_t mask;

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

	sigfillset(&mask);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	/* This gets control in the container's new root (if any) */
	if (ea->env)
		execvpe(ea->path, ea->argv, ea->env);
	else
		execvp(ea->path, ea->argv);
err:
	return -1;
}

static int local_spawn_execve(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, char **env, int *fds)
{
	struct execv_args ea;

	ea.path = path;
	ea.argv = argv;
	ea.env = env;
	ea.fds = fds;

	return local_spawn_cb(ct, pr, ct_execv, &ea);
}

static int local_enter_cb(ct_handler_t h, ct_process_desc_t ph, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	struct process_desc *p = prh2pr(ph);
	int aux = -1, pid;

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;

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

		if (apply_creds(p))
			exit(-1);

		aux = cb(arg);
		exit(aux);
	}

	if (aux >= 0)
		restore_ns(aux, &pid_ns);

	return pid;
}

static int local_enter_execve(ct_handler_t h, ct_process_desc_t p, char *path, char **argv, char **env, int *fds)
{
	struct execv_args ea = {};

	ea.path	= path;
	ea.argv	= argv;
	ea.env	= env;
	ea.fds = fds;

	return local_enter_cb(h, p, ct_execv, &ea);
}

static int local_ct_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;
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
		return -LCTERR_BADCTSTATE;

	ret = waitpid(ct->root_pid, &status, 0);
	if (ret < 0)
		return -1;

	fs_umount(ct);
	cgroups_destroy(ct); /* FIXME -- can be held accross restarts */
	net_stop(ct);

	ct->state = CT_STOPPED;
	return 0;
}

static int local_set_option(ct_handler_t h, int opt, void *args)
{
	int ret = -LCTERR_BADTYPE;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		ret = 0;
		if (args)
			ct->cgroup_sub = xstrdup((char *) args);
		else
			ct->cgroup_sub = xstrdup(DEFAULT_CGROUPS_PATH);
		if (!ct->cgroup_sub)
			ret = -1;
		break;
	case LIBCT_OPT_KILLABLE:
		ret = cgroups_create_service();
		if (!ret)
			ct->flags |= CT_KILLABLE;
		break;
	case LIBCT_OPT_NOSETSID:
		ret = 0;
		ct->flags |= CT_NOSETSID;
		break;
	}

	return ret;
}

static int local_uname(ct_handler_t h, char *host, char *dom)
{
	struct container *ct = cth2ct(h);

	if (!(ct->nsmask & CLONE_NEWUTS))
		return -LCTERR_NONS;
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE; /* FIXME */

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

char *local_ct_name(ct_handler_t h)
{
	return cth2ct(h)->name;
}

static int local_set_console_fd(ct_handler_t h, int fd)
{
	struct container *ct = cth2ct(h);
	ct->tty_fd = fd;
	return 0;
}

static int local_add_map(struct list_head *list, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	struct _uid_gid_map *_map;

	_map = xmalloc(sizeof(struct _uid_gid_map));
	if (_map == NULL)
		return -1;

	_map->first		= first;
	_map->lower_first	= lower_first;
	_map->count		= count;

	list_add(&_map->node, list);

	return 0;
}

int local_add_uid_map(ct_handler_t h, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	struct container *ct = cth2ct(h);

	return local_add_map(&ct->uid_map, first, lower_first, count);
}

int local_add_gid_map(ct_handler_t h, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	struct container *ct = cth2ct(h);

	return local_add_map(&ct->gid_map, first, lower_first, count);
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
	.fs_add_bind_mount	= local_add_bind_mount,
	.fs_del_bind_mount	= local_del_bind_mount,
	.fs_add_devnode		= local_add_devnode,
	.get_state		= local_get_state,
	.set_option		= local_set_option,
	.set_console_fd		= local_set_console_fd,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.net_route_add		= local_net_route_add,
	.uname			= local_uname,
	.add_uid_map		= local_add_uid_map,
	.add_gid_map		= local_add_gid_map,
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
		ct->tty_fd = -1;
		INIT_LIST_HEAD(&ct->cgroups);
		INIT_LIST_HEAD(&ct->cg_configs);
		INIT_LIST_HEAD(&ct->ct_nets);
		INIT_LIST_HEAD(&ct->ct_net_routes);
		INIT_LIST_HEAD(&ct->fs_mnts);
		INIT_LIST_HEAD(&ct->fs_devnodes);
		INIT_LIST_HEAD(&ct->uid_map);
		INIT_LIST_HEAD(&ct->gid_map);

		return &ct->h;
	}

	return NULL;
}

ct_handler_t vz_ct_create(char *name)
{
	struct container *ct;

	ct = xzalloc(sizeof(*ct));
	if (ct) {
		ct_handler_init(&ct->h);
		ct->h.ops = get_vz_ct_ops();
		ct->state = CT_STOPPED;
		ct->name = xstrdup(name);
		ct->tty_fd = -1;
		INIT_LIST_HEAD(&ct->cgroups);
		INIT_LIST_HEAD(&ct->cg_configs);
		INIT_LIST_HEAD(&ct->ct_nets);
		INIT_LIST_HEAD(&ct->ct_net_routes);
		INIT_LIST_HEAD(&ct->fs_mnts);
		INIT_LIST_HEAD(&ct->fs_devnodes);
		INIT_LIST_HEAD(&ct->uid_map);
		INIT_LIST_HEAD(&ct->gid_map);

		return &ct->h;
	}

	return NULL;

}
