#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mount.h>
#include <stdlib.h>

#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "linux-kernel.h"
#include "session.h"
#include "ct.h"
#include "namespaces.h"
#include "cgroups.h"
#include "asm/page.h"
#include "fs.h"
#include "net.h"

static enum ct_state local_get_state(ct_handler_t h)
{
	return cth2ct(h)->state;
}

static void container_destroy(struct container *ct)
{
	list_del(&ct->s_lh);
	cgroups_destroy(ct);
	if (ct->fs_ops)
		ct->fs_ops->put(ct->fs_priv);
	free_netconf(ct);
	xfree(ct->root_path);
	xfree(ct->name);
	xfree(ct);
}

static void local_ct_destroy(ct_handler_t h)
{
	container_destroy(cth2ct(h));
}

void containers_cleanup(struct list_head *cts)
{
	struct container *ct, *n;

	list_for_each_entry_safe(ct, n, cts, s_lh)
		container_destroy(ct);
}

static int local_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -1;

	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return -1;

	ct->nsmask = nsmask;
	return 0;
}

struct ct_clone_arg {
	char stack[PAGE_SIZE] __attribute__((aligned (8)));
	char stack_ptr[0];
	int (*cb)(void *);
	void *arg;
	struct container *ct;
	int start_sync_pipe[2];
};

static int re_mount_proc(bool have_old_proc)
{
	if (have_old_proc) {
		if (mount("none", "/proc", "none", MS_PRIVATE|MS_REC, NULL))
			return -1;

		umount2("/proc", MNT_DETACH);
	}

	return mount("proc", "/proc", "proc", 0, NULL);
}

static int try_mount_proc(struct container *ct, bool have_old_proc)
{
	if (!(ct->flags & CT_AUTO_PROC))
		return 0;

	/* Container w/o pidns can work on existing proc */
	if (!(ct->nsmask & CLONE_NEWPID))
		return 0;
	/* Container w/o mountns cannot have it's own proc */
	if (!(ct->nsmask & CLONE_NEWNS))
		return 0;

	return re_mount_proc(have_old_proc);
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
	char put_root[] = "libct-root.XXXX";

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

static int ct_clone(void *arg)
{
	bool have_old_proc = true;
	int ret;
	struct ct_clone_arg *ca = arg;

	close(ca->start_sync_pipe[1]);

	if (ca->ct->nsmask & CLONE_NEWNS) {
		/*
		 * Remount / as slave, so that it doesn't
		 * propagate its changes to our container.
		 */
		if (mount("none", "/", "none", MS_SLAVE, NULL))
			exit(-1);

	}

	if (ca->ct->root_path) {
		if (set_ct_root(ca->ct))
			exit(-1);

		have_old_proc = false;
	}

	ret = try_mount_proc(ca->ct, have_old_proc);
	if (ret < 0)
		exit(ret);

	ret = cgroups_attach(ca->ct);
	if (ret < 0)
		exit(ret);

	ret = -1;
	read(ca->start_sync_pipe[0], &ret, sizeof(ret));
	close(ca->start_sync_pipe[0]);
	if (ret)
		exit(ret);

	return ca->cb(ca->arg);
}

static int local_spawn_cb(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int pid, aux;
	struct ct_clone_arg ca;

	if (ct->state != CT_STOPPED)
		return -1;

	if (ct->fs_ops) {
		int ret;

		if (!ct->root_path)
			return -1;

		ret = ct->fs_ops->mount(ct->root_path, ct->fs_priv);
		if (ret < 0)
			return ret;
	}

	if (cgroups_create(ct))
		goto err_cg;

	if (pipe(ca.start_sync_pipe))
		goto err_pipe;

	ca.cb = cb;
	ca.arg = arg;
	ca.ct = ct;
	pid = clone(ct_clone, &ca.stack_ptr, ct->nsmask | SIGCHLD, &ca);
	if (pid < 0)
		goto err_clone;

	close(ca.start_sync_pipe[0]);
	if (net_start(ct))
		goto err_net;

	aux = 0;
	write(ca.start_sync_pipe[1], &aux, sizeof(aux));
	close(ca.start_sync_pipe[1]);

	ct->root_pid = pid;
	ct->state = CT_RUNNING;
	return 0;

err_net:
	aux = -1;
	write(ca.start_sync_pipe[1], &aux, sizeof(aux));
	waitpid(pid, NULL, 0);
err_clone:
	close(ca.start_sync_pipe[0]);
	close(ca.start_sync_pipe[1]);
err_pipe:
	cgroups_destroy(ct);
err_cg:
	if (ct->fs_ops)
		ct->fs_ops->umount(ct->root_path, ct->fs_priv);
	return -1;
}

struct execv_args {
	char *path;
	char **argv;
};

static int ct_execv(void *a)
{
	struct execv_args *ea = a;

	/* This gets control in the container's new root (if any) */
	execv(ea->path, ea->argv);
	return -1;
}

static int local_spawn_execv(ct_handler_t ct, char *path, char **argv)
{
	struct execv_args ea;

	ea.path = path;
	ea.argv = argv;

	return local_spawn_cb(ct, ct_execv, &ea);
}

static int local_enter_cb(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int aux = -1, pid;

	if (ct->state != CT_RUNNING)
		return -1;

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

		if (ct->root_path && !(ct->nsmask & CLONE_NEWNS)) {
			char nroot[128];

			sprintf(nroot, "/proc/%d/root", ct->root_pid);
			if (set_current_root(nroot))
				exit(-1);
		}

		if (cgroups_attach(ct))
			exit(-1);

		aux = cb(arg);
		exit(aux);
	}

	if (aux >= 0)
		restore_ns(aux, &pid_ns);

	return pid;
}

static int local_enter_execv(ct_handler_t h, char *path, char **argv)
{
	struct execv_args ea;

	ea.path = path;
	ea.argv = argv;

	return local_spawn_cb(h, ct_execv, &ea);
}

static int local_ct_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_RUNNING)
		return -1;
	if (!(ct->nsmask & CLONE_NEWPID))
		return -1;

	kill(ct->root_pid, SIGKILL);
	return 0;
}

static int local_ct_wait(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	int ret, status;

	if (ct->state != CT_RUNNING)
		return -1;

	ret = waitpid(ct->root_pid, &status, 0);
	if (ret < 0)
		return -1;

	if (ct->fs_ops)
		ct->fs_ops->umount(ct->root_path, ct->fs_priv);

	net_stop(ct);

	ct->state = CT_STOPPED;
	return 0;
}

static int local_set_option(ct_handler_t h, int opt, va_list parms)
{
	int ret = -1;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	}

	return ret;
}

const struct container_ops local_ct_ops = {
	.spawn_cb = local_spawn_cb,
	.spawn_execv = local_spawn_execv,
	.enter_cb = local_enter_cb,
	.enter_execv = local_enter_execv,
	.kill = local_ct_kill,
	.wait = local_ct_wait,
	.destroy = local_ct_destroy,
	.set_nsmask = local_set_nsmask,
	.add_controller = local_add_controller,
	.config_controller = local_config_controller,
	.fs_set_root = local_fs_set_root,
	.fs_set_private = local_fs_set_private,
	.get_state = local_get_state,
	.set_option = local_set_option,
	.net_add = local_net_add,
};

