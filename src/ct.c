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

ct_handler_t libct_container_create(libct_session_t ses)
{
	struct container *ct;

	ct = xmalloc(sizeof(*ct));
	if (ct) {
		ct->session = ses;
		ct->state = CT_STOPPED;
		ct->nsmask = 0;
		ct->flags = 0;
		ct->root_path = NULL;
		ct->fs_ops = NULL;
		ct->fs_priv = NULL;
		list_add_tail(&ct->s_lh, &ses->s_cts);
		INIT_LIST_HEAD(&ct->cgroups);
	}

	return &ct->h;
}

enum ct_state libct_container_state(ct_handler_t h)
{
	return cth2ct(h)->state;
}

static void container_destroy(struct container *ct)
{
	list_del(&ct->s_lh);
	cgroups_destroy(ct);
	if (ct->fs_ops)
		ct->fs_ops->put(ct->fs_priv);
	xfree(ct->root_path);
	xfree(ct);
}

void libct_container_destroy(ct_handler_t h)
{
	container_destroy(cth2ct(h));
}

void containers_cleanup(struct libct_session *s)
{
	struct container *ct, *n;

	list_for_each_entry_safe(ct, n, &s->s_cts, s_lh)
		container_destroy(ct);
}

int libct_container_set_nsmask(ct_handler_t h, unsigned long nsmask)
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
static int set_ct_root(struct container *ct)
{
	char put_root[] = "libct-root.XXXX";

	if (!(ct->nsmask & CLONE_NEWNS)) {
		if (chroot(ct->root_path))
			return -1;
		if (chdir("/"))
			return -1;
		return 0;
	}

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

	return ca->cb(ca->arg);
}

int libct_container_spawn_cb(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int pid;
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

	ca.cb = cb;
	ca.arg = arg;
	ca.ct = ct;
	pid = clone(ct_clone, &ca.stack_ptr, ct->nsmask | SIGCHLD, &ca);
	if (pid < 0)
		return -1;

	ct->root_pid = pid;
	ct->state = CT_RUNNING;
	return 0;
}

int libct_container_enter(ct_handler_t h, int (*cb)(void *), void *arg)
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
			if (chroot(nroot))
				exit(-1);
			if (chdir("/"))
				exit(-1);
		}

		aux = cb(arg);
		exit(aux);
	}

	if (aux >= 0)
		restore_ns(aux, &pid_ns);

	return pid;
}

int libct_container_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_RUNNING)
		return -1;

	kill(ct->root_pid, SIGKILL);
	return 0;
}

int libct_container_wait(ct_handler_t h)
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

	ct->state = CT_STOPPED;
	return 0;
}

int libct_container_set_option(ct_handler_t h, int opt, ...)
{
	int ret = -1;
	va_list parms;
	struct container *ct = cth2ct(h);

	va_start(parms, opt);
	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	}
	va_end(parms);

	return ret;
}
