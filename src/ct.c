#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mount.h>

#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "linux-kernel.h"
#include "session.h"
#include "ct.h"
#include "namespaces.h"
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
		list_add_tail(&ct->s_lh, &ses->s_cts);
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

static int mount_proc(void)
{
	umount("/proc");
	return mount("proc", "/proc", "proc", 0, NULL);
}

static int try_mount_proc(struct container *ct)
{
	/* Container w/o pidns can work on existing proc */
	if (!(ct->nsmask & CLONE_NEWPID))
		return 0;
	/* Container w/o mountns cannot have it's own proc */
	if (!(ct->nsmask & CLONE_NEWNS))
		return 0;
	/* Explicitly disabled by user (LIBCT_OPT_NO_PROC_MOUNT) */
	if (ct->flags & CT_NO_PROC)
		return 0;

	return mount_proc();
}

static int ct_clone(void *arg)
{
	int ret;
	struct ct_clone_arg *ca = arg;

	ret = try_mount_proc(ca->ct);
	if (ret < 0)
		exit(ret);

	return ca->cb(ca->arg);
}

int libct_container_spawn(ct_handler_t h, int (*cb)(void *), void *arg)
{
	struct container *ct = cth2ct(h);
	int pid;
	struct ct_clone_arg ca;

	if (ct->state != CT_STOPPED)
		return -1;

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

			if (ns->cflag == CLONE_NEWNS)
				continue;
			if (!(ns->cflag & ct->nsmask))
				continue;

			if (switch_ns(ct->root_pid, ns, NULL))
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

int libct_container_join(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	int ret, status;

	if (ct->state != CT_RUNNING)
		return -1;

	ret = waitpid(ct->root_pid, &status, 0);
	if (ret < 0)
		return -1;

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
	case LIBCT_OPT_NO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_NO_PROC;
		break;
	}
	va_end(parms);

	return ret;
}
