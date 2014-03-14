#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "linux-kernel.h"
#include "session.h"
#include "ct.h"
#include "asm/page.h"

ct_handler_t libct_container_create(libct_session_t ses)
{
	struct container *ct;

	ct = xmalloc(sizeof(*ct));
	if (ct) {
		ct->session = ses;
		ct->state = CT_STOPPED;
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
};

static int ct_clone(void *arg)
{
	struct ct_clone_arg *ca = arg;
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
	pid = clone(ct_clone, &ca.stack_ptr, ct->nsmask | SIGCHLD, &ca);
	if (pid < 0)
		return -1;

	ct->root_pid = pid;
	ct->state = CT_RUNNING;
	return 0;
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
