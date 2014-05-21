#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "uapi/libct.h"

#include "linux-kernel.h"
#include "libct.h"
#include "list.h"
#include "ct.h"

void ct_handler_init(ct_handler_t h)
{
	h->ops = NULL;
	INIT_LIST_HEAD(&h->s_lh);
}

int libct_init_local(void)
{
	static bool done = false;

	if (done)
		return 0;

	if (linux_get_ns_mask())
		return -1;

	if (linux_get_cgroup_mounts())
		return -1;

	done = true;
	return 0;
}

enum ct_state libct_container_state(ct_handler_t h)
{
	return h->ops->get_state(h);
}

int libct_container_spawn_cb(ct_handler_t ct, int (*cb)(void *), void *arg)
{
	/* This one is optional -- only local ops support */
	if (!ct->ops->spawn_cb)
		return LCTERR_OPNOTSUPP;

	return ct->ops->spawn_cb(ct, cb, arg);
}

int libct_container_spawn_execv(ct_handler_t ct, char *path, char **argv)
{
	return libct_container_spawn_execve(ct, path, argv, NULL);
}

int libct_container_spawn_execve(ct_handler_t ct, char *path, char **argv, char **env)
{
	return ct->ops->spawn_execve(ct, path, argv, env, NULL);
}

int libct_container_spawn_execvr(ct_handler_t ct, char *path, char **argv, int *fds)
{
	return libct_container_spawn_execver(ct, path, argv, NULL, fds);
}

int libct_container_spawn_execver(ct_handler_t ct, char *path, char **argv, char **env, int *fds)
{
	return ct->ops->spawn_execve(ct, path, argv, env, fds);
}

int libct_container_enter_cb(ct_handler_t ct, int (*cb)(void *), void *arg)
{
	if (!ct->ops->enter_cb)
		return LCTERR_OPNOTSUPP;

	return ct->ops->enter_cb(ct, cb, arg);
}

int libct_container_enter_execv(ct_handler_t ct, char *path, char **argv)
{
	return libct_container_enter_execve(ct, path, argv, NULL);
}

int libct_container_enter_execve(ct_handler_t ct, char *path, char **argv, char **env)
{
	return ct->ops->enter_execve(ct, path, argv, env);
}


int libct_container_kill(ct_handler_t ct)
{
	return ct->ops->kill(ct);
}

int libct_container_wait(ct_handler_t ct)
{
	return ct->ops->wait(ct);
}

void libct_container_destroy(ct_handler_t ct)
{
	list_del_init(&ct->s_lh);
	ct->ops->destroy(ct);
}

void libct_container_close(ct_handler_t ct)
{
	list_del_init(&ct->s_lh);
	ct->ops->detach(ct);
}

int libct_container_set_nsmask(ct_handler_t ct, unsigned long nsmask)
{
	return ct->ops->set_nsmask(ct, nsmask);
}

int libct_container_set_option(ct_handler_t ct, int opt, ...)
{
	int ret;
	va_list parms;

	va_start(parms, opt);
	ret = ct->ops->set_option(ct, opt, parms);
	va_end(parms);

	return ret;
}

int libct_container_uname(ct_handler_t ct, char *host, char *domain)
{
	return ct->ops->uname(ct, host, domain);
}

int libct_container_set_caps(ct_handler_t ct, unsigned long mask, unsigned int apply_to)
{
	if (!apply_to || (apply_to & ~CAPS_ALL))
		return LCTERR_INVARG;

	return ct->ops->set_caps(ct, mask, apply_to);
}

libct_session_t libct_session_open(char *how)
{
	if (!how || !strcmp(how, "local"))
		return libct_session_open_local();
	if (!strncmp(how, "unix://", 7))
		return libct_session_open_pbunix(how + 7);

	return NULL;
}
