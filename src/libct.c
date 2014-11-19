#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "uapi/libct.h"

#include "linux-kernel.h"
#include "process.h"
#include "libct.h"
#include "list.h"
#include "err.h"
#include "ct.h"

void *libct_err_to_handle(long err)
{
	return ERR_PTR(err);
}

long libct_handle_to_err(void *h)
{
	return PTR_ERR(h);
}

int libct_handle_is_err(void *h)
{
	return IS_ERR(h);
}

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

int libct_container_spawn_cb(ct_handler_t ct, ct_process_desc_t pr, int (*cb)(void *), void *arg)
{
	/* This one is optional -- only local ops support */
	if (!ct->ops->spawn_cb)
		return -LCTERR_OPNOTSUPP;

	return ct->ops->spawn_cb(ct, pr, cb, arg);
}

int libct_container_spawn_execv(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv)
{
	return libct_container_spawn_execve(ct, pr, path, argv, NULL);
}

int libct_container_spawn_execve(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, char **env)
{
	return ct->ops->spawn_execve(ct, pr, path, argv, env, NULL);
}

int libct_container_spawn_execvfds(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, int *fds)
{
	return libct_container_spawn_execvefds(ct, pr, path, argv, NULL, fds);
}

int libct_container_spawn_execvefds(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, char **env, int *fds)
{
	return ct->ops->spawn_execve(ct, pr, path, argv, env, fds);
}

int libct_container_enter_cb(ct_handler_t ct, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	if (!ct->ops->enter_cb)
		return -LCTERR_OPNOTSUPP;

	return ct->ops->enter_cb(ct, p, cb, arg);
}

int libct_container_enter_execvfds(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv, int *fds)
{
	return libct_container_enter_execvefds(ct, p, path, argv, NULL, fds);
}

int libct_container_enter_execvefds(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv, char **env, int *fds)
{
	return ct->ops->enter_execve(ct, p, path, argv, env, fds);
}

int libct_container_enter_execv(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv)
{
	return libct_container_enter_execve(ct, p, path, argv, NULL);
}

int libct_container_enter_execve(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv, char **env)
{
	return ct->ops->enter_execve(ct, p, path, argv, env, NULL);
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

int libct_container_set_option(ct_handler_t ct, int opt, void *args)
{
	return ct->ops->set_option(ct, opt, args);
}

int libct_container_set_console_fd(ct_handler_t ct, int tty_fd)
{
	return ct->ops->set_console_fd(ct, tty_fd);
}

int libct_container_uname(ct_handler_t ct, char *host, char *domain)
{
	return ct->ops->uname(ct, host, domain);
}

libct_session_t libct_session_open(char *how)
{
	if (!how || !strcmp(how, "local"))
		return libct_session_open_local();

	return libct_err_to_handle(-LCTERR_INVARG);
}

int libct_userns_add_uid_map(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	return ct->ops->add_uid_map(ct, first, lower_first, count);
}

int libct_userns_add_gid_map(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	return ct->ops->add_gid_map(ct, first, lower_first, count);
}

int libct_process_desc_set_caps(ct_process_desc_t p, unsigned long mask, unsigned int apply_to)
{
	if (!apply_to || (apply_to & ~CAPS_ALL))
		return -LCTERR_INVARG;

	return p->ops->set_caps(p, mask, apply_to);
}

int libct_process_desc_set_pdeathsig(ct_process_desc_t p, int sig)
{
	return p->ops->set_pdeathsig(p, sig);
}

int libct_process_desc_setuid(ct_process_desc_t p, unsigned int uid)
{
	return p->ops->setuid(p, uid);
}

int libct_process_desc_setgid(ct_process_desc_t p, unsigned int gid)
{
	return p->ops->setgid(p, gid);
}

int libct_process_desc_setgroups(ct_process_desc_t p, unsigned int size, unsigned int groups[])
{
	return p->ops->setgroups(p, size, groups);
}

ct_process_desc_t libct_process_desc_copy(ct_process_desc_t p)
{
	return p->ops->copy(p);
}

void libct_process_desc_destroy(ct_process_desc_t p)
{
	return p->ops->destroy(p);
}

int libct_process_desc_set_lsm_label(ct_process_desc_t p, char *label)
{
	return p->ops->set_lsm_label(p, label);
}
