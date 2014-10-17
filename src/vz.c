#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/vzcalluser.h>
#include <linux/vzlist.h>
#include <linux/vziolimit.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/personality.h>
#include <linux/vzcalluser.h>
#include <linux/vziolimit.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>

#include "linux-kernel.h"
#include "vz.h"
#include "ct.h"
#include "xmalloc.h"
#include "fs.h"
#include "cgroups.h"
#include "net.h"
#include "util.h"

#define VZCTLDEV			"/dev/vzctl"

static int __vzctlfd = -1;

void vzctl_close(void)
{
	if (__vzctlfd != -1)
		close(__vzctlfd);
}

int vzctl_open(void)
{
	if (__vzctlfd != -1)
		return 0;

	__vzctlfd = open(VZCTLDEV, O_RDWR);
	if (__vzctlfd == -1) {
		pr_perror("Unable to open " VZCTLDEV);
		return -1;
	}

	return 0;
}

int get_vzctlfd(void)
{
	if (__vzctlfd == -1)
		vzctl_open();

	return __vzctlfd;
}

static void vz_ct_destroy(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	fs_free(ct);

	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(ct);
}

static int vz_spawn_cb(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	pr_err("Spawn with callback is not supported");
	return -1;
}

static int vz_set_option(ct_handler_t h, int opt, void *args)
{
	int ret = -LCTERR_BADTYPE;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		pr_warn("LIBCT_OPT_CGROUP_SUBMOUNT is currently unsupported");
		ret = -1;
		break;
	case LIBCT_OPT_KILLABLE:
		pr_warn("LIBCT_OPT_KILLABLE option is always set for VZ containers");
		ret = -1;
		break;
	case LIBCT_OPT_NOSETSID:
		pr_warn("LIBCT_OPT_NOSETSID option is always set for VZ containers");
		ret = -1;
		break;
	}

	return ret;
}

static int vz_uname(ct_handler_t h, char *host, char *dom)
{
	struct container *ct = NULL;

	if (!h)
		return -LCTERR_BADARG;

	ct = cth2ct(h);
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

static enum ct_state vz_get_state(ct_handler_t h)
{
	if (!h)
		return CT_ERROR;
	return cth2ct(h)->state;
}

static int vz_set_console_fd(ct_handler_t h, int fd)
{
	struct container *ct = NULL;
	if (!h || fd == -1)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	ct->tty_fd = fd;
	return 0;
}

static int vz_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = NULL;
	if (!h)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;
	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return -LCTERR_NONS;

	if (!(nsmask & CLONE_NEWIPC &&
	      nsmask & CLONE_NEWNET &&
	      nsmask & CLONE_NEWNS &&
	      nsmask & CLONE_NEWPID &&
	      nsmask & CLONE_NEWUTS)) {
		pr_err("Only full nsmask is supported in VZ containers");
		return -LCTERR_NONS;
	}
	ct->nsmask = nsmask;
	return 0;
}

static int vz_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	pr_perror("Controller configuration are not supported");
	return -LCTERR_CGCONFIG;
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= vz_spawn_cb,
	.spawn_execve		= NULL,
	.enter_cb		= NULL,
	.enter_execve		= NULL,
	.kill			= NULL,
	.wait			= NULL,
	.destroy		= vz_ct_destroy,
	.detach			= vz_ct_destroy,
	.set_nsmask		= vz_set_nsmask,
	.add_controller		= local_add_controller,
	.config_controller	= vz_config_controller,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_add_bind_mount	= local_add_bind_mount,
	.fs_del_bind_mount	= local_del_bind_mount,
	.fs_add_devnode		= NULL,
	.get_state		= vz_get_state,
	.set_option		= vz_set_option,
	.set_console_fd		= vz_set_console_fd,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.net_route_add		= local_net_route_add,
	.uname			= vz_uname,
	.add_uid_map		= local_add_uid_map,
	.add_gid_map		= local_add_gid_map,
};

const struct container_ops *get_vz_ct_ops(void)
{
	return &vz_ct_ops;
}
