#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include "uapi/libct.h"
#include "list.h"
#include "ct.h"
#include "cgroups.h"
#include "xmalloc.h"
#include "linux-kernel.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

struct cg_desc cg_descs[CT_NR_CONTROLLERS] = {
	[CTL_BLKIO]	= { .name = "blkio", },
	[CTL_CPU]	= { .name = "cpu", },
	[CTL_CPUACCT]	= { .name = "cpuacct", },
	[CTL_CPUSET]	= { .name = "cpuset", },
	[CTL_DEVICES]	= { .name = "devices", },
	[CTL_FREEZER]	= { .name = "freezer", },
	[CTL_HUGETLB]	= { .name = "hugetlb", },
	[CTL_MEMORY]	= { .name = "memory", },
	[CTL_NETCLS]	= { .name = "net_cls", },
};

int libct_controller_add(ct_handler_t ct, enum ct_controller ctype)
{
	return ct->ops->add_controller(ct, ctype);
}

int local_add_controller(ct_handler_t h, enum ct_controller ctype)
{
	struct container *ct = cth2ct(h);
	struct controller *ctl;

	if (ct->state != CT_STOPPED)
		return -1;

	if (ctype >= CT_NR_CONTROLLERS)
		return -1;

	if (ct->cgroups_mask & (1 << ctype))
		return 0;

	ctl = xmalloc(sizeof(*ctl));
	if (!ctl)
		return -1;

	ctl->ctype = ctype;
	list_add_tail(&ctl->ct_l, &ct->cgroups);
	ct->cgroups_mask |= (1 << ctype);
	return 0;
}

int local_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	struct container *ct = cth2ct(h);
	char path[PATH_MAX], *t;
	int fd, ret;

	if (!(ct->cgroups_mask & (1 << ctype)))
		return -1;

	if (ct->state != CT_RUNNING) {
		struct cg_config *cfg;

		/*
		 * Postpone cgroups configuration
		 */

		cfg = xmalloc(sizeof(*cfg));
		if (!cfg)
			return -1;

		cfg->ctype = ctype;
		cfg->param = xstrdup(param);
		cfg->value = xstrdup(value);
		list_add_tail(&cfg->l, &ct->cg_configs);
		return 0;
	}

	t = cgroup_get_path(ctype, path, sizeof(path));
	sprintf(t, "/%s/%s", ct->name, param);

	ret = fd = open(path, O_WRONLY);
	if (fd >= 0) {
		if (write(fd, value, strlen(value)) < 0)
			ret = -1;
		close(fd);
	}

	return ret;
}

static int cgroup_create_one(struct container *ct, struct controller *ctl)
{
	char path[PATH_MAX], *t;

	t = cgroup_get_path(ctl->ctype, path, sizeof(path));
	sprintf(t, "/%s", ct->name);

	return mkdir(path, 0600);
}

int cgroups_create(struct container *ct)
{
	struct controller *ctl;
	struct cg_config *cfg;
	int ret = 0;

	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		ret = cgroup_create_one(ct, ctl);
		if (ret)
			return ret;
	}

	list_for_each_entry(cfg, &ct->cg_configs, l) {
		ret = local_config_controller(&ct->h, cfg->ctype, cfg->param, cfg->value);
		if (ret)
			return ret;
	}

	return 0;
}

static int cgroup_attach_one(struct container *ct, struct controller *ctl, char *pid)
{
	return local_config_controller(&ct->h, ctl->ctype, "tasks", pid);
}

int cgroups_attach(struct container *ct)
{
	char pid[12];
	struct controller *ctl;
	int ret = 0;

	sprintf(pid, "%d", getpid());
	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		ret = cgroup_attach_one(ct, ctl, pid);
		if (ret)
			break;
	}

	return ret;
}

static void destroy_controller(struct container *ct, struct controller *ctl)
{
	char path[PATH_MAX], *t;

	/*
	 * Remove the directory with cgroup. It may fail, but what
	 * to do in that case? XXX
	 */
	t = cgroup_get_path(ctl->ctype, path, sizeof(path));
	sprintf(t, "/%s", ct->name);
	rmdir(path);

	list_del(&ctl->ct_l);
	xfree(ctl);
}

void cgroups_destroy(struct container *ct)
{
	struct controller *ctl, *n;
	struct cg_config *cfg, *cn;

	list_for_each_entry_safe(ctl, n, &ct->cgroups, ct_l)
		destroy_controller(ct, ctl);
	list_for_each_entry_safe(cfg, cn, &ct->cg_configs, l) {
		list_del(&cfg->l);
		xfree(cfg->param);
		xfree(cfg->value);
		xfree(cfg);
	}
}

int libct_controller_configure(ct_handler_t ct, enum ct_controller ctype,
		char *param, char *value)
{
	return ct->ops->config_controller(ct, ctype, param, value);
}
