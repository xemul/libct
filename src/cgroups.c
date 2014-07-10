#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <mntent.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/mount.h>

#include "uapi/libct.h"

#include "list.h"
#include "bug.h"
#include "ct.h"
#include "cgroups.h"
#include "xmalloc.h"
#include "util.h"
#include "linux-kernel.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/*
 * Private controllers for libct internal needs
 */
enum {
	CTL_SERVICE = CT_NR_CONTROLLERS,
	CT_NR_CONTROLLERS_ALL
};

#define LIBCT_CTL_NAME	".libct"
#define LIBCT_CTL_PATH	DEFAULT_CGROUPS_PATH"/"LIBCT_CTL_NAME

struct cg_desc cg_descs[CT_NR_CONTROLLERS_ALL] = {
	[CTL_BLKIO]	= { .name = "blkio", },
	[CTL_CPU]	= { .name = "cpu", },
	[CTL_CPUACCT]	= { .name = "cpuacct", },
	[CTL_CPUSET]	= { .name = "cpuset", },
	[CTL_DEVICES]	= { .name = "devices", },
	[CTL_FREEZER]	= { .name = "freezer", },
	[CTL_HUGETLB]	= { .name = "hugetlb", },
	[CTL_MEMORY]	= { .name = "memory", },
	[CTL_NETCLS]	= { .name = "net_cls", },
	[CTL_SERVICE]	= { .name = LIBCT_CTL_NAME, },
};

int cgroup_add_mount(struct mntent *me)
{
	int i, found = -1;

	for (i = 0; i < CT_NR_CONTROLLERS; i++) {
		if (cg_descs[i].mounted_at)
			continue;

		if (hasmntopt(me, cg_descs[i].name)) {
			if (found == -1) {
				found = i;
				cg_descs[i].mounted_at = xstrdup(me->mnt_dir);
				if (!cg_descs[i].mounted_at)
					return -1;
			} else {
				cg_descs[i].merged = &cg_descs[found];
				cg_descs[i].mounted_at = cg_descs[found].mounted_at;
			}
		}
	}

	if (found == -1 && hasmntopt(me, "name=libct")) {
		i = CTL_SERVICE;
		cg_descs[i].mounted_at = xstrdup(me->mnt_dir);
		if (!cg_descs[i].mounted_at)
			return -1;
	}

	/* FIXME -- add custom cgroups' mount points if found == -1 */
	return 0;
}

int cgroups_create_service(void)
{
	if (cg_descs[CTL_SERVICE].mounted_at)
		return 0;

	mkdir(LIBCT_CTL_PATH, 0600);
	if (mount("cgroup", LIBCT_CTL_PATH, "cgroup",
				MS_MGC_VAL, "none,name=libct") < 0)
		return -LCTERR_CGCREATE;

	cg_descs[CTL_SERVICE].mounted_at = LIBCT_CTL_PATH;
	return 0;
}

static inline char *cgroup_get_path(int type, char *buf, int blen)
{
	int lp;
	lp = snprintf(buf, blen, "%s", cg_descs[type].mounted_at);
	return buf + lp;
}

int libct_controller_add(ct_handler_t ct, enum ct_controller ctype)
{
	if (ctype >= CT_NR_CONTROLLERS)
		return -LCTERR_INVARG;

	return ct->ops->add_controller(ct, ctype);
}

#define cbit(ctype)	(1 << ctype)

static int add_controller(struct container *ct, int ctype)
{
	struct controller *ctl;

	if (ct->cgroups_mask & cbit(ctype))
		return 0;

	ctl = xmalloc(sizeof(*ctl));
	if (!ctl)
		return -1;

	ctl->ctype = ctype;
	list_add_tail(&ctl->ct_l, &ct->cgroups);
	ct->cgroups_mask |= cbit(ctype);
	return 0;
}

int add_service_controller(struct container *ct)
{
	return add_controller(ct, CTL_SERVICE);
}

int local_add_controller(ct_handler_t h, enum ct_controller ctype)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	return add_controller(ct, ctype);
}

static void cg_config_free(struct cg_config *cg)
{
	if (cg) {
		xfree(cg->param);
		xfree(cg->value);
		xfree(cg);
	}
}

static struct cg_config *cg_config_alloc(enum ct_controller ctype, char *param, char *value)
{
	struct cg_config *cg = xmalloc(sizeof(*cg));

	BUG_ON(!param || !value);

	if (cg) {
		INIT_LIST_HEAD(&cg->l);
		cg->ctype = ctype;
		cg->param = xstrdup(param);
		cg->value = xstrdup(value);
		if (!cg->param || !cg->value) {
			cg_config_free(cg);
			cg = NULL;
		}
	}

	return cg;
}

static int config_controller(struct container *ct, enum ct_controller ctype,
		char *param, char *value)
{
	char path[PATH_MAX], *t;
	int fd, ret;

	t = cgroup_get_path(ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s/%s", ct->name, param);

	ret = fd = open(path, O_WRONLY);
	if (fd >= 0) {
		ret = 0;
		if (write(fd, value, strlen(value)) < 0)
			ret = -1;
		close(fd);
	}

	return ret;
}

int local_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	struct container *ct = cth2ct(h);

	if (!(ct->cgroups_mask & cbit(ctype)))
		return -LCTERR_NOTFOUND;

	if (ct->state != CT_RUNNING) {
		struct cg_config *cfg;

		/*
		 * Postpone cgroups configuration
		 */

		list_for_each_entry(cfg, &ct->cg_configs, l) {
			char *new;
			if (cfg->ctype != ctype || strcmp(cfg->param, param))
				continue;

			new = xstrdup(value);
			if (!new)
				return -1;
			xfree(cfg->value);
			cfg->value = new;
			return 0;
		}

		cfg = cg_config_alloc(ctype, param, value);
		if (!cfg)
			return -1;
		list_add_tail(&cfg->l, &ct->cg_configs);
		return 0;
	}

	return config_controller(ct, ctype, param, value) ? -LCTERR_CGCONFIG : 0;
}

static int cgroup_create_one(struct container *ct, struct controller *ctl)
{
	char path[PATH_MAX], *t;

	t = cgroup_get_path(ctl->ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s", ct->name);

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
			return -LCTERR_CGCREATE;
	}

	list_for_each_entry(cfg, &ct->cg_configs, l) {
		ret = local_config_controller(&ct->h, cfg->ctype, cfg->param, cfg->value);
		if (ret)
			return -LCTERR_CGCONFIG;
	}

	return 0;
}

static int cgroup_attach_one(struct container *ct, struct controller *ctl, char *pid)
{
	return config_controller(ct, ctl->ctype, "tasks", pid) ? -LCTERR_CGATTACH : 0;
}

int cgroups_attach(struct container *ct)
{
	char pid[12];
	struct controller *ctl;
	int ret = 0;

	snprintf(pid, sizeof(pid), "%d", getpid());
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
	snprintf(t, sizeof(path) - (t - path), "/%s", ct->name);
	rmdir(path);
}

void cgroups_destroy(struct container *ct)
{
	struct controller *ctl;

	list_for_each_entry(ctl, &ct->cgroups, ct_l)
		destroy_controller(ct, ctl);
}

void cgroups_free(struct container *ct)
{
	struct controller *ctl, *n;
	struct cg_config *cfg, *cn;

	list_for_each_entry_safe(ctl, n, &ct->cgroups, ct_l) {
		list_del(&ctl->ct_l);
		xfree(ctl);
	}

	list_for_each_entry_safe(cfg, cn, &ct->cg_configs, l) {
		list_del(&cfg->l);
		cg_config_free(cfg);
	}
}

/*
 * Bind mount container's controller root dir into @to
 */
static int re_mount_controller(struct container *ct, struct controller *ctl, char *to)
{
	char path[PATH_MAX], *t;

	if (mkdir(to, 0600))
		return -1;

	t = cgroup_get_path(ctl->ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s", ct->name);

	if (bind_mount(path, to, 0)) {
		rmdir(to);
		return -1;
	}

	return 0;
}

static int re_mount_cg(struct container *ct)
{
	char tpath[PATH_MAX];
	struct controller *ctl;
	int l;

	if (!ct->root_path)
		return -1; /* FIXME -- implement */

	l = snprintf(tpath, sizeof(tpath), "%s/%s", ct->root_path, ct->cgroup_sub);
	if (mount("none", tpath, "tmpfs", 0, NULL))
		goto err;

	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		if (ctl->ctype >= CT_NR_CONTROLLERS)
			continue;

		snprintf(tpath + l, sizeof(tpath) - l,
			 "/%s", cg_descs[ctl->ctype].name);
		if (re_mount_controller(ct, ctl, tpath))
			goto err_ctl;
	}

	return 0;

err_ctl:
	tpath[l] = '\0';
	umount2(tpath, MNT_DETACH);
err:
	return -1;
}

int try_mount_cg(struct container *ct)
{
	/* Not requested by user */
	if (!ct->cgroup_sub)
		return 0;
	/* Can't have cgroup submount in shared FS */
	if (!fs_private(ct))
		return -1;

	return re_mount_cg(ct);
}

int libct_controller_configure(ct_handler_t ct, enum ct_controller ctype,
		char *param, char *value)
{
	if (!param || !value)
		return -LCTERR_INVARG;

	return ct->ops->config_controller(ct, ctype, param, value);
}

int service_ctl_killall(struct container *ct)
{
	char path[PATH_MAX], *p, spid[16];
	FILE *f;
	bool has_tasks;

	p = cgroup_get_path(CTL_SERVICE, path, sizeof(path));
	snprintf(p, sizeof(path) - (p - path), "/%s/%s", ct->name, "tasks");

try_again:
	f = fopen(path, "r");
	if (!f)
		return -1;

	has_tasks = false;
	while (fgets(spid, sizeof(spid), f)) {
		int pid;

		has_tasks = true;
		pid = atoi(spid);
		if (kill(pid, SIGKILL))
			goto err;
	}

	fclose(f);
	if (has_tasks)
		/* they might have fork()-ed while we read the file */
		goto try_again;

	return 0;

err:
	fclose(f);
	return -1;
}
