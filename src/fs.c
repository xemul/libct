#include <stdio.h>
#include <sched.h>
#include <string.h>
#include <limits.h>

#include <sys/mount.h>

#include "uapi/libct.h"

#include "xmalloc.h"
#include "list.h"
#include "util.h"
#include "bug.h"
#include "ct.h"

/*
 * External bind mounts
 */

struct fs_mount {
	char *src;
	char *dst;
	struct list_head l;
};

static inline void umount_one(struct container *ct, struct fs_mount *fm, char *rdst)
{
	snprintf(rdst, PATH_MAX, "%s/%s", ct->root_path, fm->dst);
	umount(rdst);
}

int fs_mount_ext(struct container *ct)
{
	struct fs_mount *fm;
	char rdst[PATH_MAX];

	list_for_each_entry(fm, &ct->fs_mnts, l) {
		snprintf(rdst, PATH_MAX, "%s/%s", ct->root_path, fm->dst);
		if (bind_mount(fm->src, rdst))
			goto err;
	}

	return 0;

err:
	list_for_each_entry_continue_reverse(fm, &ct->fs_mnts, l)
		umount_one(ct, fm, rdst);

	return -LCTERR_CANTMOUNT;
}

void fs_umount_ext(struct container *ct)
{
	struct fs_mount *fm;
	char rdst[PATH_MAX];

	list_for_each_entry_reverse(fm, &ct->fs_mnts, l)
		umount_one(ct, fm, rdst);
}

static void fs_mount_free(struct fs_mount *fm)
{
	if (fm) {
		xfree(fm->src);
		xfree(fm->dst);
		xfree(fm);
	}
}

static void free_ext(struct container *ct)
{
	struct fs_mount *m, *mn;

	list_for_each_entry_safe(m, mn, &ct->fs_mnts, l) {
		list_del(&m->l);
		fs_mount_free(m);
	}
}

static struct fs_mount *fs_mount_alloc(char *src, char *dst)
{
	struct fs_mount *fm = xmalloc(sizeof(*fm));

	BUG_ON(!src || !dst);

	if (fm) {
		INIT_LIST_HEAD(&fm->l);
		fm->src = xstrdup(src);
		fm->dst = xstrdup(dst);

		if (!fm->dst || !fm->src) {
			fs_mount_free(fm);
			fm = NULL;
		}
	}

	return fm;
}

int local_add_mount(ct_handler_t h, char *src, char *dst, int flags)
{
	struct container *ct = cth2ct(h);
	struct fs_mount *fm;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -LCTERR_BADCTSTATE;

	fm = fs_mount_alloc(src, dst);
	if (!fm)
		return -1;
	list_add_tail(&fm->l, &ct->fs_mnts);
	return 0;
}

int local_del_mount(ct_handler_t h, char *dst)
{
	struct container *ct = cth2ct(h);
	struct fs_mount *fm;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -LCTERR_BADCTSTATE;

	list_for_each_entry(fm, &ct->fs_mnts, l) {
		if (strcmp(fm->dst, dst))
			continue;

		list_del(&fm->l);
		fs_mount_free(fm);
		return 0;
	}

	return -LCTERR_NOTFOUND;
}

/*
 * CT_FS_SUBDIR driver
 */

static int mount_subdir(char *root, void *priv)
{
	return bind_mount(priv, root);
}

static void umount_subdir(char *root, void *priv)
{
	umount(root);
}

static void *get_subdir_path(void *priv)
{
	return xstrdup(priv);
}

static void put_subdir_path(void *priv)
{
	xfree(priv);
}

static const struct ct_fs_ops ct_subdir_fs_ops = {
	.mount		= mount_subdir,
	.umount		= umount_subdir,
	.get		= get_subdir_path,
	.put		= put_subdir_path,
};

/*
 * Generic
 */

const struct ct_fs_ops *fstype_get_ops(enum ct_fs_type type)
{
	/* FIXME -- make this pluggable */
	if (type == CT_FS_SUBDIR)
		return &ct_subdir_fs_ops;

	return NULL;
}

int fs_mount(struct container *ct)
{
	if (ct->fs_ops) {
		int ret;

		if (!ct->root_path)
			return -1;

		ret = ct->fs_ops->mount(ct->root_path, ct->fs_priv);
		if (ret < 0)
			return -LCTERR_CANTMOUNT;
	}

	return 0;
}

void fs_umount(struct container *ct)
{
	if (!(ct->nsmask & CLONE_NEWNS))
		/* Otherwise they will die by themselves */
		fs_umount_ext(ct);

	if (ct->fs_ops)
		ct->fs_ops->umount(ct->root_path, ct->fs_priv);
}

void fs_free(struct container *ct)
{
	if (ct->fs_ops)
		ct->fs_ops->put(ct->fs_priv);
	xfree(ct->root_path);
	free_ext(ct);
	fs_free_devnodes(ct);
}

int local_fs_set_private(ct_handler_t h, enum ct_fs_type type, void *priv)
{
	int ret;
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	if (type == CT_FS_NONE) {
		if (ct->fs_ops) {
			ct->fs_ops->put(ct->fs_priv);
			ct->fs_priv = NULL;
		}

		return 0;
	}

	ret = -LCTERR_BADTYPE;
	ct->fs_ops = fstype_get_ops(type);
	if (ct->fs_ops) {
		ret = -LCTERR_BADARG;
		ct->fs_priv = ct->fs_ops->get(priv);
		if (ct->fs_priv != NULL)
			ret = 0;
	}

	return ret;
}

int local_fs_set_root(ct_handler_t h, char *root)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	ct->root_path = xstrdup(root);
	if (!ct->root_path)
		return -1;

	return 0;
}

int libct_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *priv)
{
	return ct->ops->fs_set_private(ct, type, priv);
}

int libct_fs_set_root(ct_handler_t ct, char *root)
{
	return ct->ops->fs_set_root(ct, root);
}

int libct_fs_add_mount(ct_handler_t ct, char *src, char *dst, int flags)
{
	if (flags != 0)
		return -LCTERR_INVARG;

	if (!src || !dst)
		return -LCTERR_INVARG;

	return ct->ops->fs_add_mount(ct, src, dst, flags);
}

int libct_fs_del_mount(ct_handler_t ct, char *dst)
{
	if (!dst)
		return -LCTERR_INVARG;

	return ct->ops->fs_del_mount(ct, dst);
}
