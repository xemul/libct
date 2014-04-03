#include <stdio.h>
#include <sys/mount.h>

#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "ct.h"
#include "protobuf/rpc.pb-c.h"

struct fs_mount {
	char *src;
	char *dst;
	struct list_head l;
};

static int mount_subdir(char *root, void *priv)
{
	return mount(root, (char *)priv, NULL, MS_BIND, NULL);
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

static void pb_pack_subdir(void *arg, struct _SetprivReq *req)
{
	req->path = arg;
}

static void *pb_unpack_subdir(struct _SetprivReq *req)
{
	return xstrdup(req->path);
}

static const struct ct_fs_ops ct_subdir_fs_ops = {
	.mount = mount_subdir,
	.umount = umount_subdir,
	.get = get_subdir_path,
	.put = put_subdir_path,
	.pb_pack = pb_pack_subdir,
	.pb_unpack = pb_unpack_subdir,
};

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
			return ret;
	}

	return 0;
}

void fs_umount(struct container *ct)
{
	if (ct->fs_ops)
		ct->fs_ops->umount(ct->root_path, ct->fs_priv);
}

void free_fs(struct container *ct)
{
	struct fs_mount *m, *mn;

	if (ct->fs_ops)
		ct->fs_ops->put(ct->fs_priv);
	xfree(ct->root_path);

	list_for_each_entry_safe(m, mn, &ct->fs_mnts, l) {
		list_del(&m->l);
		xfree(m->src);
		xfree(m->dst);
		xfree(m);
	}
}

int local_fs_set_private(ct_handler_t h, enum ct_fs_type type, void *priv)
{
	int ret = -1;
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED || ct->fs_ops != NULL)
		return -1;

	if (type == CT_FS_NONE)
		return 0;

	ct->fs_ops = fstype_get_ops(type);
	if (ct->fs_ops) {
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
		return -1;

	ct->root_path = xstrdup(root);
	if (!ct->root_path)
		return -1;

	return 0;
}

int local_add_mount(ct_handler_t h, char *src, char *dst, int flags)
{
	struct container *ct = cth2ct(h);
	struct fs_mount *fm;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -1;

	if (flags != 0)
		return -1;

	fm = xmalloc(sizeof(*fm));
	if (!fm)
		return -1;

	fm->src = xstrdup(src);
	fm->dst = xstrdup(dst);
	list_add_tail(&fm->l, &ct->fs_mnts);
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
	return ct->ops->fs_add_mount(ct, src, dst, flags);
}
