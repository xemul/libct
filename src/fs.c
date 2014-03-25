#include <stdio.h>
#include <sys/mount.h>

#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "ct.h"

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

static const struct ct_fs_ops ct_subdir_fs_ops = {
	.mount = mount_subdir,
	.umount = umount_subdir,
	.get = get_subdir_path,
	.put = put_subdir_path,
};

const struct ct_fs_ops *fstype_get_ops(enum ct_fs_type type)
{
	/* FIXME -- make this pluggable */
	if (type == CT_FS_SUBDIR)
		return &ct_subdir_fs_ops;

	return NULL;
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

int libct_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *priv)
{
	return ct->ops->fs_set_private(ct, type, priv);
}

int libct_fs_set_root(ct_handler_t ct, char *root)
{
	return ct->ops->fs_set_root(ct, root);
}
