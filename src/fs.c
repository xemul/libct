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

static void put_subdir_path(void *priv)
{
	xfree(priv);
}

static const struct ct_fs_ops ct_subdir_fs_ops = {
	.mount = mount_subdir,
	.umount = umount_subdir,
	.put = put_subdir_path,
};

int libct_fs_set_private(ct_handler_t h, enum ct_fs_type type,
		void *priv)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED || ct->fs_ops != NULL)
		return -1;

	if (type == CT_FS_NONE)
		return 0;

	/* FIXME -- make this pluggable */
	if (type == CT_FS_SUBDIR) {
		ct->fs_ops = &ct_subdir_fs_ops;
		ct->fs_priv = xstrdup(priv);
		return 0;
	}

	return -1;
}

int libct_fs_set_root(ct_handler_t h, char *root)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -1;

	ct->root_path = xstrdup(root);
	if (!ct->root_path)
		return -1;

	return 0;
}
