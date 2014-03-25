#ifndef __LIBCT_FS_H__
#define __LIBCT_FS_H__
struct ct_fs_ops {
	int (*mount)(char *root, void *fs_priv);
	void (*umount)(char *root, void *fs_priv);
	void *(*get)(void *fs_priv);
	void (*put)(void *fs_priv);
};

const struct ct_fs_ops *fstype_get_ops(enum ct_fs_type type);
int local_fs_set_root(ct_handler_t h, char *root);
int local_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *priv);
#endif
