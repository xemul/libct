#ifndef __LIBCT_FS_H__
#define __LIBCT_FS_H__
struct ct_fs_ops {
	int (*mount)(char *root, void *fs_priv);
	void (*umount)(char *root, void *fs_priv);
	void *(*get)(void *fs_priv);
	void (*put)(void *fs_priv);
};
#endif
