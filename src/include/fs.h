#ifndef __LIBCT_FS_H__
#define __LIBCT_FS_H__
struct _SetprivReq;
struct container;

struct ct_fs_ops {
	int (*mount)(char *root, void *fs_priv);
	void (*umount)(char *root, void *fs_priv);
	void *(*get)(void *fs_priv);
	void (*put)(void *fs_priv);
	void (*pb_pack)(void *arg, struct _SetprivReq *);
	void *(*pb_unpack)(struct _SetprivReq *);
};

const struct ct_fs_ops *fstype_get_ops(enum ct_fs_type type);
int local_fs_set_root(ct_handler_t h, char *root);
int local_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *priv);
int local_add_mount(ct_handler_t ct, char *src, char *dst, int flags);

int fs_mount(struct container *ct);
void fs_umount(struct container *ct);
#endif
