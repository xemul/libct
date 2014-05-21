#ifndef __LIBCT_CT_H__
#define __LIBCT_CT_H__

#include <stdbool.h>
#include <stdarg.h>
#include <sched.h>

#include "uapi/libct.h"

#include "fs.h"
#include "net.h"

struct container_ops {
	int (*spawn_cb)(ct_handler_t h, int (*cb)(void *), void *arg);
	int (*spawn_execve)(ct_handler_t, char *path, char **argv, char **env, int *fds);
	int (*enter_cb)(ct_handler_t h, int (*cb)(void *), void *arg);
	int (*enter_execve)(ct_handler_t h, char *path, char **argv, char **env);
	int (*kill)(ct_handler_t h);
	int (*wait)(ct_handler_t h);
	enum ct_state (*get_state)(ct_handler_t h);
	int (*set_nsmask)(ct_handler_t h, unsigned long nsmask);
	int (*add_controller)(ct_handler_t h, enum ct_controller ctype);
	int (*config_controller)(ct_handler_t h, enum ct_controller ctype, char *param, char *value);
	int (*fs_set_root)(ct_handler_t h, char *root);
	int (*fs_set_private)(ct_handler_t h, enum ct_fs_type, void *priv);
	int (*fs_add_mount)(ct_handler_t h, char *src, char *dst, int flags);
	int (*fs_del_mount)(ct_handler_t h, char *dst);
	int (*set_option)(ct_handler_t h, int opt, va_list parms);
	void (*destroy)(ct_handler_t h);
	void (*detach)(ct_handler_t h);
	int (*net_add)(ct_handler_t h, enum ct_net_type, void *arg);
	int (*net_del)(ct_handler_t h, enum ct_net_type, void *arg);
	int (*uname)(ct_handler_t h, char *host, char *domain);
	int (*set_caps)(ct_handler_t h, unsigned long mask, unsigned int apply_to);
};

struct ct_handler {
	const struct container_ops *ops;
	struct list_head s_lh;
};

ct_handler_t ct_create(char *name);

#define CT_AUTO_PROC		0x1
#define CT_KILLABLE		0x2

/*
 * The main structure describing a container
 */
struct container {
	char			*name;
	struct ct_handler	h;
	enum ct_state		state;

	int			root_pid;	/* pid of the root task */
	unsigned int		flags;

	/*
	 * Virtualization-specific fields
	 */

	unsigned long		nsmask;		/* namespaces used by container */
	unsigned long		cgroups_mask;
	struct list_head	cgroups;
	struct list_head	cg_configs;
	char			*cgroup_sub;
	char			*hostname;
	char			*domainname;

	/*
	 * Security 
	 */

	unsigned int		cap_mask;

	unsigned long		cap_bset;
	unsigned long		cap_caps;

	/*
	 * FS-specific fields
	 */

	char			*root_path;	/* directory where the CT's root is */
	const struct ct_fs_ops	*fs_ops;
	void			*fs_priv;
	struct list_head	fs_mnts;	/* list of struct fs_mount objects */

	/*
	 * Network-specific fields
	 */

	struct list_head	ct_nets;	/* list of struct ct_net objects */

	void			*private;	/* driver-specific */
};

static inline struct container *cth2ct(struct ct_handler *h)
{
	return container_of(h, struct container, h);
}

extern char *local_ct_name(ct_handler_t h);

static inline bool fs_private(struct container *ct)
{
	return /* FIXME ct->root_path || */ (ct->nsmask & CLONE_NEWNS);
}

extern void ct_handler_init(ct_handler_t h);

#endif /* __LIBCT_CT_H__ */
