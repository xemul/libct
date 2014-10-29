#ifndef __LIBCT_CT_H__
#define __LIBCT_CT_H__

#include <stdbool.h>
#include <stdarg.h>
#include <sched.h>

#include "uapi/libct.h"

#include "fs.h"
#include "net.h"
#include "process.h"

struct container_ops {
	int (*spawn_cb)(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg);
	int (*spawn_execve)(ct_handler_t, ct_process_desc_t p, char *path, char **argv, char **env, int *fds);
	int (*enter_cb)(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg);
	int (*enter_execve)(ct_handler_t h, ct_process_desc_t p, char *path, char **argv, char **env, int *fds);
	int (*kill)(ct_handler_t h);
	int (*wait)(ct_handler_t h);
	enum ct_state (*get_state)(ct_handler_t h);
	int (*set_nsmask)(ct_handler_t h, unsigned long nsmask);
	int (*add_controller)(ct_handler_t h, enum ct_controller ctype);
	int (*config_controller)(ct_handler_t h, enum ct_controller ctype, char *param, char *value);
	int (*fs_set_root)(ct_handler_t h, char *root);
	int (*fs_set_private)(ct_handler_t h, enum ct_fs_type, void *priv);
	int (*fs_add_mount)(ct_handler_t h, char *src, char *dst, int flags, char *fstype, char *data);
	int (*fs_add_bind_mount)(ct_handler_t h, char *src, char *dst, int flags);
	int (*fs_del_bind_mount)(ct_handler_t h, char *dst);
	int (*set_option)(ct_handler_t h, int opt, void *args);
	int (*fs_add_devnode)(ct_handler_t h, char *path, int type, int major, int minor);
	int (*set_console_fd)(ct_handler_t h, int fd);
	void (*destroy)(ct_handler_t h);
	void (*detach)(ct_handler_t h);
	ct_net_t (*net_add)(ct_handler_t h, enum ct_net_type, void *arg);
	int (*net_del)(ct_handler_t h, enum ct_net_type, void *arg);
	ct_net_route_t (*net_route_add)(ct_handler_t h);
	int (*uname)(ct_handler_t h, char *host, char *domain);
	int (*set_caps)(ct_handler_t h, unsigned long mask, unsigned int apply_to);
	int (*set_pdeathsig)(ct_handler_t h, int sig);
	int (*add_uid_map)(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count);
	int (*add_gid_map)(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count);
};

struct ct_handler {
	const struct container_ops *ops;
	struct list_head s_lh;
};

ct_handler_t ct_create(char *name);

#define CT_AUTO_PROC		0x1
#define CT_KILLABLE		0x2
#define CT_NOSETSID		0x4

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
	int			pdeathsig;

	/*
	 * FS-specific fields
	 */

	char			*root_path;	/* directory where the CT's root is */
	const struct ct_fs_ops	*fs_ops;
	void			*fs_priv;
	struct list_head	fs_mnts;	/* list of struct fs_mount objects */
	struct list_head	fs_devnodes;	/* list of struct fs_mount objects */

	/*
	 * Network-specific fields
	 */

	struct list_head	ct_nets;	/* list of struct ct_net objects */
	struct list_head	ct_net_routes;	/* list of struct ct_net objects */

	/*
	 * Session-specific fields
	 */
	int			tty_fd;

	void			*private;	/* driver-specific */

	struct list_head	uid_map;
	struct list_head	gid_map;
};

struct _uid_gid_map {
	struct list_head	node;
	unsigned int first;
	unsigned int lower_first;
	unsigned int count;
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
