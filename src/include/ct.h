#ifndef __LIBCT_CT_H__
#define __LIBCT_CT_H__

#include "fs.h"

struct container_ops {
	int (*spawn_cb)(ct_handler_t, int (*cb)(void *), void *);
	int (*spawn_execv)(ct_handler_t, char *path, char **argv);
	int (*enter_cb)(ct_handler_t, int (*cb)(void *), void *);
	int (*enter_execv)(ct_handler_t, char *path, char **argv);
	int (*kill)(ct_handler_t);
	int (*wait)(ct_handler_t);
	enum ct_state (*get_state)(ct_handler_t);
	int (*set_nsmask)(ct_handler_t, unsigned long nsmask);
	int (*add_controller)(ct_handler_t, enum ct_controller ctype);
	int (*config_controller)(ct_handler_t, enum ct_controller ctype, char *, char *);
	int (*fs_set_root)(ct_handler_t, char *root);
	int (*fs_set_private)(ct_handler_t, enum ct_fs_type, void *);
	int (*set_option)(ct_handler_t h, int opt, va_list parms);
	void (*destroy)(ct_handler_t);
	int (*net_add)(ct_handler_t h, enum ct_net_type, void *);
};

struct ct_handler {
	const struct container_ops *ops;
};

extern const struct container_ops local_ct_ops;

#define CT_AUTO_PROC		0x1

/*
 * Postponed cgroups configuration
 */

struct cg_config {
	enum ct_controller ctype;
	char *param;
	char *value;
	struct list_head l;
};

struct ct_net {
	struct list_head l;
	const struct ct_net_ops *ops;
};

/*
 * The main structure describing a container
 */
struct container {
	char *name;
	struct list_head s_lh;
	struct libct_session *session;
	struct ct_handler h;
	enum ct_state state;

	int root_pid;		/* pid of the root task */
	unsigned int flags;

	/*
	 * Virtualization-specific fields
	 */

	unsigned long nsmask;	/* namespaces used by container */
	unsigned long cgroups_mask;
	struct list_head cgroups;
	struct list_head cg_configs;

	/*
	 * FS-specific fields
	 */

	char *root_path;	/* directory where the CT's root is */
	const struct ct_fs_ops *fs_ops;
	void *fs_priv;

	/*
	 * Network-specific fields
	 */

	struct list_head	ct_nets; /* list of struct ct_net objects */

	void *private; /* driver-specific */
};

static inline struct container *cth2ct(struct ct_handler *h)
{
	return container_of(h, struct container, h);
}

void containers_cleanup(struct list_head *cts);

#endif /* __LIBCT_CT_H__ */
