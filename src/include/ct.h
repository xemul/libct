#ifndef __LIBCT_CT_H__
#define __LIBCT_CT_H__

#include "fs.h"

struct container_ops {
	int (*spawn_cb)(ct_handler_t, int (*cb)(void *), void *);
	int (*spawn_execv)(ct_handler_t, char *path, char **argv);
	enum ct_state (*get_state)(ct_handler_t);
};

struct ct_handler {
	const struct container_ops *ops;
};

extern const struct container_ops local_ct_ops;

#define CT_AUTO_PROC		0x1

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
	struct list_head cgroups;

	/*
	 * FS-specific fields
	 */

	char *root_path;	/* directory where the CT's root is */
	const struct ct_fs_ops *fs_ops;
	void *fs_priv;

	void *private; /* driver-specific */
};

static inline struct container *cth2ct(struct ct_handler *h)
{
	return container_of(h, struct container, h);
}

void containers_cleanup(struct list_head *cts);

#endif /* __LIBCT_CT_H__ */
