#ifndef __LIBCT_CGROUP_H__
#define __LIBCT_CGROUP_H__

#include "list.h"
#include "uapi/libct.h"

struct controller {
	struct list_head ct_l;	/* links into container->cgroups */
	enum ct_controller ctype;
};

struct cg_desc {
	char *name;
	char *mounted_at;
	struct cg_desc *merged;
};

struct mntent;
int cgroup_add_mount(struct mntent *);

/*
 * Postponed cgroups configuration
 */

struct cg_config {
	enum ct_controller ctype;
	char *param;
	char *value;
	struct list_head l;
};

extern struct cg_desc cg_descs[CT_NR_CONTROLLERS];

struct container;
int cgroups_create(struct container *);
int cgroups_attach(struct container *);
void cgroups_destroy(struct container *);
void cgroups_free(struct container *);
int local_add_controller(ct_handler_t h, enum ct_controller ctype);
int local_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value);

int try_mount_cg(struct container *);


#define DEFAULT_CGROUPS_PATH	"/sys/fs/cgroup"

#endif /* __LIBCT_CGROUP_H__ */
