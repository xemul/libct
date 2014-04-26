#ifndef __LIBCT_CGROUP_H__
#define __LIBCT_CGROUP_H__

#include "uapi/libct.h"

#include "list.h"

struct container;
struct mntent;

struct controller {
	struct list_head	ct_l;	/* links into container->cgroups */
	enum ct_controller	ctype;
};

struct cg_desc {
	char			*name;
	char			*mounted_at;
	struct cg_desc		*merged;
};

int cgroup_add_mount(struct mntent *);

/*
 * Postponed cgroups configuration
 */

struct cg_config {
	enum ct_controller	ctype;
	char			*param;
	char			*value;
	struct list_head	l;
};

extern struct cg_desc cg_descs[];

extern int cgroups_create(struct container *ct);
extern int cgroups_attach(struct container *ct);
extern void cgroups_destroy(struct container *ct);
extern void cgroups_free(struct container *ct);

extern int local_add_controller(ct_handler_t h, enum ct_controller ctype);
extern int local_config_controller(ct_handler_t h, enum ct_controller ctype, char *param, char *value);

extern int try_mount_cg(struct container *ct);

extern int cgroups_create_service(void);
extern int add_service_controller(struct container *ct);
extern int service_ctl_killall(struct container *ct);

#define DEFAULT_CGROUPS_PATH	"/sys/fs/cgroup"

#endif /* __LIBCT_CGROUP_H__ */
