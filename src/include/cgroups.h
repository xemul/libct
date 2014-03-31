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
};

extern struct cg_desc cg_descs[CT_NR_CONTROLLERS];

struct container;
int cgroups_create(struct container *);
int cgroups_attach(struct container *);
void cgroups_destroy(struct container *);
int local_add_controller(ct_handler_t h, enum ct_controller ctype);
#endif
