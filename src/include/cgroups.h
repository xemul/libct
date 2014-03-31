#ifndef __LIBCT_CGROUP_H__
#define __LIBCT_CGROUP_H__
struct controller {
	struct list_head ct_l;	/* links into container->cgroups */
	enum ct_controller ctype;
};

struct container;
int cgroups_create(struct container *);
int cgroups_attach(struct container *);
void cgroups_destroy(struct container *);
int local_add_controller(ct_handler_t h, enum ct_controller ctype);
#endif
