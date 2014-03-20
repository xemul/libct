#ifndef __LIBCT_CGROUP_H__
#define __LIBCT_CGROUP_H__
struct controller {
	struct list_head ct_l;	/* links into container->cgroups */
	enum ct_controller ctype;
};

struct container;
void cgroups_destroy(struct container *);
#endif
