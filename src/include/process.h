#ifndef __LIBCT_PROCESS_H__
#define __LIBCT_PROCESS_H__

#include "uapi/libct.h"

#include "compiler.h"

struct process_desc_ops {
	int (*setuid)(ct_process_desc_t p, unsigned int uid);
	int (*setgid)(ct_process_desc_t p, unsigned int gid);
	int (*setgroups)(ct_process_desc_t p, unsigned int size, unsigned int *groups);
	int (*set_caps)(ct_process_desc_t h, unsigned long mask, unsigned int apply_to);
	int (*set_pdeathsig)(ct_process_desc_t h, int sig);
	int (*set_lsm_label)(ct_process_desc_t h, char *label);
	int (*set_fds)(ct_process_desc_t h, int *fds, int fdn);
	ct_process_desc_t (*copy)(ct_process_desc_t h);
	void (*destroy)(ct_process_desc_t p);
};

struct ct_process_desc {
	const struct process_desc_ops *ops;
};

struct process_desc {
	struct ct_process_desc       h;
	unsigned int		uid;
	unsigned int		gid;
	unsigned int		ngroups;
	unsigned int		*groups;

	unsigned int		cap_mask;
	unsigned long		cap_bset;
	unsigned long		cap_caps;

	int			pdeathsig;

	int			lsm_on_exec;
	char			*lsm_label;

	int			*fds;
	int			fdn;
};

static inline struct process_desc *prh2pr(ct_process_desc_t h)
{
	return container_of(h, struct process_desc, h);
}

extern void local_process_init(struct process_desc *p);
extern struct process_desc *local_process_copy(struct process_desc *p);

#endif //__LIBCT_PROCESS_H__
