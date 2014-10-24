#ifndef __LIBCT_PROCESS_H__
#define __LIBCT_PROCESS_H__

#include "uapi/libct.h"

#include "compiler.h"

struct process_desc_ops {
	ct_process_desc_t (*copy)(ct_process_desc_t h);
	void (*destroy)(ct_process_desc_t p);
};

struct ct_process_desc {
	const struct process_desc_ops *ops;
};

struct process_desc {
	struct ct_process_desc       h;
};

static inline struct process_desc *prh2pr(ct_process_desc_t h)
{
	return container_of(h, struct process_desc, h);
}

extern void local_process_init(struct process_desc *p);
extern struct process_desc *local_process_copy(struct process_desc *p);

#endif //__LIBCT_PROCESS_H__
