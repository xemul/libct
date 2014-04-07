#ifndef __LIBCT_SESSION_H__
#define __LIBCT_SESSION_H__

#include "list.h"
#include "ct.h"

struct backend_ops {
	ct_handler_t (*create_ct)(libct_session_t s, char *name);
	ct_handler_t (*open_ct)(libct_session_t s, char *name);
	void (*close)(libct_session_t s);
};

struct libct_session {
	const struct backend_ops *ops;
	struct list_head s_cts;
};

struct container;
void local_session_add(libct_session_t, struct container *);
#endif /* __LIBCT_SESSION_H__ */
