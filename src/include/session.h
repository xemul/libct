#ifndef __LIBCT_SESSION_H__
#define __LIBCT_SESSION_H__

#include "list.h"

struct backend_ops {
	void (*close)(libct_session_t s);
};

struct libct_session {
	const struct backend_ops *ops;
};

struct container;
void local_session_add(libct_session_t, struct container *);
#endif /* __LIBCT_SESSION_H__ */
