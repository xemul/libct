#ifndef __LIBCT_ASYNC_H__
#define __LIBCT_ASYNC_H__

#include "uapi/libct.h"

enum {
	CT_STATE,
};

typedef int (async_callback)(libct_session_t s, void *req_args, int type, void *args);
typedef void (async_callback_destroy)(libct_session_t s, void *req_args);

int async_req_add(libct_session_t s, async_callback *cb,
		  async_callback_destroy *cb_destroy, void *args);
int async_req_run(libct_session_t s, int type, void *args);
void async_req_destroy(libct_session_t s);

#endif
