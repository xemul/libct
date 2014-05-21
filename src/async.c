#include <stdbool.h>

#include "xmalloc.h"
#include "session.h"
#include "list.h"
#include "log.h"
#include "async.h"

struct async_req {
	struct list_head	node;
	async_callback		*cb;
	async_callback_destroy	*cb_destroy;
	void			*args;
};

int async_req_add(libct_session_t s, async_callback *cb,
			async_callback_destroy *cb_destroy, void *args)
{
	struct async_req *r;

	r = xmalloc(sizeof(struct async_req));
	if (r == NULL)
		return -1;

	r->args		= args;
	r->cb		= cb;
	r->cb_destroy	= cb_destroy;
	list_add(&r->node, &s->async_list);

	return 1;
}

int async_req_run(libct_session_t s, int type, void *args)
{
	struct async_req *req, *t;
	int ret;

	list_for_each_entry_safe(req, t, &s->async_list, node) {
		ret = req->cb(s, req->args, type,  args);
		if (ret < 0)
			return -1;
		if (ret == 1) {
			list_del(&req->node);
			xfree(req);
		}
	}

	return 0;
}

void async_req_destroy(libct_session_t s)
{
	struct async_req *req, *t;

	list_for_each_entry_safe(req, t, &s->async_list, node) {
		req->cb_destroy(s, req->args);
		list_del(&req->node);
		xfree(req);
	}
}
