#include "xmalloc.h"
#include "uapi/libct.h"
#include "libct.h"
#include "session.h"
#include "ct.h"

struct local_session {
	struct list_head s_cts;
	struct libct_session s;
};

static inline struct local_session *s2ls(libct_session_t s)
{
	return container_of(s, struct local_session, s);
}

static void close_local_session(libct_session_t s)
{
	struct local_session *ls;

	ls = s2ls(s);
	containers_cleanup(&ls->s_cts);
	xfree(ls);
}

void local_session_add(libct_session_t s, struct container *ct)
{
	struct local_session *ls;

	ls = s2ls(s);
	list_add_tail(&ct->s_lh, &ls->s_cts);
}

static const struct backend_ops local_session_ops = {
	.close = close_local_session,
};

libct_session_t libct_session_open_local(void)
{
	struct local_session *s;

	if (libct_init_local())
		return NULL;

	s = xmalloc(sizeof(*s));
	if (s) {
		INIT_LIST_HEAD(&s->s_cts);
		s->s.ops = &local_session_ops;
	}

	return &s->s;
}

void libct_session_close(libct_session_t s)
{
	s->ops->close(s);
}
