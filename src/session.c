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

static ct_handler_t create_local_ct(libct_session_t s, char *name)
{
	struct local_session *ls;
	struct container *ct;

	ls = s2ls(s);
	ct = xzalloc(sizeof(*ct));
	if (ct) {
		ct->session = s;
		ct->h.ops = &local_ct_ops;
		ct->state = CT_STOPPED;
		ct->name = xstrdup(name);
		INIT_LIST_HEAD(&ct->cgroups);
		list_add_tail(&ct->s_lh, &ls->s_cts);
	}

	return &ct->h;
}

static const struct backend_ops local_session_ops = {
	.create_ct = create_local_ct,
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

ct_handler_t libct_container_create(libct_session_t ses, char *name)
{
	if (!name)
		return NULL;

	return ses->ops->create_ct(ses, name);
}

void libct_session_close(libct_session_t s)
{
	s->ops->close(s);
}
