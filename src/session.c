#include "xmalloc.h"
#include "uapi/libct.h"
#include "libct.h"
#include "session.h"
#include "ct.h"

struct local_session {
	struct libct_session s;
};

static inline struct local_session *s2ls(libct_session_t s)
{
	return container_of(s, struct local_session, s);
}

static void close_local_session(libct_session_t s)
{
	xfree(s2ls(s));
}

static ct_handler_t create_local_ct(libct_session_t s, char *name)
{
	return ct_create(name);
}

static const struct backend_ops local_session_ops = {
	.type = BACKEND_LOCAL,
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
		INIT_LIST_HEAD(&s->s.s_cts);
		s->s.ops = &local_session_ops;
		return &s->s;
	}

	return NULL;
}

static inline ct_handler_t new_ct(libct_session_t ses, ct_handler_t cth)
{
	if (cth && list_empty(&cth->s_lh))
		list_add_tail(&cth->s_lh, &ses->s_cts);

	return cth;
}

ct_handler_t libct_container_create(libct_session_t ses, char *name)
{
	ct_handler_t cth;

	if (!name)
		return NULL;

	cth = ses->ops->create_ct(ses, name);
	return new_ct(ses, cth);
}

ct_handler_t libct_container_open(libct_session_t ses, char *name)
{
	ct_handler_t cth;

	if (!name)
		return NULL;

	if (!ses->ops->open_ct)
		return NULL;

	/*
	 * FIXME -- there can exist multiple handlers, need
	 * to invalidate them all on container destruction.
	 */

	cth = ses->ops->open_ct(ses, name);
	return new_ct(ses, cth);
}

void libct_session_close(libct_session_t s)
{
	ct_handler_t cth, n;

	list_for_each_entry_safe(cth, n, &s->s_cts, s_lh)
		libct_container_close(cth);

	s->ops->close(s);
}
