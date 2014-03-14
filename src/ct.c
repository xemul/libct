#include "xmalloc.h"
#include "list.h"
#include "uapi/libct.h"
#include "session.h"
#include "ct.h"

ct_handler_t libct_container_create(libct_session_t ses)
{
	struct container *ct;

	ct = xmalloc(sizeof(*ct));
	if (ct) {
		ct->session = ses;
		ct->state = CT_STOPPED;
		list_add_tail(&ct->s_lh, &ses->s_cts);
	}

	return &ct->h;
}

enum ct_state libct_container_state(ct_handler_t h)
{
	return cth2ct(h)->state;
}

static void container_destroy(struct container *ct)
{
	list_del(&ct->s_lh);
	xfree(ct);
}

void libct_container_destroy(ct_handler_t h)
{
	container_destroy(cth2ct(h));
}

void containers_cleanup(struct libct_session *s)
{
	struct container *ct, *n;

	list_for_each_entry_safe(ct, n, &s->s_cts, s_lh)
		container_destroy(ct);
}
