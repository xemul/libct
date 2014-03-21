#include "xmalloc.h"
#include "uapi/libct.h"
#include "libct.h"
#include "session.h"
#include "ct.h"

libct_session_t libct_session_open_local(void)
{
	struct libct_session *s;

	if (libct_init_local())
		return NULL;

	s = xmalloc(sizeof(*s));
	if (s) {
		INIT_LIST_HEAD(&s->s_cts);
	}

	return s;
}

void libct_session_close(libct_session_t s)
{
	containers_cleanup(s);
	xfree(s);
}
