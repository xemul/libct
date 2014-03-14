#include "xmalloc.h"
#include "uapi/libct.h"
#include "session.h"

libct_session_t libct_session_open_local(void)
{
	struct libct_session *s;

	s = xmalloc(sizeof(*s));

	return s;
}

void libct_session_close(libct_session_t s)
{
	xfree(s);
}
