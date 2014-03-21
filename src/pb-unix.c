#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include "uapi/libct.h"
#include "session.h"
#include "compiler.h"
#include "list.h"
#include "xmalloc.h"
#include "ct.h"

struct pbunix_session {
	int sk;
	struct libct_session s;
};

static inline struct pbunix_session *s2us(libct_session_t s)
{
	return container_of(s, struct pbunix_session, s);
}

static ct_handler_t send_create_req(libct_session_t s)
{
	return NULL;
}

static void close_pbunix_session(libct_session_t s)
{
	struct pbunix_session *us;

	us = s2us(s);
	close(us->sk);
	xfree(us);
}

static const struct backend_ops pbunix_session_ops = {
	.create_ct = send_create_req,
	.close = close_pbunix_session,
};

libct_session_t libct_session_open_pbunix(char *sk_path)
{
	struct pbunix_session *us;
	struct sockaddr_un addr;
	socklen_t alen;

	us = xmalloc(sizeof(*us));
	if (us == NULL)
		return NULL;

	us->sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (us->sk == -1)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sk_path, sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	if (connect(us->sk, (struct sockaddr *)&addr, alen))
		goto err;

	us->s.ops = &pbunix_session_ops;
	return &us->s;

err:
	xfree(us);
	return NULL;
}
