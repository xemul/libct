#ifndef __UAPI_LIBCT_H__
#define __UAPI_LIBCT_H__

#include <sys/types.h>

/*
 * Session management
 */

struct libct_session;
typedef struct libct_session *libct_session_t;

libct_session_t libct_session_open_local(void);
void libct_session_close(libct_session_t s);

#endif /* __UAPI_LIBCT_H__ */
