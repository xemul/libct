#ifndef __UAPI_LIBCT_H__
#define __UAPI_LIBCT_H__

#include <sys/types.h>

/*
 * Basic init/fini
 */

int libct_init(void);
void libct_exit(void);

/*
 * Session management
 */

struct libct_session;
typedef struct libct_session *libct_session_t;

libct_session_t libct_session_open_local(void);
void libct_session_close(libct_session_t s);

/*
 * Basic container (virtualization and resources) management
 */

struct ct_handler;
typedef struct ct_handler *ct_handler_t;

ct_handler_t libct_container_create(libct_session_t ses);
void libct_container_destroy(ct_handler_t ct);

#endif /* __UAPI_LIBCT_H__ */
