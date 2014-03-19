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

enum ct_state {
	CT_STOPPED,
	CT_RUNNING,
};

ct_handler_t libct_container_create(libct_session_t ses);
enum ct_state libct_container_state(ct_handler_t ct);
int libct_container_set_nsmask(ct_handler_t ct, unsigned long ns_mask);
int libct_container_spawn(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
int libct_container_enter(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
int libct_container_kill(ct_handler_t ct);
int libct_container_join(ct_handler_t ct);
void libct_container_destroy(ct_handler_t ct);

/*
 * FS configuration
 */

int libct_container_set_root(ct_handler_t ct, char *root_path);

/*
 * Do not mount proc when PID _and_ mount namespaces
 * are used together. Default -- off, i.e. proc will
 * be automatically mounted into default location.
 */
#define LIBCT_OPT_NO_PROC_MOUNT			1

int libct_container_set_option(ct_handler_t ct, int opt, ...);

#endif /* __UAPI_LIBCT_H__ */
