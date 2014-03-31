#ifndef __UAPI_LIBCT_H__
#define __UAPI_LIBCT_H__

#include <sys/types.h>

/*
 * Session management
 */

struct libct_session;
typedef struct libct_session *libct_session_t;

libct_session_t libct_session_open(char *url);
libct_session_t libct_session_open_local(void);
libct_session_t libct_session_open_pbunix(char *sk_path);
void libct_session_close(libct_session_t s);

/*
 * Basic container management
 */

struct ct_handler;
typedef struct ct_handler *ct_handler_t;

enum ct_state {
	CT_ERROR = -1,
	CT_STOPPED,
	CT_RUNNING,
};

ct_handler_t libct_container_create(libct_session_t ses, char *name);
enum ct_state libct_container_state(ct_handler_t ct);
int libct_container_spawn_cb(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
int libct_container_spawn_execv(ct_handler_t ct, char *path, char **argv);
int libct_container_enter_cb(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
int libct_container_enter_execv(ct_handler_t ct, char *path, char **argv);
int libct_container_kill(ct_handler_t ct);
int libct_container_wait(ct_handler_t ct);
void libct_container_destroy(ct_handler_t ct);

/*
 * CT namespaces and cgroups management
 */

int libct_container_set_nsmask(ct_handler_t ct, unsigned long ns_mask);

enum ct_controller {
	CTL_BLKIO,
	CTL_CPU,
	CTL_CPUACCT,
	CTL_CPUSET,
	CTL_DEVICES,
	CTL_FREEZER,
	CTL_HUGETLB,
	CTL_MEMORY,
	CTL_NETCLS,
	CT_NR_CONTROLLERS
};

int libct_controller_add(ct_handler_t ct, enum ct_controller ctype);

/*
 * FS configuration
 */

int libct_fs_set_root(ct_handler_t ct, char *root_path);

enum ct_fs_type {
	CT_FS_NONE,	/* user may prepare himself */
	CT_FS_SUBDIR,	/* just a directory in existing tree */
};

int libct_fs_set_private(ct_handler_t ct, enum ct_fs_type, void *arg);

/* Mount proc when PID _and_ mount namespaces are used together */
#define LIBCT_OPT_AUTO_PROC_MOUNT			1

int libct_container_set_option(ct_handler_t ct, int opt, ...);

#endif /* __UAPI_LIBCT_H__ */
