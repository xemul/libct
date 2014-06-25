#ifndef __UAPI_LIBCT_H__
#define __UAPI_LIBCT_H__

#include <sys/types.h>
#include "libct-errors.h"

/*
 * Session management
 */

struct libct_session;
typedef struct libct_session *libct_session_t;

extern void *libct_err_to_handle(long err);
extern long libct_handle_to_err(void *handle);
extern int libct_handle_is_err(void *handle);

extern libct_session_t libct_session_open(char *url);
extern libct_session_t libct_session_open_local(void);
extern void libct_session_close(libct_session_t s);

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

extern ct_handler_t libct_container_create(libct_session_t ses, char *name);
extern ct_handler_t libct_container_open(libct_session_t ses, char *name);
extern void libct_container_close(ct_handler_t ct);

enum ct_state libct_container_state(ct_handler_t ct);
extern int libct_container_spawn_cb(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
extern int libct_container_spawn_execvfds(ct_handler_t ct, char *path, char **argv, int *fds);
extern int libct_container_spawn_execvefds(ct_handler_t ct, char *path, char **argv, char **env, int *fds);
extern int libct_container_spawn_execv(ct_handler_t ct, char *path, char **argv);
extern int libct_container_spawn_execve(ct_handler_t ct, char *path, char **argv, char **env);
extern int libct_container_enter_cb(ct_handler_t ct, int (*ct_fn)(void *), void *arg);
extern int libct_container_enter_execv(ct_handler_t ct, char *path, char **argv);
extern int libct_container_enter_execve(ct_handler_t ct, char *path, char **argv, char **env);
extern int libct_container_kill(ct_handler_t ct);
extern int libct_container_wait(ct_handler_t ct);
extern void libct_container_destroy(ct_handler_t ct);

/*
 * CT namespaces and cgroups management
 */

extern int libct_container_set_nsmask(ct_handler_t ct, unsigned long ns_mask);

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

extern int libct_controller_add(ct_handler_t ct, enum ct_controller ctype);
extern int libct_controller_configure(ct_handler_t ct, enum ct_controller ctype, char *param, char *value);

extern int libct_container_uname(ct_handler_t ct, char *host, char *domain);

#define CAPS_BSET	0x1
#define CAPS_ALLCAPS	0x2
#define CAPS_ALL	(CAPS_BSET | CAPS_ALLCAPS)
extern int libct_container_set_caps(ct_handler_t ct, unsigned long mask, unsigned int apply_to);

/*
 * FS configuration
 */

extern int libct_fs_set_root(ct_handler_t ct, char *root_path);

enum ct_fs_type {
	CT_FS_NONE,	/* user may prepare himself */
	CT_FS_SUBDIR,	/* just a directory in existing tree */
};

extern int libct_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *arg);
extern int libct_fs_add_mount(ct_handler_t ct, char *source, char *destination, int flags);
extern int libct_fs_del_mount(ct_handler_t ct, char *destination);

/*
 * Networking configuration
 */

enum ct_net_type {
	CT_NET_NONE,	/* no configured networking */
	CT_NET_HOSTNIC,	/* assign nic from host */
	CT_NET_VETH,	/* assign veth pair */
};

struct ct_net_veth_arg {
	char *host_name;
	char *ct_name;
	/* FIXME -- macs */
};

extern int libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg);
extern int libct_net_del(ct_handler_t ct, enum ct_net_type ntype, void *arg);

/*
 * Options
 */

/* Mount proc when PID _and_ mount namespaces are used together */
#define LIBCT_OPT_AUTO_PROC_MOUNT			1
/*
 * Bind mount CT's cgroup inside CT to let it create subgroups 
 * Argument: path where to mount it. NULL results in libct default
 */
#define LIBCT_OPT_CGROUP_SUBMOUNT			2
/*
 * Make it possible to libct_container_kill(). This is always
 * so when nsmask includes PIDNS, but if not this option will
 * help.
 */
#define LIBCT_OPT_KILLABLE				3
/*
 * Don't create a session for an initial process in CT
 */
#define LIBCT_OPT_NOSETSID				4

extern int libct_container_set_option(ct_handler_t ct, int opt, ...);

extern int libct_container_set_console_fd(ct_handler_t ct, int tty_fd);

extern int libct_fs_add_devnode(ct_handler_t ct, char *path, int mode, int major, int minor);

#endif /* __UAPI_LIBCT_H__ */
