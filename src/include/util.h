#ifndef __LIBCT_UTIL_H__
#define __LIBCT_UTIL_H__

#include <stdarg.h>
#include <sys/types.h>
#include <dirent.h>

#define xvaopt(parm, type, def) ({	\
		type s;			\
		s = va_arg(parm, type);	\
		if (!s)			\
			s = def;	\
		s; })


extern int do_mount(char *src, char *dst, int flags, char *fstype, char *data);
extern int set_string(char **dest, char *src);
extern int parse_int(const char *str, int *val);
extern int parse_uint(const char *str, unsigned int *val);
extern int stat_file(const char *file);
extern int setup_fds_at(DIR *proc_self_d, int *fds, int n);
extern int setup_fds(int *fds, int n);

extern int spawn_wait(int *pipe);
extern int spawn_wait_and_close(int *pipe);
extern void spawn_wake_and_close(int *pipe, int ret);
extern void spawn_wake_and_cloexec(int *pipe, int ret);

#endif /* __LIBCT_UTIL_H__ */
