#ifndef __LIBCT_UTIL_H__
#define __LIBCT_UTIL_H__

#include <stdarg.h>

#define xvaopt(parm, type, def) ({	\
		type s;			\
		s = va_arg(parm, type);	\
		if (!s)			\
			s = def;	\
		s; })


extern int bind_mount(char *src, char *dst);

#endif /* __LIBCT_UTIL_H__ */
