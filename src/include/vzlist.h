#ifndef __LINUX_VZLIST_H__
#define __LINUX_VZLIST_H__

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __KERNEL__
#include <stdint.h>
#endif

#ifndef __ENVID_T_DEFINED__
typedef unsigned envid_t;
#define __ENVID_T_DEFINED__
#endif

#ifndef __user
#define __user
#endif

struct vzlist_veidctl {
	unsigned int	num;
	envid_t	__user	*id;
};

struct vzlist_vepidctl {
	envid_t		veid;
	unsigned int	num;
	pid_t __user	*pid;
};

struct vzlist_veipctl {
	envid_t		veid;
	unsigned int	num;
	void __user	*ip;
};

#define VZLISTTYPE 'x'
#define VZCTL_GET_VEIDS		_IOR(VZLISTTYPE, 1, struct vzlist_veidctl)
#define VZCTL_GET_VEPIDS	_IOR(VZLISTTYPE, 2, struct vzlist_vepidctl)
#define VZCTL_GET_VEIPS		_IOR(VZLISTTYPE, 3, struct vzlist_veipctl)
#define VZCTL_GET_VEIP6S	_IOR(VZLISTTYPE, 4, struct vzlist_veipctl)

#endif /* __LINUX_VZLIST_H__ */
