#ifndef __LIBCT_LINUX_KERNEL_H__
#define __LIBCT_LINUX_KERNEL_H__
extern unsigned long kernel_ns_mask;
int linux_get_ns_mask(void);
int linux_get_cgroup_mounts(void);
char *cgroup_get_path(int type, char *buf, int s);
#endif /* __LIBCT_LINUX_KERNEL_H__ */
