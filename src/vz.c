#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/personality.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <ctype.h>

#include "vzcalluser.h"
#include "vzlist.h"
#include "vziolimit.h"
#include "linux-kernel.h"
#include "vz.h"
#include "ct.h"
#include "xmalloc.h"
#include "fs.h"
#include "vzsyscalls.h"
#include "readelf.h"
#include "cgroups.h"
#include "net.h"
#include "util.h"

#define MAX_SHTD_TM 			120
#define VZCTLDEV			"/dev/vzctl"
#define ENVRETRY 			3
#define STR_SIZE			512
#define LINUX_REBOOT_MAGIC1		0xfee1dead
#define LINUX_REBOOT_MAGIC2		672274793
#define LINUX_REBOOT_CMD_POWER_OFF	0x4321FEDC

typedef enum {
	M_HALT,
	M_REBOOT,
	M_KILL,
	M_KILL_FORCE,
} stop_mode_e;

static int __vzctlfd = -1;

void vzctl_close(void)
{
	if (__vzctlfd != -1)
		close(__vzctlfd);
}

int vzctl_open(void)
{
	if (__vzctlfd != -1)
		return 0;

	__vzctlfd = open(VZCTLDEV, O_RDWR);
	if (__vzctlfd == -1) {
		pr_perror("Unable to open " VZCTLDEV);
		return -1;
	}

	return 0;
}

int get_vzctlfd(void)
{
	if (__vzctlfd == -1)
		vzctl_open();

	return __vzctlfd;
}

static int configure_sysctl(const char *var, const char *val)
{
	int fd = -1, len = -1, ret = -1;

	if (!var || !val)
		return -LCTERR_BADARG;

	fd = open(var, O_WRONLY);
	if (fd == -1)
		return -1;

	len = strlen(val);
	ret = write(fd, val, strlen(val));
	close(fd);

	return ret == len ? 0 : -1;
}

static int set_personality(unsigned long mask)
{
	unsigned long per;

	per = personality(0xffffffff) | mask;
	if (personality(per) == -1)
		return -1;
	return 0;
}

static int set_personality32(void)
{
#ifdef  __x86_64__
	if (get_arch_from_elf("/sbin/init") == elf_32)
		return set_personality(PER_LINUX32);
#endif
	return 0;
}

static void vz_ct_destroy(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	fs_free(ct);

	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(ct);
}

static int env_is_run(unsigned veid)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	memset(&env_create, 0, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = VE_TEST;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);

	if (errcode < 0 && (errno == ESRCH || errno == ENOTTY)) {
		return 0;
	} else if (errcode < 0) {
		pr_perror("unable to get Container state");
		return -1;
	}
	return 1;
}

static int env_get_pids_ioctl(unsigned veid, pid_t **pid)
{
	struct vzlist_vepidctl ve;
	int i, ret, size;
	pid_t buf[4096 * 2];
	pid_t *tmp;

	ve.veid = veid;
	ve.num = sizeof(buf) / 2;
	ve.pid = buf;
	while (1) {
		ret = ioctl(get_vzctlfd(), VZCTL_GET_VEPIDS, &ve);
		if (ret <= 0) {
			goto err;
		} else if (ret <= ve.num)
			break;
		size = ret + 20;
		if (ve.pid == buf)
			tmp = malloc(size * (2 * sizeof(pid_t)));
		else
			tmp = realloc(ve.pid, size * (2 * sizeof(pid_t)));
		if (tmp == NULL) {
			ret = -1;
			goto err;
		}
		ve.num = size;
		ve.pid = tmp;
	}
	*pid = malloc(ret * sizeof(pid_t));
	if (*pid == NULL) {
		ret = -1;
		goto err;
	}
	/* Copy pid from [pid:vpid] pair */
	for (i = 0; i < ret; i++)
		(*pid)[i] = ve.pid[2*i];
err:
	if (ve.pid != buf)
		free(ve.pid);
	return ret;
}

static int vzctl2_set_iolimit(unsigned veid, int limit)
{
	int ret;
	struct iolimit_state io;

	if (limit < 0)
		return -LCTERR_BADARG;

	io.id = veid;
	io.speed = limit;
	io.burst = limit * 3;
	io.latency = 10*1000;
	pr_info("Set up iolimit: %d", limit);
	ret = ioctl(get_vzctlfd(), VZCTL_SET_IOLIMIT, &io);
	if (ret) {
		if (errno == ESRCH) {
			pr_err("Container is not running");
			return -1;
		}
		else if (errno == ENOTTY) {
			pr_warn("iolimit feature is not supported by the kernel; "
					"iolimit configuration is skipped");
			return -1;
		}
		pr_perror("Unable to set iolimit");
		return -1;
	}
	return 0;
}

static int env_kill(unsigned veid)
{
	int ret, i;
	pid_t *pids = NULL;

	ret = env_get_pids_ioctl(veid, &pids);
	if (ret < 0)
		return -1;
	/* Kill all Container processes from VE0 */
	for (i = 0; i < ret; i++)
		kill(pids[i], SIGKILL);

	if (pids != NULL) free(pids);

	/* Wait for real Container shutdown */
	for (i = 0; i < (MAX_SHTD_TM / 2); i++) {
		if (!env_is_run(veid))
			return 0;
		usleep(500000);
	}
	return -1;
}

static int env_wait(int pid, int timeout, int *retcode)
{
	int ret, status;

	while ((ret = waitpid(pid, &status, 0)) == -1) {
		if (errno != EINTR) {
			pr_perror("Error in waitpid(%d)", pid);
			return -1;
		}
	}

	ret = -1;
	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (retcode != NULL) {
			*retcode = ret;
			ret = 0;
		}
	} else if (WIFSIGNALED(status)) {
		pr_info("Got signal %d", WTERMSIG(status));
		if (timeout) {
			pr_err("Timeout while waiting");
			return -1;
		}
	}

	return ret;
}

static int execvep(const char *path, char *const argv[], char *const envp[])
{
	if (!strchr(path, '/')) {
		char *p = "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin";
		for (; p && *p;) {
			char partial[FILENAME_MAX];
			char *p2;

			p2 = strchr(p, ':');
			if (p2) {
				size_t len = p2 - p;

				strncpy(partial, p, len);
				partial[len] = 0;
			} else {
				strcpy(partial, p);
			}
			if (strlen(partial))
				strcat(partial, "/");
			strcat(partial, path);

			execve(partial, argv, envp);

			if (errno != ENOENT)
				return -1;
			if (p2) {
				p = p2 + 1;
			} else {
				p = 0;
			}
		}
		return -1;
	} else
		return execve(path, argv, envp);
}

static int vzctl_chroot(const char *root)
{
	int i;
	sigset_t sigset;
	struct sigaction act;

	if (root == NULL)
		return -1;

        if (chdir(root)) {
                pr_perror("unable to change dir to %s", root);
		return -1;
	}
	if (chroot(root)) {
		pr_perror("chroot %s failed", root);
		return -1;
	}
	if (setsid() == -1)
		pr_perror("setsid()");

	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	for (i = 1; i <= NSIG; ++i)
		sigaction(i, &act, NULL);
	return 0;
}

static int vzctl_env_create_ioctl(unsigned veid, int flags)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	memset(&env_create, 0, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = flags;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);
#ifdef  __x86_64__
	/* Set personality PER_LINUX32 for i386 based VEs */
	if (errcode >= 0 && (flags & VE_ENTER))
		set_personality32();
#endif
	return errcode;
}

static int vz_spawn_cb(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	pr_err("Spawn with callback is not supported");
	return -1;
}

static int vz_set_option(ct_handler_t h, int opt, void *args)
{
	int ret = -LCTERR_BADTYPE;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		pr_warn("LIBCT_OPT_CGROUP_SUBMOUNT is currently unsupported");
		ret = -1;
		break;
	case LIBCT_OPT_KILLABLE:
		pr_warn("LIBCT_OPT_KILLABLE option is always set for VZ containers");
		ret = -1;
		break;
	case LIBCT_OPT_NOSETSID:
		pr_warn("LIBCT_OPT_NOSETSID option is always set for VZ containers");
		ret = -1;
		break;
	}

	return ret;
}

static int vz_ct_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	unsigned int veid;

	if (parse_uint(ct->name, &veid) == -1)
		return -LCTERR_NOTFOUND;

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;
	if (ct->nsmask & CLONE_NEWPID)
		return kill(ct->root_pid, SIGKILL);
	return env_kill(veid); /* for VZ containers CT_KILLABLE option is ignored */
}

static int wait_env_state(unsigned int veid, int state, unsigned int timeout)
{
	int i, rc;

	for (i = 0; i < timeout * 2; i++) {
		rc = env_is_run(veid);
		switch (state) {
		case CT_RUNNING:
			if (rc == 1)
				return 0;
			break;
		case CT_STOPPED:
			if (rc == 0)
				return 0;
			break;
		}
		usleep(500000);
	}
	return -1;
}

static int vzctl2_set_iopslimit(unsigned veid, int limit)
{
	int ret;
	struct iolimit_state io;

	if (limit < 0)
		return -LCTERR_BADARG;
	io.id = veid;
	io.speed = limit;
	io.burst = limit * 3;
	io.latency = 10*1000;
	pr_info("Set up iopslimit: %d", limit);
	ret = ioctl(get_vzctlfd(), VZCTL_SET_IOPSLIMIT, &io);
	if (ret) {
		if (errno == ESRCH) {
			pr_err("Container is not running");
			return -LCTERR_BADCTSTATE;
		}
		else if (errno == ENOTTY) {
			pr_warn("iopslimit feature is not supported"
				" by the kernel; iopslimit configuration is skipped");
			return -LCTERR_OPNOTSUPP;
		}
		pr_perror("Unable to set iopslimit");
		return -1;
	}
	return 0;
}

static int real_env_stop(int stop_mode)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd != -1) {
		dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
		close(fd);
	} else {
		close(0); close(1); close(2);
	}

	/* Disable fsync. The fsync will be done by umount() */
	configure_sysctl("/proc/sys/fs/fsync-enable", "0");
	switch (stop_mode) {
	case M_HALT: {
		char *argv[] = {"halt", NULL};
		char *argv_init[] = {"init", "0", NULL};
		execvep(argv[0], argv, NULL);
		execvep(argv_init[0], argv_init, NULL);
		break;
	}
	case M_REBOOT: {
		char *argv[] = {"reboot", NULL};
		execvep(argv[0], argv, NULL);
		break;
	}
	case M_KILL:
		return syscall(__NR_reboot, LINUX_REBOOT_MAGIC1,
			LINUX_REBOOT_MAGIC2,
			LINUX_REBOOT_CMD_POWER_OFF, NULL);
	}
	return -1;
}

static int vz_ct_wait(ct_handler_t h)
{
	struct container *ct = NULL;
	unsigned int veid = -1;
	int pid, child_pid, ret = 0;

	if (!h)
		return -LCTERR_BADARG;

	ct = cth2ct(h);
	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID");
		return -1;
	}

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;

	child_pid = fork();
	if (child_pid < 0) {
		pr_perror("Unable to stop Container, fork failed");
		goto kill_force;
	} else if (child_pid == 0) {
		struct sigaction act, actold;
		sigaction(SIGCHLD, NULL, &actold);
		sigemptyset(&act.sa_mask);
		act.sa_handler = SIG_IGN;
		act.sa_flags = SA_NOCLDSTOP;
		sigaction(SIGCHLD, &act, NULL);

		ret = syscall(__NR_setluid, veid);
		if (ret)
			_exit(ret);

		ret = vzctl_chroot(ct->root_path);
		if (ret)
			_exit(ret);

		pr_info("Stopping the Container ...");
		pid = fork();
		if (pid < 0) {
			pr_perror("Unable to stop Container, fork failed");
			_exit(1);
		} else if (pid == 0) {
			ret = vzctl_env_create_ioctl(veid, VE_ENTER);
			if (ret >= 0)
				ret = real_env_stop(M_HALT);
			_exit(ret);
		}

		if (wait_env_state(veid, CT_STOPPED, MAX_SHTD_TM) == 0)
			_exit(0);

		pr_info("Forcibly stop the Container...");
		vzctl2_set_iolimit(veid, 0);
		vzctl2_set_iopslimit(veid, 0);

		pid = fork();
		if (pid < 0) {
			pr_perror("Unable to stop Container, fork failed");
			_exit(1);
		} else if (pid == 0) {
			ret = vzctl_env_create_ioctl(veid, VE_ENTER);
			if (ret >= 0)
				ret = real_env_stop(M_KILL);
			_exit(ret);
		}
		if (wait_env_state(veid, CT_STOPPED, MAX_SHTD_TM) == 0)
			_exit(0);

		_exit(1);
	}
	env_wait(child_pid, 0, NULL);
	if (!env_is_run(veid)) {
		pr_info("Container was stopped");
		return 0;
	}

kill_force:
	pr_info("Forcibly kill the Container...");
	if (env_kill(veid)) {
		pr_err("Unable to stop Container: operation timed out");
		return -1;
	}

	return 0;
}

static int vz_uname(ct_handler_t h, char *host, char *dom)
{
	struct container *ct = NULL;

	if (!h)
		return -LCTERR_BADARG;

	ct = cth2ct(h);
	if (!(ct->nsmask & CLONE_NEWUTS))
		return -LCTERR_NONS;
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE; /* FIXME */

	if (host) {
		host = xstrdup(host);
		if (!host)
			return -1;
	}
	xfree(ct->hostname);
	ct->hostname = host;

	if (dom) {
		dom = xstrdup(dom);
		if (!dom)
			return -1;
	}
	xfree(ct->domainname);
	ct->domainname = dom;

	return 0;
}

static enum ct_state vz_get_state(ct_handler_t h)
{
	if (!h)
		return CT_ERROR;
	return cth2ct(h)->state;
}

static int vz_set_console_fd(ct_handler_t h, int fd)
{
	struct container *ct = NULL;
	if (!h || fd == -1)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	ct->tty_fd = fd;
	return 0;
}

static int vz_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = NULL;
	if (!h)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;
	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return -LCTERR_NONS;

	if (!(nsmask & CLONE_NEWIPC &&
	      nsmask & CLONE_NEWNET &&
	      nsmask & CLONE_NEWNS &&
	      nsmask & CLONE_NEWPID &&
	      nsmask & CLONE_NEWUTS)) {
		pr_err("Only full nsmask is supported in VZ containers");
		return -LCTERR_NONS;
	}
	ct->nsmask = nsmask;
	return 0;
}

static int vz_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	pr_perror("Controller configuration are not supported");
	return -LCTERR_CGCONFIG;
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= vz_spawn_cb,
	.spawn_execve		= NULL,
	.enter_cb		= NULL,
	.enter_execve		= NULL,
	.kill			= vz_ct_kill,
	.wait			= vz_ct_wait,
	.destroy		= vz_ct_destroy,
	.detach			= vz_ct_destroy,
	.set_nsmask		= vz_set_nsmask,
	.add_controller		= local_add_controller,
	.config_controller	= vz_config_controller,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_add_bind_mount	= local_add_bind_mount,
	.fs_del_bind_mount	= local_del_bind_mount,
	.fs_add_devnode		= NULL,
	.get_state		= vz_get_state,
	.set_option		= vz_set_option,
	.set_console_fd		= vz_set_console_fd,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.net_route_add		= local_net_route_add,
	.uname			= vz_uname,
	.add_uid_map		= local_add_uid_map,
	.add_gid_map		= local_add_gid_map,
};

const struct container_ops *get_vz_ct_ops(void)
{
	return &vz_ct_ops;
}
