#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include "namespaces.h"

struct ns_desc pid_ns = {
	.name = "pid",
	.cflag = CLONE_NEWPID,
};

struct ns_desc net_ns = {
	.name = "net",
	.cflag = CLONE_NEWNET,
};

static struct ns_desc mnt_ns = {
	.name = "mnt",
	.cflag = CLONE_NEWNS,
};

static struct ns_desc ipc_ns = {
	.name = "ipc",
	.cflag = CLONE_NEWIPC,
};

static struct ns_desc uts_ns = {
	.name = "uts",
	.cflag = CLONE_NEWUTS,
};

struct ns_desc *namespaces[] = {
	&pid_ns,
	&net_ns,
	&mnt_ns,
	&ipc_ns,
	&uts_ns,
	NULL
};

int switch_ns(int pid, struct ns_desc *nd, int *rst)
{
	char buf[32];
	int nsfd;
	int ret = -1;

	snprintf(buf, sizeof(buf), "/proc/%d/ns/%s", pid, nd->name);
	nsfd = open(buf, O_RDONLY);
	if (nsfd < 0)
		goto err_ns;

	if (rst) {
		snprintf(buf, sizeof(buf), "/proc/self/ns/%s", nd->name);
		*rst = open(buf, O_RDONLY);
		if (*rst < 0)
			goto err_rst;
	}

#ifndef VZ
	ret = setns(nsfd, nd->cflag);
#endif
	if (ret < 0)
		goto err_set;

	close(nsfd);
	return 0;

err_set:
	if (rst)
		close(*rst);
err_rst:
	close(nsfd);
err_ns:
	return -1;
}

void restore_ns(int rst, struct ns_desc *nd)
{
#ifndef VZ
	setns(rst, nd->cflag);
#endif
	close(rst);
}
