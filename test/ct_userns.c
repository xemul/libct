/*
 * Test empty "container" creation
 */
#define _GNU_SOURCE
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <linux/sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>

#include "test.h"

#define CT_USERNS_ROOT "ct_userns_root"

static int set_ct_alive(void *a)
{
	struct stat st;

	if (getuid() != 0)
		return -1;
	if (getgid() != 0)
		return -1;

	if (stat("test", &st))
		return -1;

	if (st.st_uid || st.st_gid)
		return -1;

	*(int *)a = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int *ct_alive;
	libct_session_t s;
	ct_handler_t ct;

	ct_alive = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	*ct_alive = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	if (libct_container_set_nsmask(ct, CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWNS))
		return 1;

	unshare(CLONE_NEWNS);

	umask(0);
	mkdir(CT_USERNS_ROOT, 0777);

	if (mount("ct_user", CT_USERNS_ROOT, "tmpfs", 0, NULL))
		return -1;
	libct_fs_set_root(ct, CT_USERNS_ROOT);

	mkdir(CT_USERNS_ROOT "/test", 0777);
	chown(CT_USERNS_ROOT "/test", 120000, 140000);

	if (libct_userns_add_uid_map(ct, 0, 120000, 1100) ||
	    libct_userns_add_uid_map(ct, 1100, 130000, 1200) ||
	    libct_userns_add_gid_map(ct, 0, 140000, 1200) ||
	    libct_userns_add_gid_map(ct, 1200, 150000, 1100))
		return 1;
	libct_container_spawn_cb(ct, set_ct_alive, ct_alive);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (!*ct_alive)
		return fail("Container is not alive");
	else
		return pass("Container is alive");
}
