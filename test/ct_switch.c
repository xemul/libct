/*
 * Test entering into living container
 */
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>

#include "test.h"

int main(int argc, char **argv)
{
	libct_session_t s;
	ct_handler_t ct1, ct2;
	ct_process_desc_t pd;
	ct_process_t pr;
	char root1[] = "libct_root1";
	char root2[] = "libct_root2";
	char buf[1024];

	test_init();

	mkdir(root1, 0700);
	mkdir(root2, 0700);
	snprintf(buf, sizeof(buf), "%s/%s", root1, "test1");
	mkdir(buf, 0700);
	snprintf(buf, sizeof(buf), "%s/%s", root2, "test2");
	mkdir(buf, 0700);

	s = libct_session_open_local();
	ct1 = libct_container_create(s, "test1");
	ct2 = libct_container_create(s, "test2");

	libct_container_set_nsmask(ct1, CLONE_NEWNS);
	libct_container_set_nsmask(ct2, CLONE_NEWNS);
	libct_fs_set_root(ct1, root1);
	libct_fs_set_root(ct2, root2);

	libct_container_set_option(ct1, LIBCT_OPT_TASKLESS, 0);
	libct_container_set_option(ct2, LIBCT_OPT_TASKLESS, 0);

	pd = libct_process_desc_create(s);

	pr = libct_container_spawn_cb(ct1, pd, NULL, NULL);
	if (libct_handle_is_err(pr)) {
		return fail("Unable to start CT");
	}

	pr = libct_container_spawn_cb(ct2, pd, NULL, NULL);
	if (libct_handle_is_err(pr)) {
		return fail("Unable to start CT");
	}

	if (libct_container_switch(ct1))
		return fail("Unable to switch CT");
	if (access("/test1", F_OK))
		return fail("Unable to access /test1");
	if (libct_container_switch(ct2))
		return fail("Unable to switch CT");
	if (access("/test2", F_OK))
		return fail("Unable to access /test2");

	libct_container_kill(ct1);
	libct_container_kill(ct2);
	libct_container_destroy(ct1);
	libct_container_destroy(ct2);
	libct_session_close(s);

	return pass("CT is created and entered");
}
