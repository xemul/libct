#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <linux/sched.h>

#include "test.h"

#define FS_ROOT		"root"
int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t p;
	char *ls_a[2] = { "ls", NULL};

	s = libct_session_open_local();
	ct = libct_container_create(s, "1337");
	pd = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);
	libct_container_set_nsmask(ct,
			CLONE_NEWNS |
			CLONE_NEWUTS |
			CLONE_NEWIPC |
			CLONE_NEWNET |
			CLONE_NEWPID);

	p = libct_container_spawn_execv(ct, pd, "/bin/ls", ls_a);
	if (libct_handle_is_err(p))
		goto err;

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
