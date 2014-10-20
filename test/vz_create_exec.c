#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <sched.h>

#include "test.h"

#define FS_ROOT		"/"
int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	char *ls_a[2] = { "ls", NULL};
	int fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};

	s = libct_session_open_local();
	ct = libct_container_create(s, "1337");
	p = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);

	if (libct_container_spawn_execvfds(ct, p, "/bin/ls", ls_a, fds) <= 0)
		goto err;

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
