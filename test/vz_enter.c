#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "test.h"

#define FS_ROOT		"root"
int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	char *sleep_a[] = { "cat", NULL};
	char *ls_a[] = { "sh", "-c", "echo ok", NULL};
	int fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
	int pfd[2], tfd[2], status;
	char buf[10];
	pid_t pid;

	test_init();

	s = libct_session_open_local();
	ct = libct_container_create(s, "1339");
	p = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);

	libct_container_set_nsmask(ct,
			CLONE_NEWNS |
			CLONE_NEWUTS |
			CLONE_NEWIPC |
			CLONE_NEWNET |
			CLONE_NEWPID);

	if (pipe(pfd))
		goto err;

	fds[0] = pfd[0];
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
	libct_process_desc_set_fds(p, fds, 3);
	if (libct_container_spawn_execv(ct, p, "/bin/cat", sleep_a) <= 0)
		goto err;
	close(pfd[0]);

	if (pipe(tfd))
		goto err;

	fds[0] = STDIN_FILENO;
	fds[1] = tfd[1];
	fcntl(tfd[0], F_SETFD, FD_CLOEXEC);
	libct_process_desc_set_fds(p, fds, 3);
	pid = libct_container_enter_execv(ct, p, "/bin/sh", ls_a);
	if (pid <= 0)
		goto err;
	close(tfd[1]);

	if (read(tfd[0], buf, sizeof(buf)) != 3)
		goto err;

	waitpid(pid, &status, 0);

	close(pfd[1]);

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
