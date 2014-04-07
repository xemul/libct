#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "test.h"

#define PIGGY_FILE	"libct_piggy_file"
#define PIGGY_DATA	"libct_piggy_data"
#define LIBCTD_SK	"libctd-test.sk"
#define LIBCTD_PF	"libctd-pidf"

static int start_libctd(void)
{
	int pid;

	pid = fork();
	if (pid == 0) {
		execl("../src/libctd/libctd", "libctd",
				"--daemon",
				"--socket", LIBCTD_SK,
				"--pidfile", LIBCTD_PF,
				NULL);
		exit(1);
	}

	wait(NULL); /* it will daemonize once socket is created and listened */
	if (access(LIBCTD_SK, F_OK))
		return -1;

	return 0;
}

static void stop_libctd(void)
{
	system("kill -9 $(cat " LIBCTD_PF ")");
	unlink(LIBCTD_SK);
	unlink(LIBCTD_PF);
}

int main(int argc, char **argv)
{
	libct_session_t s;
	ct_handler_t ct;
	char *piggy_a[4];
	int fd;
	char dat[sizeof(PIGGY_DATA)];

	if (start_libctd())
		return err("Can't start daemon");

	s = libct_session_open_pbunix(LIBCTD_SK);
	if (!s)
		return err("Can't open session");

	ct = libct_container_create(s, "test");
	if (!ct)
		return err("Can't create CT");

	libct_session_close(s);

	s = libct_session_open_pbunix(LIBCTD_SK);
	if (!s)
		return err("Can't re-open session");

	ct = libct_container_open(s, "test");
	if (!ct)
		return fail("Can't open handle");

	piggy_a[0] = "file_piggy";
	piggy_a[1] = PIGGY_FILE;
	piggy_a[2] = PIGGY_DATA;
	piggy_a[3] = NULL;

	unlink(PIGGY_FILE);

	if (libct_container_spawn_execv(ct, "file_piggy", piggy_a))
		return fail("Can't spawn container");

	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	stop_libctd();

	fd = open(PIGGY_FILE, O_RDONLY);
	if (fd < 0)
		return fail("Piggy file not created");

	memset(dat, 0, sizeof(dat));
	read(fd, dat, sizeof(dat));
	close(fd);

	if (strcmp(dat, PIGGY_DATA))
		return fail("Piggy data differs");
	else
		return pass("Piggy file is OK");
}
