#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include "test.h"

#define PIGGY_FILE	"libct_piggy_file"
#define PIGGY_DATA	"libct_piggy_data"

int main(int argc, char **argv)
{
	libct_session_t s;
	ct_handler_t ct;
	char *piggy_a[4];
	int fd;
	char dat[sizeof(PIGGY_DATA)];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");

	piggy_a[0] = "file_piggy";
	piggy_a[1] = PIGGY_FILE;
	piggy_a[2] = PIGGY_DATA;
	piggy_a[3] = NULL;

	libct_container_spawn_execv(ct, "file_piggy", piggy_a);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

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
