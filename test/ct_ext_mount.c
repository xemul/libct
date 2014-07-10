/*
 * Test external bind mount works
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include "test.h"

#define FS_ROOT	"libct_test_root"
#define FS_EXT	"libct_test_external"
#define FS_DIR	"dir"
#define FS_FILE	"file"

static int check_fs_data(void *a)
{
	int fd;
	int *fs_data = a;

	fd = open("/" FS_DIR "/" FS_FILE, O_RDONLY);
	if (fd < 0)
		return 0;

	*fs_data = 1;
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	char *fs_data;
	libct_session_t s;
	ct_handler_t ct;
	int fs_err = 0;

	mkdir(FS_EXT);
	if (creat(FS_EXT "/" FS_FILE, 0600) < 0)
		return err("Can't create file");

	mkdir(FS_ROOT);
	mkdir(FS_ROOT "/" FS_DIR);
	unlink(FS_ROOT "/" FS_DIR "/" FS_FILE);

	fs_data = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	fs_data[0] = '\0';

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	printf("Set root\n");
	libct_fs_set_root(ct, FS_ROOT);
	printf("Set bind\n");
	libct_fs_add_bind_mount(ct, FS_EXT, FS_DIR, 0);
	printf("Spawn\n");
	libct_container_spawn_cb(ct, check_fs_data, fs_data);
	printf("Done\n");
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (rmdir(FS_ROOT "/" FS_DIR) < 0)
		fs_err |= 1;
	if (rmdir(FS_ROOT) < 0)
		fs_err |= 2;
	if (unlink(FS_EXT "/" FS_FILE) < 0)
		fs_err |= 4;
	if (rmdir(FS_EXT) < 0)
		fs_err |= 8;

	if (fs_err) {
		printf("FS remove failed %x\n", fs_err);
		return fail("FS broken");
	}

	if (!fs_data[0])
		return fail("FS private not accessible");

	return pass("Subdir as private is OK");
}
