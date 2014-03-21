#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv)
{
	int fd, len, ret;

	/* usage: piggy file_name data_to_put_there */
	if (argc < 3)
		return 1;

	fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;

	len = strlen(argv[2]);
	ret = write(fd, argv[2], len);
	close(fd);

	if (ret != len) {
		unlink(argv[1]);
		return 1;
	}

	return 0;
}
