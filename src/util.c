#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uapi/libct.h"
#include "xmalloc.h"
#include "util.h"
#include "log.h"

static int create_dest(char *path, mode_t mode, bool isdir)
{
	char *tok;
	int ret;

	tok = path;
	while (1) {
		char c = 0;

		tok = strchr(tok + 1, '/');
		if (tok != NULL) {
			c = *tok;
			*tok = 0;
		}

		if (tok == NULL && !isdir) {
			ret = open(path, O_CREAT | O_WRONLY, mode);
			if (ret >= 0)
				close(ret);
		} else
			ret = mkdir(path, mode);

		if (ret < 0 && errno != EEXIST) {
			pr_perror("couldn't create %s", path);
			if (tok != NULL)
				*tok = c;
			return -1;
		}

		if (tok == NULL)
			break;

		*tok = c;
	}

	return 0;
}

int do_mount(char *src, char *dst, int flags, char *fstype, char *data)
{
	unsigned long mountflags = 0;
	struct stat st;
	bool isdir = true;

	if (flags & CT_FS_BIND) {
		if (fstype || data)
			return -1;

		mountflags |= MS_BIND;

		if (stat(src, &st)) {
			pr_perror("Unable to stat %s", src);
			return -1;
		}
		isdir = S_ISDIR(st.st_mode);
	}

	if (create_dest(dst, 0755, isdir))
		return -1;

	if (flags & CT_FS_RDONLY)
		mountflags |= MS_RDONLY;
	if (flags & CT_FS_NOEXEC)
		mountflags |= MS_NOEXEC;
	if (flags & CT_FS_NOSUID)
		mountflags |= MS_NOSUID;
	if (flags & CT_FS_NODEV)
		mountflags |= MS_NODEV;
	if (flags & CT_FS_STRICTATIME)
		mountflags |= MS_STRICTATIME;

	if (mount(src, dst, fstype, mountflags, data) == -1) {
		pr_perror("Unable to mount %s -> %s\n", src, dst);
		return -1;
	}

	if (flags & CT_FS_PRIVATE) {
		if (mount(NULL, dst, NULL, MS_PRIVATE, NULL) == -1) {
			pr_perror("Unable to mark %s as private", dst);
			umount(dst);
			return -1;
		}
	}

	return 0;
}

int set_string(char **dest, char *src)
{
	char *t;

	t = xstrdup(src);
	if (t == NULL)
		return -1;

	xfree(*dest);
	*dest = t;

	return 0;
}

