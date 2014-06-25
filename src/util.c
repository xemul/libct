#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int bind_mount(char *src, char *dst)
{

	struct stat st;

	if (stat(src, &st)) {
		pr_perror("Unable to stat %s", src);
		return -1;
	}

	if (create_dest(dst, 0755, S_ISDIR(st.st_mode)))
		return -1;

	return mount(src, dst, NULL, MS_BIND, NULL);
}
