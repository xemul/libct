/*
 * Daemon that gets requests from remote library backend
 * and forwards them to local session.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include "uapi/libct.h"

static char *opt_sk_path = NULL;
static bool opt_daemon = false;
static char *opt_pid_file = NULL;

static int parse_options(int argc, char **argv)
{
	static const char so[] = "ds:P:h";
	static struct option lo[] = {
		{ "daemon", no_argument, 0, 'd' },
		{ "socket", required_argument, 0, 's' },
		{ "pidfile", required_argument, 0, 'P' },
		{ "help", no_argument, 0, 'h' },
		{ }
	};
	int opt, idx;

	do {
		opt = getopt_long(argc, argv, so, lo, &idx);
		switch (opt) {
		case -1:
			break;
		case 'h':
			goto usage;
		case 'd':
			opt_daemon = true;
			break;
		case 's':
			opt_sk_path = optarg;
			break;
		case 'P':
			opt_pid_file = optarg;
			break;
		default:
			goto bad_usage;
		}
	} while (opt != -1);

	if (!opt_sk_path) {
		printf("Specify socket to work with\n");
		goto bad_usage;
	}

	return 0;

usage:
	printf("Usage: libctd [-d|--daemon] [-s|--socket <path>]\n");
	printf("\t-d|--daemon           daemonize after start\n");
	printf("\t-s|--socket <path>    path to socket to listen on\n");
	printf("\t-P|--pidfile <path>	write daemon pid to this file\n");
	printf("\n");
	printf("\t-h|--help             print this text\n");
bad_usage:
	return -1;
}

int main(int argc, char **argv)
{
	libct_session_t ses;

	if (parse_options(argc, argv))
		goto err;

	ses = libct_session_open_local();
	if (!ses)
		goto err;

	if (!libct_session_export_prepare(ses, opt_sk_path)) {
		if (opt_daemon)
			daemon(1, 0);

		if (opt_pid_file) {
			FILE *pf;

			pf = fopen(opt_pid_file, "w");
			if (!pf)
				goto err_close;

			fprintf(pf, "%d", getpid());
			fclose(pf);
		}
		libct_session_export(ses);
	}

err_close:
	libct_session_close(ses);
err:
	return 1;
}
