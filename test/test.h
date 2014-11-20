#ifndef __LIBCT_TEST_H__
#define __LIBCT_TEST_H__

#include <unistd.h>

#include <libct-log-levels.h>

static inline void test_init()
{
	libct_log_init(STDERR_FILENO, LOG_DEBUG);
}

static inline int pass(char *msg)
{
	printf("%s\n", msg);
	printf("PASS\n");
	return 0;
}

static inline int fail(char *msg)
{
	printf("%s\n", msg);
	printf("FAIL\n");
	return 1;
}

static inline int err(char *msg)
{
	printf("%s\n", msg);
	printf("ERROR\n");
	return 2;
}
#endif
