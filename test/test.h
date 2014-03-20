#ifndef __LIBCT_TEST_H__
#define __LIBCT_TEST_H__
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
