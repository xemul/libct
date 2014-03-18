#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>

static int set_ct_alive(void *a)
{
	*(int *)a = 1;
	return 0;
}

static int set_ct_enter(void *a)
{
	*((int *)a + 1) = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int *ct_alive;
	libct_session_t s;
	ct_handler_t ct;

	ct_alive = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	ct_alive[0] = 0;
	ct_alive[1] = 0;

	libct_init();
	s = libct_session_open_local();
	ct = libct_container_create(s);
	libct_container_spawn(ct, set_ct_alive, ct_alive);
	libct_container_enter(ct, set_ct_enter, ct_alive);
	libct_container_join(ct);
	libct_container_destroy(ct);
	libct_session_close(s);
	libct_exit();

	if (!ct_alive[0]) {
		printf("Container is not alive\nFAIL\n");
		return 1;
	}

	if (!ct_alive[1]) {
		printf("Container couldn't be entered\nFAIL\n");
		return 1;
	}

	printf("Container is enterable\nPASS\n");
	return 0;
}
