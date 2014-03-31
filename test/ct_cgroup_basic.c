#include <libct.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "test.h"

static int check_freezer_cg(void *a)
{
	int *st = a;
	char path[128];

	sprintf(path, "/sys/fs/cgroup/freezer/test-fr/freezer.state");
	st[0] = 1;
	if (access(path, F_OK) == 0)
		st[1] = 1;

	return 0;
}

int main(int argc, char **argv)
{
	int *ct_state;
	libct_session_t s;
	ct_handler_t ct;

	ct_state = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	ct_state[0] = 0;
	ct_state[1] = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test-fr");
	libct_container_add_controller(ct, CTL_FREEZER);
	libct_container_spawn_cb(ct, check_freezer_cg, ct_state);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (!ct_state[0])
		return fail("Container is not alive");
	if (!ct_state[1])
		return fail("Freezer cgroup is not there");

	return pass("Freezed CT is OK");
}
