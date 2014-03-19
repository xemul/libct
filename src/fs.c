#include <stdio.h>
#include "list.h"
#include "uapi/libct.h"
#include "ct.h"

int libct_container_set_private(ct_handler_t h, enum ct_fs_type type,
		void *priv)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED || ct->fstype != CT_FS_NONE)
		return -1;

	if (type == CT_FS_NONE)
		return 0;

	return -1;
}
