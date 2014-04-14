#ifndef __LIBCT_ERRORS_H__
#define __LIBCT_ERRORS_H__
/*
 * This file contains errors, that can be returned from various
 * library calls
 */

/* Generic */
#define LCTERR_BADCTSTATE	-2	/* Bad container state */
#define LCTERR_BADFSTYPE	-3	/* Bad FS type */
#define LCTERR_BADNETTYPE	-4	/* Bad Net type */

/* RPC-specific ones */
#define LCTERR_BADCTRID		-42	/* Bad container remote ID given */
#define LCTERR_BADCTRNAME	-43	/* Bad name on open */
#define LCTERR_RPCUNKNOWN	-44	/* Remote problem , but err is not given */
#define LCTERR_RPCCOMM		-45	/* Error communicating via channel */

#endif /* __LIBCT_ERRORS_H__ */
