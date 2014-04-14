#ifndef __LIBCT_ERRORS_H__
#define __LIBCT_ERRORS_H__
/*
 * This file contains errors, that can be returned from various
 * library calls
 */

/*
 * -1 is "reserved" for generic "something went wrong" result
 * since this value can be (well, is) widely explicitly used
 * all over the code.
 */

/* Generic */
#define LCTERR_BADCTSTATE	-2	/* Bad container state */
#define LCTERR_BADTYPE		-3	/* Bad type requested */
#define LCTERR_BADARG		-4	/* Bad argument for request */
#define LCTERR_NONS		-5	/* Required namespace is not available */

/* RPC-specific ones */
#define LCTERR_BADCTRID		-42	/* Bad container remote ID given */
#define LCTERR_BADCTRNAME	-43	/* Bad name on open */
#define LCTERR_RPCUNKNOWN	-44	/* Remote problem , but err is not given */
#define LCTERR_RPCCOMM		-45	/* Error communicating via channel */

#endif /* __LIBCT_ERRORS_H__ */
