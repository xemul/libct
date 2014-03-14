#ifndef __LIBCT_CT_H__
#define __LIBCT_CT_H__
struct ct_handler {
};

/*
 * The main structure describing a container
 */
struct container {
	char *name;
	struct list_head s_lh;
	struct libct_session *session;
	struct ct_handler h;
	enum ct_state state;

	/*
	 * Virtualization-specific fields
	 */

	unsigned long nsmask;	/* namespaces used by container */

	void *private; /* driver-specific */
};

static inline struct container *cth2ct(struct ct_handler *h)
{
	return container_of(h, struct container, h);
}

void containers_cleanup(struct libct_session *s);

#endif /* __LIBCT_CT_H__ */
