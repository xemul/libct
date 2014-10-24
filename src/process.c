#include "process.h"
#include "xmalloc.h"

static void local_desc_destroy(ct_process_desc_t h)
{
	struct process_desc *p = prh2pr(h);

	xfree(p);
}

ct_process_desc_t local_desc_copy(ct_process_desc_t h)
{
	struct process_desc *p = prh2pr(h);
	struct process_desc *c;

	c = xmalloc(sizeof(struct process_desc));
	if (c == NULL)
		return NULL;

	memcpy(c, p, sizeof(struct process_desc));

	return &c->h;
}

static const struct process_desc_ops local_process_ops = {
	.copy		= local_desc_copy,
	.destroy	= local_desc_destroy,
};

void local_process_init(struct process_desc *p)
{
	p->h.ops	= &local_process_ops;
}
