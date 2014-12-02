#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "process.h"
#include "xmalloc.h"

static int local_desc_setuid(ct_process_desc_t h, unsigned uid)
{
	struct process_desc *p = prh2pr(h);

	p->uid = uid;

	return 0;
}

static int local_desc_setgid(ct_process_desc_t h, unsigned gid)
{
	struct process_desc *p = prh2pr(h);

	p->gid = gid;

	return 0;
}

static int local_desc_setgroups(ct_process_desc_t h, unsigned int ngroups, unsigned int *groups)
{
	struct process_desc *p = prh2pr(h);
	unsigned int *g = NULL;

	if (ngroups) {
		g = xmalloc(ngroups * (sizeof(*groups)));
		if (g == NULL)
			return -1;
		memcpy(g, groups, ngroups * (sizeof(*groups)));
	}

	p->groups = g;
	p->ngroups = ngroups;

	return 0;
}

static int local_desc_set_caps(ct_process_desc_t h, unsigned long mask, unsigned int apply_to)
{
	struct process_desc *p = prh2pr(h);

	if (apply_to & CAPS_BSET) {
		p->cap_mask |= CAPS_BSET;
		p->cap_bset = mask;
	}

	if (apply_to & CAPS_ALLCAPS) {
		p->cap_mask |= CAPS_ALLCAPS;
		p->cap_caps = mask;
	}

	return 0;
}

static int local_desc_set_pdeathsig(ct_process_desc_t h, int sig)
{
	struct process_desc *p = prh2pr(h);

	p->pdeathsig = sig;

	return 0;
}

static void local_desc_destroy(ct_process_desc_t h)
{
	struct process_desc *p = prh2pr(h);

	xfree(p->lsm_label);
	xfree(p->groups);
	xfree(p->fds);
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
	c->groups = NULL;
	c->lsm_label = NULL;
	c->fds = NULL;

	if (p->ngroups) {
		c->groups = xmalloc(p->ngroups * sizeof(c->groups[0]));
		if (c->groups == NULL)
			goto err;
		memcpy(c->groups, p->groups, p->ngroups * sizeof(c->groups[0]));
	}

	if (p->fds) {
		/* reserve space for wait_pipe */
		c->fds = xmalloc((p->fdn + 1) * sizeof(c->fds[0]));
		if (c->fds == NULL)
			goto err;
		memcpy(c->fds, p->fds, p->fdn * sizeof(c->fds[0]));
	}

	if (p->lsm_label) {
		c->lsm_label = xstrdup(p->lsm_label);
		if (c->lsm_label == NULL)
			goto err;
	}

	return &c->h;
err:
	local_desc_destroy(&c->h);
	return NULL;
}

int local_desc_set_lsm_label(ct_process_desc_t h, char *label)
{
	struct process_desc *p = prh2pr(h);
	char *l;

	l = xstrdup(label);
	if (l == NULL)
		return -1;

	p->lsm_label = l;
	return 0;
}

int local_desc_set_fds(ct_process_desc_t h, int *fds, int fdn)
{
	struct process_desc *p = prh2pr(h);
	int *t = NULL;

	if (fds) {
		/* reserve space for wait_pipe */
		t = xmalloc(sizeof(int) * (fdn + 1));
		if (t == NULL)
			return -1;

		memcpy(t, fds, sizeof(int) * fdn);
	}

	xfree(p->fds);
	p->fds = t;
	p->fdn = fdn;

	return 0;
}

static const struct process_desc_ops local_process_ops = {
	.copy		= local_desc_copy,
	.destroy	= local_desc_destroy,
	.setuid		= local_desc_setuid,
	.setgid		= local_desc_setgid,
	.setgroups	= local_desc_setgroups,
	.set_caps	= local_desc_set_caps,
	.set_pdeathsig	= local_desc_set_pdeathsig,
	.set_lsm_label	= local_desc_set_lsm_label,
	.set_fds	= local_desc_set_fds,
};

void local_process_init(struct process_desc *p)
{
	p->h.ops	= &local_process_ops;
	p->uid		= 0;
	p->gid		= 0;
	p->cap_caps	= 0;
	p->cap_bset	= 0;
	p->pdeathsig	= 0;
	p->groups	= NULL;
	p->ngroups	= 0;
	p->lsm_label	= NULL;
	p->fds		= NULL;
	p->fdn		= 0;
}
