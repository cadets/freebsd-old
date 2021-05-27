/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2020 Domagoj Stolfa. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each list element contains an embedded dt_list_t (previous and next
 * pointers), which is typically the first member of the element struct.
 * An additional dt_list_t is used to store the head (dl_next) and tail
 * (dl_prev) pointers.  The current head and tail list elements have their
 * previous and next pointers set to NULL, respectively.
 */

#include <unistd.h>
#include <assert.h>
#include <string.h>

#include <dt_list.h>

void
dt_list_append(dt_list_t *dlp, void *new)
{
	dt_list_t *p = dlp->dl_prev;	/* p = tail list element */
	dt_list_t *q = new;		/* q = new list element */

	dlp->dl_prev = q;
	q->dl_prev = p;
	q->dl_next = NULL;

	if (p != NULL) {
		assert(p->dl_next == NULL);
		p->dl_next = q;
	} else {
		assert(dlp->dl_next == NULL);
		dlp->dl_next = q;
	}
}

void
dt_list_prepend(dt_list_t *dlp, void *new)
{
	dt_list_t *p = new;		/* p = new list element */
	dt_list_t *q = dlp->dl_next;	/* q = head list element */

	dlp->dl_next = p;
	p->dl_prev = NULL;
	p->dl_next = q;

	if (q != NULL) {
		assert(q->dl_prev == NULL);
		q->dl_prev = p;
	} else {
		assert(dlp->dl_prev == NULL);
		dlp->dl_prev = p;
	}
}

void
dt_list_insert(dt_list_t *dlp, void *after_me, void *new)
{
	dt_list_t *p = after_me;
	dt_list_t *q = new;

	if (p == NULL || p->dl_next == NULL) {
		dt_list_append(dlp, new);
		return;
	}

	q->dl_next = p->dl_next;
	q->dl_prev = p;
	p->dl_next = q;
	q->dl_next->dl_prev = q;
}

void
dt_list_delete(dt_list_t *dlp, void *existing)
{
	dt_list_t *p = existing;

	if (p->dl_prev != NULL)
		p->dl_prev->dl_next = p->dl_next;
	else
		dlp->dl_next = p->dl_next;

	if (p->dl_next != NULL)
		p->dl_next->dl_prev = p->dl_prev;
	else
		dlp->dl_prev = p->dl_prev;
}

void
dt_list_copy(dt_list_t *dst, dt_list_t *src, size_t entry_size)
{
	void *e, *new;

	e = new = NULL;

	for (e = dt_list_next(src); e; e = dt_list_next(e)) {
		new = malloc(entry_size);
		assert(new != NULL);

		memset(new, 0, sizeof(dt_list_t));
		/*
		 * We ensure all pointers are set to NULL, and then we copy
		 * the actual data at the right offset.
		 */
		memcpy(((char *)new) + sizeof(dt_list_t),
		    ((char *)e) + sizeof(dt_list_t),
		    entry_size - sizeof(dt_list_t));

		dt_list_append(dst, new);
	}
}

int
dt_list_equal(dt_list_t *fst, dt_list_t *snd, size_t entry_size)
{
	int empty;
	void *e1, *e2;

	empty = 1;
	e1 = e2 = NULL;

	for (e1 = dt_list_next(fst), e2 = dt_list_next(snd);
	     e1 && e2; e1 = dt_list_next(e1), e2 = dt_list_next(e2)) {
		if (memcmp((char *)e1 + sizeof(dt_list_t),
		    (char *)e2 + sizeof(dt_list_t),
		    entry_size - sizeof(dt_list_t)) != 0)
			return (0);

		empty = 0;
	}

	return (!empty);
}

void *
dt_in_list(dt_list_t *lst, void *find, size_t size)
{
	void *e;

	for (e = dt_list_next(lst); e; e = dt_list_next(e))
		if (memcmp((char *)e + sizeof(dt_list_t), find, size) == 0)
			return (e);

	return (NULL);
}

