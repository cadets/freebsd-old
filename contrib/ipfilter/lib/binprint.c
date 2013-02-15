/*	$FreeBSD: head/contrib/ipfilter/lib/binprint.c 170268 2007-06-04 02:54:36Z darrenr $	*/

/*
 * Copyright (C) 2000-2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void binprint(ptr, size)
void *ptr;
size_t size;
{
	u_char *s;
	int i, j;

	for (i = size, j = 0, s = (u_char *)ptr; i; i--, s++) {
		j++;
		printf("%02x ", *s);
		if (j == 16) {
			printf("\n");
			j = 0;
		}
	}
	putchar('\n');
	(void)fflush(stdout);
}
