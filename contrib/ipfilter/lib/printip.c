/*	$FreeBSD: head/contrib/ipfilter/lib/printip.c 170268 2007-06-04 02:54:36Z darrenr $	*/

/*
 * Copyright (C) 2002-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void	printip(addr)
u_32_t	*addr;
{
	struct in_addr ipa;

	ipa.s_addr = *addr;
	if (ntohl(ipa.s_addr) < 256)
		printf("%lu", (u_long)ntohl(ipa.s_addr));
	else
		printf("%s", inet_ntoa(ipa));
}
