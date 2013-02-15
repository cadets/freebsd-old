/*	$FreeBSD: head/contrib/ipfilter/lib/printsbuf.c 170268 2007-06-04 02:54:36Z darrenr $	*/

/*
 * Copyright (C) 2002-2004 by Darren Reed.
 * 
 * See the IPFILTER.LICENCE file for details on licencing.  
 *   
 * $Id$ 
 */     

#ifdef	IPFILTER_SCAN

#include <ctype.h>
#include <stdio.h>
#include "ipf.h"
#include "netinet/ip_scan.h"

void printsbuf(buf)
char *buf;
{
	u_char *s;
	int i;

	for (s = (u_char *)buf, i = ISC_TLEN; i; i--, s++) {
		if (ISPRINT(*s))
			putchar(*s);
		else
			printf("\\%o", *s);
	}
}

#endif
