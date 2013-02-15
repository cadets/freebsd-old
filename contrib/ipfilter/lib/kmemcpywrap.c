/*	$FreeBSD: head/contrib/ipfilter/lib/kmemcpywrap.c 170268 2007-06-04 02:54:36Z darrenr $	*/

/*
 * Copyright (C) 2002 by Darren Reed.
 * 
 * See the IPFILTER.LICENCE file for details on licencing.  
 *   
 * $Id$ 
 */     

#include "ipf.h"
#include "kmem.h"

int kmemcpywrap(from, to, size)
void *from, *to;
size_t size;
{
	int ret;

	ret = kmemcpy((caddr_t)to, (u_long)from, size);
	return ret;
}

