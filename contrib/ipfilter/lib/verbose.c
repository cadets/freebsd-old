/*	$FreeBSD: head/contrib/ipfilter/lib/verbose.c 170268 2007-06-04 02:54:36Z darrenr $	*/

/*
 * Copyright (C) 2000-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#if defined(__STDC__)
# include <stdarg.h>
#else
# include <varargs.h>
#endif
#include <stdio.h>

#include "ipt.h"
#include "opts.h"


#if defined(__STDC__)
void	verbose(char *fmt, ...)
#else
void	verbose(fmt, va_alist)
char	*fmt;
va_dcl
#endif
{
	va_list pvar;

	va_start(pvar, fmt);

	if (opts & OPT_VERBOSE)
		vprintf(fmt, pvar);
	va_end(pvar);
}
