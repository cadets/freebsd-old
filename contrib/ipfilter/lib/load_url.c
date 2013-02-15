/*
 * Copyright (C) 2006 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

alist_t *
load_url(char *url)
{
	alist_t *hosts = NULL;

	if (strncmp(url, "file://", 7) == 0) { 
		/*      
		 * file:///etc/passwd
		 *        ^------------s
		 */     
		hosts = load_file(url);

	} else if (*url == '/' || *url == '.') {
		hosts = load_file(url);

	} else if (strncmp(url, "http://", 7) == 0) {
		hosts = load_http(url);
	}

	return hosts;  
}
