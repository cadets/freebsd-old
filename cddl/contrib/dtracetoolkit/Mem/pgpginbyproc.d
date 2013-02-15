#!/usr/sbin/dtrace -s
/*
 * pgpginbyproc.d - pages paged in by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

vminfo:::pgpgin { @pg[execname] = sum(arg0); }
