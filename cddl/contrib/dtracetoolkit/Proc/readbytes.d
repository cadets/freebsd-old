#!/usr/sbin/dtrace -s
/*
 * readbytes.d - read bytes by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

sysinfo:::readch { @bytes[execname] = sum(arg0); }
