#!/usr/sbin/dtrace -s
/*
 * filebyproc.d - snoop files opened by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

syscall::open*:entry { printf("%s %s", execname, copyinstr(arg0)); }
