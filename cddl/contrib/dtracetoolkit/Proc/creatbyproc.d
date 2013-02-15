#!/usr/sbin/dtrace -s
/*
 * creatbyproc.d - file creat()s by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

syscall::creat*:entry { printf("%s %s", execname, copyinstr(arg0)); }
