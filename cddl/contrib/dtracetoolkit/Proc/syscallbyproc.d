#!/usr/sbin/dtrace -s
/*
 * syscallbyproc.d - report on syscalls by process name . DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

syscall:::entry { @num[execname] = count(); }
