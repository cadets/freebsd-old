#!/usr/sbin/dtrace -s
/*
 * syscallbysysc.d - report on syscalls by syscall. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

syscall:::entry { @num[probefunc] = count(); }
