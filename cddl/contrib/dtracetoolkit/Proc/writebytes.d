#!/usr/sbin/dtrace -s
/*
 * writebytes.d - write bytes by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

sysinfo:::writech { @bytes[execname] = sum(arg0); }
