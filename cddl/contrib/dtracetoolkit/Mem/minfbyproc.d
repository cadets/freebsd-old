#!/usr/sbin/dtrace -s
/*
 * minfbyproc.d - minor faults by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

vminfo:::as_fault { @mem[execname] = sum(arg0); }
