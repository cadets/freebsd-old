#!/usr/sbin/dtrace -s
/*
 * lockbyproc.d - lock time by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

lockstat:::adaptive-block { @time[execname] = sum(arg1); }
