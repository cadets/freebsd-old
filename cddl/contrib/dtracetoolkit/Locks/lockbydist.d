#!/usr/sbin/dtrace -s
/*
 * lockbydist.d - lock distrib. by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

lockstat:::adaptive-block { @time[execname] = quantize(arg1); }
