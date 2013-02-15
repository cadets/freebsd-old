#!/usr/sbin/dtrace -s
/*
 * writedist.d - write distribution by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

sysinfo:::writech { @dist[execname] = quantize(arg0); }
