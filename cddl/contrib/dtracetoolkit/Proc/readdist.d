#!/usr/sbin/dtrace -s
/*
 * readdist.d - read distribution by process name. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

sysinfo:::readch { @dist[execname] = quantize(arg0); }
