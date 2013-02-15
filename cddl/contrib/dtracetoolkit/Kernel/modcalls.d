#!/usr/sbin/dtrace -s
/*
 * modcalls.d - kernel function calls by module. DTrace OneLiner.
 *
 * This is a DTrace OneLiner from the DTraceToolkit.
 *
 * $Id$
 */

fbt:::entry { @calls[probemod] = count(); }
