#include <sys/dtrace.h>

#include "dtvirt.h"

void
dtvirt_probe(int probeid)
{
	dtrace_probe(probeid, 0, 0, 0, 0, 0);
}
