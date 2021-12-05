#include <sys/types.h>
#include <sys/param.h>
#include <sys/dtrace.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

int
main(void)
{
        dtrace_tscdata_t stackval;
        dtrace_tscdata_t immstackval;
        double stack, immstack;
        size_t len;

        len = sizeof(stackval);
        if (sysctlbyname("kern.dtrace.stacktsc", &stackval,
            &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
                return (EX_OSERR);
	}

        if (sysctlbyname("kern.dtrace.immstacktsc", &immstackval,
            &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
		return (EX_OSERR);
	}

        stack = ((double)stackval.sum) / ((double)stackval.cnt) / 1000000;
        immstack = ((double)immstackval.sum) / ((double)immstackval.cnt) / 1000000;

        printf("Stack: %lf\nImmstack: %lf\n", stack, immstack);

        return (EXIT_SUCCESS);
}