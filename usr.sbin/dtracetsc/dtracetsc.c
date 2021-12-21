#include <sys/types.h>
#include <sys/param.h>
#include <sys/dtrace.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

static const char *program_name;

enum {
	CSV_OUTPUT = 1000,
	HELP_PAGE,
};


static struct option longopts[] = {
	{ "csv"          ,     no_argument      ,    NULL,      CSV_OUTPUT    },
	{ "help"         ,     no_argument      ,    NULL,      HELP_PAGE     },
	{ NULL           ,     0                ,    NULL,      0             }
};

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s\n"
	    "\t--csv   Show output in csv format. The output format order is:\n"
	    "\t        (stack_time, immstack_time, cache_hit_rate).\n"
	    "\t--help  display this help page.\n",
	    program_name);
}

int
main(int argc, char **argv)
{
	dtrace_tscdata_t stackval;
	dtrace_tscdata_t immstackval;
	double stack, immstack;
	size_t len;
	int csv = 0;
	int ch;

	program_name = argv[0];

	while ((ch = getopt_long(argc, (char *const *)argv,
	    "", longopts, NULL)) != -1) {
		switch (ch) {
		case 0:
			break;

		case HELP_PAGE:
			print_help();
			return (EX_OK);

		case CSV_OUTPUT:
			csv = 1;
			break;

		default:
			print_help();
			return (EXIT_FAILURE);
		}
	}

	len = sizeof(stackval);
	if (sysctlbyname("kern.dtrace.stacktsc", &stackval, &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
		return (EX_OSERR);
	}

	if (sysctlbyname(
		"kern.dtrace.immstacktsc", &immstackval, &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
		return (EX_OSERR);
	}

	stack = ((double)stackval.sum) / ((double)stackval.cnt) / 1000000;
	immstack = ((double)immstackval.sum) / ((double)immstackval.cnt) /
	    1000000;

	if (csv != 0) {
		printf("%lf, %lf, %lf\n", stack, immstack, 0.0f);
	} else {
		printf("Stack: %lf\nImmstack: %lf\n", stack, immstack);
	}

	return (EXIT_SUCCESS);
}