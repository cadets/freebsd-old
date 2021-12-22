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
	dtrace_tscdata_t val;
	double stack, immstack, hit_rate;
	size_t len;
	int csv = 0;
	int ch;
	uint64_t hits, misses, total;

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

	len = sizeof(val);
	if (sysctlbyname("kern.dtrace.stacktscinfo", &val, &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
		return (EX_OSERR);
	}

	stack = ((double)val.stack_sum) / ((double)val.stack_cnt) / 1000000;
	immstack = ((double)val.immstack_sum) / ((double)val.immstack_cnt) /
	    1000000;

	hits = val.cache_hits;
	misses = val.cache_misses;

	total = hits + misses;
	hit_rate = ((double)hits) / ((double)total);

	if (csv != 0) {
		printf("%lf, %lf, %lf\n", stack, immstack, hit_rate);
	} else {
		printf("Stack: %lf\nImmstack: %lf\nHit rate: %lf\n", stack,
		    immstack, hit_rate);
	}

	return (EXIT_SUCCESS);
}