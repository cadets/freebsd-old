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
	BENCH_KIND = 1000,
	CSV_OUTPUT,
	HELP_PAGE,
};

enum {
	BENCH_KIND_NONE = 0,
	BENCH_KIND_XLATE,
	BENCH_KIND_STACK,
};


static struct option longopts[] = {
	{ "bench"        ,     required_argument,    NULL,      BENCH_KIND    },
	{ "csv"          ,     no_argument      ,    NULL,      CSV_OUTPUT    },
	{ "help"         ,     no_argument      ,    NULL,      HELP_PAGE     },
	{ NULL           ,     0                ,    NULL,      0             }
};

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s\n"
	    "\t--bench Specify which benchmark to check [stack|xlate].\n"
	    "\t--csv   Show output in csv format. The output format order is:\n"
	    "\t        (stack_time, immstack_time, cache_hit_rate).\n"
	    "\t--help  display this help page.\n",
	    program_name);
}

static dtrace_tscdata_t
get_data()
{
	dtrace_tscdata_t val;
	size_t len;

	len = sizeof(val);
	if (sysctlbyname("kern.dtrace.tscinfo", &val, &len, NULL, 0)) {
		fprintf(stderr, "Failed to get stack values via sysctl: %s.",
		    strerror(errno));
		exit(EX_OSERR);
	}

	return (val);
}

static void
do_stack(int csv)
{
	double stack, immstack, hit_rate, drop_rate;
	uint64_t hits, misses, total, drops, records;
	dtrace_tscdata_t val;

	val = get_data();

	stack = ((double)val.stack_sum) / ((double)val.stack_cnt);
	immstack = ((double)val.immstack_sum) / ((double)val.immstack_cnt);

	hits = val.cache_hits;
	misses = val.cache_misses;

	total = hits + misses;
	hit_rate = ((double)hits) / ((double)total);

	records = val.records;
	drops = val.drops;
	drop_rate = (double)drops / ((double)(records + drops));

	if (csv != 0) {
		printf("%lf,%lf,%lf,%lf", stack, immstack, hit_rate, drop_rate);
	} else {
		printf("Stack: %lf\n"
		       "Immstack: %lf\n"
		       "Hit rate: %lf\n"
		       "Drop rate: %lf\n",
		    stack, immstack, hit_rate, drop_rate);
	}
}

static void
do_xlate(int csv)
{
	dtrace_tscdata_t val;
	uint64_t xlate_times, xlates;
	double avg_xlate_time;

	val = get_data();
	xlate_times = val.xlate_times;
	xlates = val.xlates;

	avg_xlate_time = ((double)xlate_times) / ((double)xlates);

	if (csv != 0) {
		printf("%lf", avg_xlate_time);
	} else {
		printf("Average Translation Time: %lf\n", avg_xlate_time);
	}
}

int
main(int argc, char **argv)
{
	int csv = 0, ch, bench_kind;

	bench_kind = BENCH_KIND_NONE;
	program_name = argv[0];

	while ((ch = getopt_long(argc, (char *const *)argv,
	    "", longopts, NULL)) != -1) {
		switch (ch) {
		case 0:
			break;

		case BENCH_KIND:
			if (strcmp(optarg, "stack") == 0)
				bench_kind = BENCH_KIND_STACK;
			else if (strcmp(optarg, "xlate") == 0)
				bench_kind = BENCH_KIND_XLATE;
			else {
				print_help();
				return (EXIT_FAILURE);
			}
			break;

		case CSV_OUTPUT:
			csv = 1;
			break;

		case HELP_PAGE:
			print_help();
			return (EX_OK);

		default:
			print_help();
			return (EXIT_FAILURE);
		}
	}

	switch (bench_kind) {
	case BENCH_KIND_STACK:
		do_stack(csv);
		break;

	case BENCH_KIND_XLATE:
		do_xlate(csv);
		break;

	default:
		print_help();
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}