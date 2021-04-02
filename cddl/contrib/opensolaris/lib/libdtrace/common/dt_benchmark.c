#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <libxo/xo.h>

#include <sys/dtrace.h>
#include <dtrace.h>

#include "dt_benchmark.h"

typedef struct dt_benchmark {
	char *dtbe_name;
	char *dtbe_desc;
	int dtbe_kind;
	int dtbe_running;
	union {
		struct {
			clock_t start;
			clock_t end;
		} time;
	} u;
#define dtbe_starttime	u.time.start
#define dtbe_endtime	u.time.end
} dt_benchmark_t;

dt_benchmark_t *
dt_bench_new(const char *name, const char *desc)
{
	dt_benchmark_t *new;

	new = malloc(sizeof(dt_benchmark_t));
	memset(new, 0, sizeof(dt_benchmark_t));

	new->dtbe_name = strdup(name);
	new->dtbe_desc = strdup(desc);

	return (new);
}

void
dt_bench_free(dt_benchmark_t *bench)
{

	free(bench->dtbe_name);
	free(bench->dtbe_desc);
	free(bench);
}

int
dt_bench_start(dt_benchmark_t *bench, int kind)
{
	if (bench->dtbe_running != 0)
		return (1);

	bench->dtbe_running = 1;
	bench->dtbe_kind = kind;

	switch (kind) {
	case DT_BENCHKIND_TIME:
		bench->dtbe_starttime = clock();
	}

	return (0);
}

int
dt_bench_stop(dt_benchmark_t *bench)
{
	if (bench->dtbe_running == 0)
		return (1);

	switch (bench->dtbe_kind) {
	case DT_BENCHKIND_TIME:
		bench->dtbe_endtime = clock();
	}

	return (0);
}

int
dt_bench_update(dt_benchmark_t *bench)
{
	if (bench->dtbe_running == 0)
		return (1);

	switch (bench->dtbe_kind) {
	default:
		break;
	}

	return (0);
}

int
dt_bench_dump(dt_benchmark_t *bench, const char *fullpath)
{
	double timespent;
	FILE *fp;
	xo_handle_t *hdl;

	fp = fopen(fullpath, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Failed to create file path %s: %s\n",
				fullpath, strerror(errno));
		return (1);
	}

	hdl = xo_create_to_file(fp, XO_STYLE_JSON, XOF_FLUSH);
	if (hdl == NULL) {
		fprintf(stderr, "Failed to create a libxo handle\n");
		return (1);
	}

	switch (bench->dtbe_kind) {
	case DT_BENCHKIND_TIME:
		timespent = (double)(bench->dtbe_starttime -
				bench->dtbe_endtime) / CLOCKS_PER_SEC;
		xo_emit_h(hdl, " {:name/%s} {:desc/%s} {:time/%lf}",
				bench->dtbe_name, bench->dtbe_desc, timespent);
		break;
	default:
		break;
	}

	xo_destroy(hdl);
	fclose(fp);

	return (0);
}
