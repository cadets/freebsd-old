#include <sys/dtrace.h>

#include <dt_impl.h>
#include <dtrace.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dt_benchmark.h"

dt_benchmark_t *
dt_bench_new(const char *name, const char *desc, int kind, size_t n_snapshots)
{
	dt_benchmark_t *new;

	switch (kind) {
	case DT_BENCHKIND_TIME:
		new = malloc(sizeof(dt_benchmark_t) +
		    sizeof(clock_t) * n_snapshots);
		if (new == NULL)
			return (NULL);
		break;

	default:
		fprintf(stderr, "Unknown benchmark kind: %d\n", kind);
		return (NULL);
	}

	memset(new, 0, sizeof(dt_benchmark_t));

	new->dtbe_name = strdup(name);
	if (new->dtbe_name == NULL) {
		free(new);
		return (NULL);
	}
	
	new->dtbe_desc = strdup(desc);
	if (new->dtbe_desc = NULL) {
		free(new->dtbe_name);
		free(new);
		return (NULL);
	}

	new->dtbe_kind = kind;
	new->dtbe_nsnapshots = n_snapshots;

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
dt_bench_start(dt_benchmark_t *bench)
{
	if (bench->dtbe_running != 0)
		return (1);

	bench->dtbe_running = 1;

	switch (bench->dtbe_kind) {
	case DT_BENCHKIND_TIME:
		bench->dtbe_starttime = clock();
		return (0);

	default:
		fprintf(stderr, "Unknown benchmark kind: %d\n",
		    bench->dtbe_kind);
		return (-1);
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
		__dt_bench_stop_time(bench);
		return (0);

	default:
		fprintf(stderr, "Unknown benchmark kind: %d\n",
		    bench->dtbe_kind);
		return (-1);
	}

	return (0);
}

/*
 * This is the subroutine that should be used for snapshots. However, it does
 * some error checking and has a switch statement, which may be undesirable.
 * Therefore, the header provides inline snapshot subroutines that don't do any
 * of that.
 */
void
dt_bench_snapshot(dt_benchmark_t *bench)
{
	switch (bench->dtbe_kind) {
	case DT_BENCHKIND_TIME:
		__dt_bench_snapshot_time(bench);
		break;

	default:
		break;
	}
}

int
dt_bench_dump(dt_benchmark_t *bench, const char *fullpath, char *script)
{
	double timespent;
	FILE *fp;
	xo_handle_t *hdl;

	fp = fopen(fullpath, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Failed to create file path %s: %s\n", fullpath,
		    strerror(errno));
		return (1);
	}

	hdl = xo_create_to_file(fp, XO_STYLE_JSON, XOF_FLUSH);
	if (hdl == NULL) {
		fprintf(stderr, "Failed to create a libxo handle\n");
		return (1);
	}

	xo_open_container_h(hdl, "dtrace");
	xo_open_container_h(hdl, "benchmark");
	switch (bench->dtbe_kind) {
	case DT_BENCHKIND_TIME:
		timespent = ((double)(bench->dtbe_endtime -
		    bench->dtbe_starttime)) / CLOCKS_PER_SEC;
		xo_emit_h(hdl, " {:name/%s} {:desc/%s} {:time/%lf} ",
		    bench->dtbe_name, bench->dtbe_desc, timespent);
		break;
	default:
		break;
	}
	xo_close_container_h(hdl, "benchmark");
	/*
	 * TODO: Put options into the file.
	 */
	xo_open_list_h(hdl, "options");
	xo_close_list_h(hdl, "options");

	xo_emit_h(hdl, " {:script/%s} ", script);
	xo_close_container_h(hdl, "dtrace");
	xo_finish_h(hdl);

	xo_destroy(hdl);
	fclose(fp);

	return (0);
}
