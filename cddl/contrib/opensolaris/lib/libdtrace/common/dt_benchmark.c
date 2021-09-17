#include <sys/dtrace.h>

#include <dt_impl.h>
#include <dtrace.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dt_benchmark.h"

#ifdef __DTRACE_RUN_BENCHMARKS__

#define INITIAL_NBENCH 4096

typedef struct {
	dt_benchmark_t **benchmarks;
	size_t         size;
	size_t         current;
} dt_bmerge_t;

void *
dt_merge_new(void)
{
	dt_bmerge_t *m;

	m = malloc(sizeof(dt_bmerge_t));
	if (m == NULL)
		return (NULL);

	memset(m, 0, sizeof(dt_bmerge_t));
	return (m);
}

void
dt_merge_cleanup(void *_m)
{
	dt_bmerge_t *m = _m;

	free(m->benchmarks);
	free(m);
}

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

void *
dt_bench_merge(void *_m, dt_benchmark_t *b)
{
	dt_bmerge_t *m = _m;
	size_t cursize = m->size;
	dt_benchmark_t **bs = m->benchmarks;

	if (bs == NULL) {
		bs = malloc(sizeof(dt_benchmark_t *) * INITIAL_NBENCH);
		if (bs == NULL)
			return (NULL);

		m->size = INITIAL_NBENCH;
	}

	if (m->current >= cursize) {
		cursize <<= 1;
		bs = malloc(sizeof(dt_benchmark_t *) * cursize);
		if (bs == NULL)
			return (NULL);

		memset(bs, 0, sizeof(dt_benchmark_t *) * cursize);
		memcpy(bs, m->benchmarks, sizeof(dt_benchmark_t *) * m->size);

		free(m->benchmarks);
		m->benchmarks = bs;
		m->size = cursize;
	}

	m->benchmarks[m->current++] = b;
	return (m);
}

int
dt_bench_dump(dt_benchmark_t **benchmarks, size_t n_benches,
    const char *fullpath, char *script)
{
	double timespent;
	FILE *fp;
	xo_handle_t *hdl;
	dt_benchmark_t *bench;
	size_t i;

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
	xo_open_list_h(hdl, "benchmarks");
	for (i = 0; i < n_benches; i++) {
		bench = benchmarks[i];
		if (bench == NULL)
			continue;

		xo_open_instance_h(hdl, "benchmarks");
		xo_open_container_h(hdl, "benchmark");

		switch (bench->dtbe_kind) {
		case DT_BENCHKIND_TIME:
			timespent = ((double)(bench->dtbe_endtime -
			    bench->dtbe_starttime)) / CLOCKS_PER_SEC;
			xo_emit_h(hdl,
			    " {:kind/time} {:name/%s} {:desc/%s} {:time/%lf} ",
			    bench->dtbe_name, bench->dtbe_desc,
			    timespent);
			break;

		default:
			break;
		}
		xo_close_container_h(hdl, "benchmark");
		xo_close_instance_h(hdl, "benchmarks");
	}
	xo_close_list_h(hdl, "benchmarks");
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

#endif
