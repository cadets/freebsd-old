/*- 
 * Copyright (c) 2021 Domagoj Stolfa <ds815@gmx.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

dt_benchmark_t **
dt_merge_get(void *_m)
{
	dt_bmerge_t *m = _m;

	return (m->benchmarks);
}

size_t
dt_merge_size(void *_m)
{
	dt_bmerge_t *m = _m;

	return (m->size);
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
		new = __dt_bench_new_time(n_snapshots);
		break;

	default:
		fprintf(stderr, "Unknown benchmark kind: %d\n", kind);
		return (NULL);
	}

	new->dtbe_name = strdup(name);
	if (new->dtbe_name == NULL) {
		free(new);
		return (NULL);
	}
	
	new->dtbe_desc = strdup(desc);
	if (new->dtbe_desc == NULL) {
		free(new->dtbe_name);
		free(new);
		return (NULL);
	}

	new->dtbe_kind = kind;
	new->dtbe_nsnapshots = n_snapshots;
	new->dtbe_snapnames = malloc(n_snapshots * sizeof(dt_snapshot_name_t));
	if (new->dtbe_snapnames == NULL) {
		free(new->dtbe_name);
		free(new);
		return (NULL);
	}
	memset(new->dtbe_snapnames, 0, sizeof(dt_snapshot_name_t) * n_snapshots);

	return (new);
}

void
dt_bench_free(dt_benchmark_t *bench)
{
	size_t i;

	if (bench->dtbe_name)
		free(bench->dtbe_name);

	if (bench->dtbe_desc)
		free(bench->dtbe_desc);

	if (bench->dtbe_snapnames) {
		for (i = 0; i < bench->dtbe_nsnapshots; i++)
			if (bench->dtbe_snapnames[i])
				free(bench->dtbe_snapnames[i]);

		free(bench->dtbe_snapnames);
	}

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
		return (clock_gettime(CLOCK_MONOTONIC, &bench->dtbe_starttime));

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

	if (m->current >= cursize) {
		if (cursize == 0)
			cursize = INITIAL_NBENCH;
		else
			cursize <<= 1;

		bs = malloc(sizeof(dt_benchmark_t *) * cursize);
		if (bs == NULL)
			return (NULL);

		memset(bs, 0, sizeof(dt_benchmark_t *) * cursize);
		if (m->benchmarks) {
			assert(m->size > 0);
			memcpy(bs, m->benchmarks,
			    sizeof(dt_benchmark_t *) * m->size);
			free(m->benchmarks);
		}

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
	size_t i, j;

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

		switch (bench->dtbe_kind) {
		case DT_BENCHKIND_TIME:
			xo_emit_h(hdl,
			    " {:kind/time} {:name/%s} {:desc/%s} "
			    "{:start time sec/%jd} {:start time nsec/%jd} "
			    "{:end time sec/%jd} {:end time nsec/%jd} ",
			    bench->dtbe_name, bench->dtbe_desc,
			    bench->dtbe_starttime.tv_sec,
			    bench->dtbe_starttime.tv_nsec,
			    bench->dtbe_endtime.tv_sec,
			    bench->dtbe_endtime.tv_nsec);

			xo_open_list_h(hdl, "snapshots");
			for (j = 0; j < bench->dtbe_cursnapshot; j++) {
				struct timespec *snap;
				snap = &bench->dtbe_timesnaps[j].__time;

				xo_open_instance_h(hdl, "snapshots");
				xo_emit_h(hdl, " {:name/%s} "
				"{:time sec/%jd} {:time nsec/%jd} ",
				    bench->dtbe_snapnames == NULL ? "(null)" :
				    bench->dtbe_snapnames[j] ?
				    bench->dtbe_snapnames[j] : "(null)",
				    snap->tv_sec, snap->tv_nsec);
				xo_close_instance_h(hdl, "snapshots");
			}
			xo_close_list_h(hdl, "snapshots");

			break;

		default:
			break;
		}

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

void
dt_bench_hdl_attach(dt_benchmark_t *b, dt_snapshot_hdl_t hdl, uint64_t data)
{

	if (hdl == DT_BENCH_TOPLEVEL)
		b->dtbe_data = data;
	else
		b->dtbe_timesnaps[hdl].__data = data;
}

void
dt_snapshot_setinfo(dt_benchmark_t *b, dt_snapshot_hdl_t snap, const char *name)
{

	b->dtbe_snapnames[snap] = strdup(name);
	if (b->dtbe_snapnames[snap] == NULL)
		abort();
}

void
dt_bench_setinfo(dt_benchmark_t *b, const char *name,
    const char *description, int kind)
{
	if (b == NULL)
		return;
	
	b->dtbe_name = strdup(name);
	if (b->dtbe_name == NULL)
		abort();

	b->dtbe_desc = strdup(description);
	if (b->dtbe_desc == NULL)
		abort();

	b->dtbe_snapnames = malloc(sizeof(dt_snapshot_name_t) *
	    b->dtbe_nsnapshots);
	if (b->dtbe_snapnames == NULL)
		abort();

	b->dtbe_kind = kind;
}

char *
dt_bench_file(const char *p, char *rp)
{

	return (realpath(p, rp));
}

#endif // __DTRACE_RUN_BENCHMARKS__
