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

#ifndef __DT_BENCHMARK_H_
#define __DT_BENCHMARK_H_

#include <sys/types.h>

#include <assert.h>
#include <time.h>
#include <stdlib.h>

#define DT_BENCHKIND_TIME 0x1

#define DT_BENCH_TOPLEVEL -1

#ifdef __DTRACE_RUN_BENCHMARKS__


typedef char   *dt_snapshot_name_t;
typedef size_t dt_snapshot_hdl_t;

typedef struct dt_bench_snapshot {
	struct timespec __time;
	uint64_t        __data;
} dt_bench_snapshot_t;

typedef struct dt_benchmark {
	char               *dtbe_name;
	char               *dtbe_desc;
	int                dtbe_kind;
	int                dtbe_running;
	size_t             dtbe_nsnapshots;
	size_t             dtbe_cursnapshot;
	dt_snapshot_name_t *dtbe_snapnames;
	uint64_t           dtbe_data;

	union {
		struct {
			struct timespec     __start;
			struct timespec     __end;
			dt_bench_snapshot_t __snapshots[];
		} time;
	} u;
#define dtbe_starttime	u.time.__start
#define dtbe_endtime	u.time.__end
#define dtbe_timesnaps  u.time.__snapshots
} dt_benchmark_t;

void           *dt_merge_new(void);
void           dt_merge_cleanup(void *);
void           *dt_bench_merge(void *, dt_benchmark_t *);
dt_benchmark_t **dt_merge_get(void *);
size_t         dt_merge_size(void *);
dt_benchmark_t *dt_bench_new(const char *, const char *, int, size_t);
void           dt_bench_free(dt_benchmark_t *);
int            dt_bench_start(dt_benchmark_t *);
int            dt_bench_stop(dt_benchmark_t *);
void           dt_bench_snapshot(dt_benchmark_t *);
int            dt_bench_dump(dt_benchmark_t **, size_t, const char *, char *);
void           dt_bench_hdl_attach(dt_benchmark_t *, dt_snapshot_hdl_t, uint64_t);
void           dt_bench_setinfo(dt_benchmark_t *, const char *, const char *, int);
void           dt_snapshot_setinfo(dt_benchmark_t *, dt_snapshot_hdl_t, const char *);
char           *dt_bench_file(const char *);

static __inline dt_snapshot_hdl_t
__dt_bench_snapshot_time(dt_benchmark_t *__b)
{
#ifdef __DTRACE_SAFE_BENCH__
	assert(__b->dtbe_kind == DT_BENCHKIND_TIME);
	assert(__b->dtbe_running == 1);
	assert(__b->dtbe_cursnapshot < __b->dtbe_nsnapshots);
	assert(clock_gettime(CLOCK_MONOTONIC,
	    &__b->dtbe_timesnaps[__b->dtbe_cursnapshot++].__time) == 0);
#else
	clock_gettime(CLOCK_MONOTONIC,
	    &__b->dtbe_timesnaps[__b->dtbe_cursnapshot].__time);
	return (__b->dtbe_cursnapshot++);
#endif // __DTRACE_SAFE_BENCH__
}

static __inline void
__dt_bench_stop_time(dt_benchmark_t *__b)
{
#ifdef __DTRACE_SAFE_BENCH__
	assert(__b->dtbe_kind == DT_BENCHKIND_TIME);
	assert(__b->dtbe_running == 1);
	assert(__b->dtbe_cursnapshot <= __b->dtbe_nsnapshots);
	assert(clock_gettime(CLOCK_MONOTONIC, &__b->dtbe_endtime) == 0);
#else
	clock_gettime(CLOCK_MONOTONIC, &__b->dtbe_endtime);
#endif // __DTRACE_SAFE_BENCH__
}

static __inline dt_benchmark_t *
__dt_bench_new_time(size_t n_snapshots)
{
	dt_benchmark_t *__b;

	__b = malloc(sizeof(dt_benchmark_t) +
	    sizeof(dt_bench_snapshot_t) * n_snapshots);
	if (__b == NULL)
		abort();

	memset(__b, 0, sizeof(dt_benchmark_t) +
	    sizeof(dt_bench_snapshot_t) * n_snapshots);
	__b->dtbe_nsnapshots = n_snapshots;
	return (__b);
}

#else

/*
 * Ugly, but ensures that nobody accesses random things.
 */
typedef void   dt_benchmark_t;
typedef char   *dt_snapshot_name_t;
typedef size_t dt_snapshot_hdl_t;

#define  dt_merge_new(...) ((void *)1) /* XXX: Oof. */
#define  dt_merge_cleanup(...)
#define  dt_bench_merge(...) ((void *)1)
#define  dt_bench_new(...) ((void *)1) /* XXX: Oof. */
#define  dt_bench_free(...)
#define  dt_bench_start(...)
#define  dt_bench_stop(...)
#define  dt_bench_snapshot(...)
#define  dt_bench_dump(...)
#define  dt_bench_hdl_attach(...)
#define  dt_bench_setinfo(...)
#define  dt_snapshot_setinfo(...)
#define  dt_bench_file(...) ((void *)1) /* XXX: Oof. */
#define  __dt_bench_snapshot_time(...) (0)
#define  __dt_bench_stop_time(...)
#define  __dt_bench_new_time(...) ((void *)1) /* XXX: Oof. */

#endif // __DTRACE_RUN_BENCHMARKS__

#endif // __DT_BENCHMARK_H_
