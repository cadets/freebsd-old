#ifndef __DT_BENCHMARK_H_
#define __DT_BENCHMARK_H_

#include <time.h>

#define DT_BENCHKIND_TIME 0x1

#ifdef __DTRACE_RUN_BENCHMARKS__

typedef struct dt_benchmark {
	char   *dtbe_name;
	char   *dtbe_desc;
	int    dtbe_kind;
	int    dtbe_running;
	size_t dtbe_nsnapshots;
	size_t dtbe_cursnapshot;

	union {
		struct {
			clock_t __start;
			clock_t __end;
			clock_t __snapshots[];
		} time;
	} u;
#define dtbe_starttime	u.time.__start
#define dtbe_endtime	u.time.__end
#define dtbe_timesnaps  u.time.__snapshots
} dt_benchmark_t;

void           *dt_merge_new(void);
void           dt_merge_cleanup(void *);
dt_benchmark_t *dt_bench_new(const char *, const char *, int, size_t);
void           dt_bench_free(dt_benchmark_t *);
int            dt_bench_start(dt_benchmark_t *);
int            dt_bench_stop(dt_benchmark_t *);
void           dt_bench_snapshot(dt_benchmark_t *);
int            dt_bench_dump(dt_benchmark_t **, size_t, const char *, char *);

static __inline void
__dt_bench_snapshot_time(dt_benchmark_t *__b)
{
#ifdef __DTRACE_SAFE_BENCH__
	assert(__b->dtbe_kind == DT_BENCHKIND_TIME);
	assert(__b->dtbe_running == 1);
	assert(__b->dtbe_cursnapshot < __b->dtbe_nsnapshots);
#endif // __DTRACE_SAFE_BENCH__

	__b->dtbe_timesnaps[__b->dtbe_cursnapshot++] = clock();
}

static __inline void
__dt_bench_stop_time(dt_benchmark_t *__b)
{
#ifdef __DTRACE_SAFE_BENCH__
	assert(__b->dtbe_kind == DT_BENCHKIND_TIME);
	assert(__b->dtbe_running == 1);
	assert(__b->dtbe_cursnapshot <= __b->dtbe_nsnapshots);
#endif // __DTRACE_SAFE_BENCH__

	__b->dtbe_endtime = clock();
}

#else

/*
 * Ugly, but ensures that nobody accesses random things.
 */
typedef void dt_benchmark_t;

#define  dt_merge_new(...) (1) /* XXX: Oof. */
#define  dt_merge_cleanup(...)
#define  dt_bench_new(...) (1) /* XXX: Oof. */
#define  dt_bench_free(...)
#define  dt_bench_start(...)
#define  dt_bench_stop(...)
#define  dt_bench_snapshot(...)
#define  dt_bench_dump(...)
#define  __dt_bench_snapshot_time(...)
#define  __dt_bench_stop_time(...)

#endif // __DTRACE_RUN_BENCHMARKS__

#endif // __DT_BENCHMARK_H_
