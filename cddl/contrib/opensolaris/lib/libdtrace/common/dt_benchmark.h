#ifndef __DT_BENCHMARK_H_
#define __DT_BENCHMARK_H_

struct dt_benchmark;
typedef struct dt_benchmark dt_benchmark_t;

dt_benchmark_t *dt_bench_new(const char *, const char *);
void dt_bench_free(dt_benchmark_t *);

int dt_bench_start(dt_benchmark_t *, int);
int dt_bench_stop(dt_benchmark_t *);

int dt_bench_update(dt_benchmark_t *);

#endif // __DT_BENCHMARK_H_
