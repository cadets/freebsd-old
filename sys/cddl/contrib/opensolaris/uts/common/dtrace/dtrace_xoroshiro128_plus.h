
#ifndef _DTRACE_XOROSHIRO128_PLUS_H
#define _DTRACE_XOROSHIRO128_PLUS_H
#endif

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void dtrace_xoroshiro128_plus_jump(uint64_t * const, uint64_t * const);
extern uint64_t dtrace_xoroshiro128_plus_next(uint64_t * const);

#ifdef __cplusplus
}
#endif

