
#ifndef _DTRACE_ARC4_H
#define _DTRACE_ARC4_H

#ifdef _cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define DTRACE_ARC4_KEYBYTES		256
#define	DTRACE_ARC4_RESEED_BYTES	65536
#define	DTRACE_ARC4_RESEED_NANOSECONDS	300000000000

typedef struct dtrace_arc4_state dtrace_arc4_state_t;

struct dtrace_arc4_state {
	int		numruns;
	uint8_t		i;
	uint8_t		j;
	uint8_t		sbox[256];
	uint64_t	reseed;
};

extern void	dtrace_arc4_init(dtrace_arc4_state_t *, uint8_t *);
extern uint32_t dtrace_arc4random(dtrace_arc4_state_t *);

#ifdef _cplusplus
}
#endif

#endif

