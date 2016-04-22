#include <sys/types.h>

#include "dtrace_xoroshiro128_plus.h"

static __inline uint64_t
rotl(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

/*
 * This is the jump function for the generator. It is equivalent to 2^64 calls
 * to next(); it can be used to generate 2^64 non-overlapping subsequences for
 * parallel computations.
 */
void
dtrace_xoroshiro128_plus_jump(uint64_t * const state,
    uint64_t * const jump_state)
{
	static const uint64_t JUMP[] = { 0xbeac0467eba5facb,
		0xd86b048b86aa9922 };

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	for(int i = 0; i < sizeof JUMP / sizeof *JUMP; i++)
		for(int b = 0; b < 64; b++) {
			if (JUMP[i] & 1ULL << b) {
				s0 ^= state[0];
				s1 ^= state[1];
			}
			dtrace_xoroshiro128_plus_next(state);
		}

	jump_state[0] = s0;
	jump_state[1] = s1;
}

/*
 * xoroshiro128+ - XOR/rotate/shift/rotate
 */
uint64_t
dtrace_xoroshiro128_plus_next(uint64_t * const state)
{
	const uint64_t s0 = state[0];
	uint64_t s1 = state[1];;
	uint64_t result;
	result = s0 + s1;

	s1 ^= s0;
	state[0] = rotl(s0, 55) ^ s1 ^ (s1 << 14);
	state[1] = rotl(s1, 36);

	return result;
}
	
