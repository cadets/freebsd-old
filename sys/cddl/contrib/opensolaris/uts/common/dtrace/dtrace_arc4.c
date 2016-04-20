/*-
 * THE BEER-WARE LICENSE
 *
 * <dan@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff.  If we meet some day, and you
 * think this stuff is worth it, you can buy me a beer in return.
 *
 * Dan Moschuk
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/dtrace_bsd.h>

#include "dtrace_arc4.h"

static __inline void
arc4_swap(uint8_t *a, uint8_t *b)
{
	u_int8_t c;

	c = *a;
	*a = *b;
	*b = c;
}	

/*
 * Stir our S-box.
 */
static void
arc4_randomstir(dtrace_arc4_state_t * this, uint8_t * key)
{
	int n;
	
	for (n = 0; n < 256; n++) {
		this->j = (this->j + this->sbox[n] + key[n]) % 256;
		arc4_swap(&this->sbox[n], &this->sbox[this->j]);
	}
}
/*
 * Generate a random byte.
 */
static uint8_t
arc4_randbyte(dtrace_arc4_state_t * this)
{
	uint8_t arc4_t;

	this->i = (this->i + 1) % 256;
	this->j = (this->j + this->sbox[this->i]) % 256;

	arc4_swap(&this->sbox[this->i], &this->sbox[this->j]);

	arc4_t = (this->sbox[this->i] + this->sbox[this->j]) % 256;
	return this->sbox[arc4_t];
}

/*
 * MPSAFE
 */
static void
dtrace_arc4rand(dtrace_arc4_state_t * this, void *ptr, u_int len, int reseed)
{
	u_char *p;

	this->numruns += len;
	p = ptr;
	while (len--)
		*p++ = arc4_randbyte(this);;
}

/*
 * Initialize our S-box to its beginning defaults.
 */
void
dtrace_arc4_init(dtrace_arc4_state_t * this, uint8_t * key)
{
	struct timeval tv_now;
	int n;

	memset(this, 0, sizeof(dtrace_arc4_state_t));

	for (n = 0; n<256; n++)
		this->sbox[n] = n;
	arc4_randomstir(this, key);
	
	this->i = 0;
	this->j = 0;
	this->numruns = 0;
	this->reseed = dtrace_gethrtime() + DTRACE_ARC4_RESEED_NANOSECONDS;

	/*
	 * Throw away the first N words of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  (N = 256 in our case.)
	 *
	 * http://dl.acm.org/citation.cfm?id=646557.694759
	 */
	for (n = 0; n < 256*4; n++)
		arc4_randbyte(this);
}


uint32_t
dtrace_arc4random(dtrace_arc4_state_t * this)
{
	uint32_t ret;

	dtrace_arc4rand(this, &ret, sizeof ret, 0);
	return ret;
}
