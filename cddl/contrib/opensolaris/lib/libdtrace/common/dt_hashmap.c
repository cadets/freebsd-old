/*- 
 * Copyright (c) 2021 Domagoj Stolfa <ds815@gmx.com>
 *
 * Copyright (c) 2014 Dag-Erling Smørgrav
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

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/hash.h>
#include <sys/stdint.h>

#include <assert.h>
#include <dt_hashmap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define rol32(i32, n) ((i32) << (n) | (i32) >> (32 - (n)))

/*
 * Simple implementation of the Murmur3-32 hash function.
 *
 * This implementation is slow but safe.  It can be made significantly
 * faster if the caller guarantees that the input is correctly aligned for
 * 32-bit reads, and slightly faster yet if the caller guarantees that the
 * length of the input is always a multiple of 4 bytes.
 */
static uint32_t
mm3_hash(const void *data, size_t len, uint32_t seed)
{
	const uint8_t *bytes;
	uint32_t hash, k;
	size_t res;

	/* initialization */
	bytes = data;
	res = len;
	hash = seed;

	/* main loop */
	while (res >= 4) {
		/* replace with le32toh() if input is aligned */
		k = le32dec(bytes);
		bytes += 4;
		res -= 4;
		k *= 0xcc9e2d51;
		k = rol32(k, 15);
		k *= 0x1b873593;
		hash ^= k;
		hash = rol32(hash, 13);
		hash *= 5;
		hash += 0xe6546b64;
	}

	/* remainder */
	/* remove if input length is a multiple of 4 */
	if (res > 0) {
		k = 0;
		switch (res) {
		case 3:
			k |= bytes[2] << 16;
		case 2:
			k |= bytes[1] << 8;
		case 1:
			k |= bytes[0];
			k *= 0xcc9e2d51;
			k = rol32(k, 15);
			k *= 0x1b873593;
			hash ^= k;
			break;
		}
	}

	/* finalize */
	hash ^= (uint32_t)len;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;
	return (hash);
}

/*
 * Simplified version of the above optimized for aligned sequences of
 * 32-bit words.  The count argument is the number of words, not the
 * length in bytes.
 */
static uint32_t
mm3_hash32(const uint32_t *data, size_t count, uint32_t seed)
{
	uint32_t hash, k;
	size_t res;

	/* iterate */
	for (res = count, hash = seed; res > 0; res--, data++) {
		k = le32toh(*data);
		k *= 0xcc9e2d51;
		k = rol32(k, 15);
		k *= 0x1b873593;
		hash ^= k;
		hash = rol32(hash, 13);
		hash *= 5;
		hash += 0xe6546b64;
	}

	/* finalize */
	hash ^= (uint32_t)count;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;
	return (hash);
}

static uint32_t
_hash(const void *data, size_t len)
{
	static uint32_t seed = 0xFEEDFACE;
	
	/*
	 * Assume that if the first address is aligned, so is everything
	 * else. We don't support differing data types in one hashmap.
	 */
	if (len >= 4 && len % 4 == 0 && ((uintptr_t)data & 3) == 0)
		return (mm3_hash32(data, len/4, seed));

	return (mm3_hash(data, len, seed));
}

static int
dt_hashmap_flags_valid(uint32_t flags)
{

	return (!((flags & DTH_MANAGED) && (flags & DTH_POINTER)));
}

dt_hashmap_t *
dt_hashmap_create(size_t size)
{
	dt_hashmap_t *hm;

	hm = malloc(sizeof(dt_hashmap_t));
	if (hm == NULL)
		return (NULL);

	hm->dthm_size = size;
	hm->dthm_nitems = 0;
	hm->dthm_table = calloc(hm->dthm_size, sizeof(dt_hashbucket_t));
	if (hm->dthm_table == NULL) {
		free(hm);
		return (NULL);
	}

	return (hm);
}

void *
dt_hashmap_lookup(dt_hashmap_t *hm, void *e, size_t es)
{
	uint32_t idx;
	uint32_t pointer_cmp;
	int i;

	idx = _hash(e, es) % hm->dthm_size;

	while (hm->dthm_table[idx].key != NULL) {
		pointer_cmp = hm->dthm_table[idx].key_pointercmp;

		if (pointer_cmp == 0) {
			assert(hm->dthm_table[idx].keysize == es);
			if (memcmp(hm->dthm_table[idx].key, e, es) == 0)
				break;
		} else {
			if (hm->dthm_table[idx].key == e)
				break;
		}

		idx++;
		idx %= hm->dthm_size;
	}

	return (hm->dthm_table[idx].data);
}

int
dt_hashmap_insert(dt_hashmap_t *hm, void *e, size_t es, void *data,
    uint32_t flags)
{
	uint32_t idx;
	size_t i;
	unsigned char *k;

	if (!dt_hashmap_flags_valid(flags))
		return (EINVAL);

	idx = _hash(e, es) % hm->dthm_size;

	while (hm->dthm_table[idx].key != NULL) {
		assert(hm->dthm_table[idx].keysize == es);
		if (memcmp(hm->dthm_table[idx].key, e, es) == 0)
			break;

		idx++;
		idx %= hm->dthm_size;
	}

	if (hm->dthm_table[idx].key == NULL) {
		hm->dthm_nitems++;
		hm->dthm_table[idx].data = data;
		if (flags & DTH_MANAGED) {
			assert((flags & DTH_POINTER) == 0);
			k = malloc(es);
			if (k == NULL)
				return (ENOMEM);
			memcpy(k, e, es);
			hm->dthm_table[idx].key_ismanaged = 1;
			hm->dthm_table[idx].key_pointercmp = 0;
		} else {
			k = e;
			hm->dthm_table[idx].key_ismanaged = 0;
			hm->dthm_table[idx].key_pointercmp = flags & DTH_POINTER;
		}

		hm->dthm_table[idx].key = k;
		hm->dthm_table[idx].keysize = es;
	}

	return (0);
}

void *
dt_hashmap_delete(dt_hashmap_t *hm, void *e, size_t es)
{
	uint32_t idx;
	void *data;

	idx = _hash(e, es) % hm->dthm_size;

	while (hm->dthm_table[idx].key != NULL) {
		assert(hm->dthm_table[idx].keysize == es);
		if (memcmp(hm->dthm_table[idx].key, e, es) == 0)
			break;
		idx++;
		idx %= hm->dthm_size;
	}

	if (hm->dthm_table[idx].key == NULL)
		return (NULL);

	data = hm->dthm_table[idx].data;
	hm->dthm_nitems--;
	hm->dthm_table[idx].data = NULL;

	if (hm->dthm_table[idx].key_ismanaged)
		free(hm->dthm_table[idx].key);

	hm->dthm_table[idx].key = NULL;
	hm->dthm_table[idx].keysize = 0;

	return (data);
}

void
dt_hashmap_free(dt_hashmap_t *hm, int free_managed)
{
	size_t i;

	if (free_managed)
		for (i = 0; i < hm->dthm_size; i++)
			if (hm->dthm_table[i].key != NULL &&
			    hm->dthm_table[i].key_ismanaged)
				free(hm->dthm_table[i].key);

	free(hm->dthm_table);
	free(hm);
}

void
dt_hashmap_dump(dt_hashmap_t *hm, const char *name)
{
	size_t i;

	for (i = 0; i < hm->dthm_size; i++) {
		if (hm->dthm_table[i].key != NULL)
			fprintf(stderr, "%s[%zu] = [%p, %zu] => %p\n", name, i,
			    hm->dthm_table[i].key, hm->dthm_table[i].keysize,
			    hm->dthm_table[i].data);
	}
}

int
dt_hashmap_iter(dt_hashmap_t *hm, dt_hashmap_fn_t fn, void *arg)
{
	size_t i;
	int rval;
	dt_hashbucket_t *e;

	for (i = 0; i < hm->dthm_size; i++) {
		if (hm->dthm_table[i].key != NULL) {
			e = &hm->dthm_table[i];
			rval = fn(e->key, e->keysize, e->data, arg);
			if (rval < 0)
				return (rval);
		}
	}

	return (0);
}

