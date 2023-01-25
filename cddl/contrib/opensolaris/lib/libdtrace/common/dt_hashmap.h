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

#ifndef _DT_HASHMAP_H_
#define _DT_HASHMAP_H_

#define DT_HASHSIZE_DEFAULT (1 << 16)

#define DTH_MANAGED (1 << 1)
#define DTH_POINTER (1 << 2)

typedef int (*dt_hashmap_fn_t)(void *, size_t, void *, void *);

typedef struct {
	void *data;
	void *key;
	size_t keysize;
	int key_ismanaged;
	int key_pointercmp;
} dt_hashbucket_t;

typedef struct dt_hashmap {
	dt_hashbucket_t *dthm_table;
	size_t          dthm_size;
	size_t          dthm_nitems;
} dt_hashmap_t;

dt_hashmap_t *dt_hashmap_create(size_t);
void *dt_hashmap_lookup(dt_hashmap_t *, void *, size_t);
int dt_hashmap_insert(dt_hashmap_t *, void *, size_t, void *, uint32_t);
void *dt_hashmap_delete(dt_hashmap_t *, void *, size_t);
void dt_hashmap_free(dt_hashmap_t *, int);
void dt_hashmap_dump(dt_hashmap_t *, const char *);
int dt_hashmap_iter(dt_hashmap_t *, dt_hashmap_fn_t, void *);

#endif /* _DT_HASHMAP_H_ */
