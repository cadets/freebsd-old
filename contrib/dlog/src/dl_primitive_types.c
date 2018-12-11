/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 *
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/libkern.h>
#else
#include <stddef.h>
#include <string.h>
#endif

#include "dl_assert.h"
// TODO: temporary
#include "dl_memory.h"
#include "dl_primitive_types.h"

/* NULLABLE Strings and arrays of Bytes are represented with the value -1. */
static const int16_t DL_STRING_NULL = -1;
static const int32_t DL_BYTES_NULL = -1;

/**
 * Encoded strings are prefixed with their length (int16);
 * a value of -1 indicates a NULL string.
 */
int
dl_decode_string(struct dl_bbuf *source, struct sbuf **target)
{
	int16_t slen;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
	DL_ASSERT(target != NULL, ("Traget sbuf cannot be NULL"));

	/* Strings are NULLABLE.
	 * Therefore first check whether there is a value to decode.
	 */
	if (dl_bbuf_get_int16(source, &slen) != 0)
		return -1;

	if (slen == DL_STRING_NULL) {
		*target = NULL;
	} else {
		int8_t * temp = (int8_t *) dlog_alloc(sizeof(int8_t) * slen);

		/* TODO: Replace with bulk drain function in dl_bbuf */
		for (int i = 0; i < slen; i++)
			dl_bbuf_get_int8(source, &temp[i]);
		*target = sbuf_new(NULL, NULL, slen + 1, SBUF_FIXEDLEN);
		sbuf_bcat(*target, temp, slen);
		dlog_free(temp);
	}
	return 0;
}

/**
 * Encoded arrays are prefixed with their length (int32);
 * a value of -1 indicates a NULL string.
 */
int
dl_decode_bytes(unsigned char ** const target, int *target_len,
    struct dl_bbuf *source)
{
	int32_t nbytes;
	int rc;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Bytes are NULLABLE.
	 * therefore first check whether there is a value to decode.
	 */
	rc = dl_bbuf_get_int32(source, &nbytes);
	if (rc != 0)
		return -1;

	if (nbytes == DL_BYTES_NULL) {
		*target_len = 0;
		*target = NULL;
		return 0;
	}

	*target = (int8_t *) dlog_alloc(nbytes * sizeof(int8_t));
#ifdef _KERNEL
	DL_ASSERT(*target != NULL, ("Failed allocating target buffer."));
#else
	if (*target == NULL)
		return -1;
#endif
	*target_len = nbytes;

	/* TODO: Replace with bulk drain function in dl_bbuf */
	for (int i = 0; i < nbytes; i++) {
		dl_bbuf_get_int8(source, (* target) + i);
	}
	return 0;
}

/**
 * Encoded strings are prefixed with their length (int16).
 */
int32_t
dl_encode_string(struct dl_bbuf *target, struct sbuf *source)
{

	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	if (source == NULL) {
		dl_bbuf_put_int16(target, DL_STRING_NULL);
	} else {
		/* Prepended a 16bit value indicating the length (in bytes). */
		if (dl_bbuf_put_int16(target, sbuf_len(source)) == 0) {

			/* Copy source bytes into the target buffer. */
			dl_bbuf_scat(target, source);
		} else {
			return -1;
		}
	}
	return 0;
}

/**
 * Encoded byte arrays are prefixed with their length (int32).
 */
int
dl_encode_bytes(unsigned char const * const source, const int32_t source_len,
    struct dl_bbuf * target)
{

	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	if (source == NULL) {
		dl_bbuf_put_int32(target, DL_BYTES_NULL);
	} else {
		/* Prepend a 32bit value indicating the length (in bytes). */
		dl_bbuf_put_int32(target, source_len);

		/* Copy source_len bytes from source into the target buffer. */
		dl_bbuf_bcat(target, source, source_len);
	}
	return 0;
}
