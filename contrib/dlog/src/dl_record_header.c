/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#include <sys/time.h>
#ifdef _KERNEL
#include <sys/types.h>
#include <sys/libkern.h>
#else
#include <stddef.h>
#include <strings.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_record_header.h"
#include "dl_utils.h"

#define DL_ENCODE_KEY_LEN(source, value) dl_bbuf_put_int32_as_varint(source, value)
#define DL_ENCODE_VALUE_LEN(source, value) dl_bbuf_put_int32_as_varint(source, value)

static inline void
#ifdef _KERNEL
dl_record_header_assert_integrity(const char *func,
#else
dl_record_header_assert_integrity(const char *func __attribute((unused)),
#endif
    struct dl_record_header const * const self)
{

	DL_ASSERT(self != NULL,
	    ("%s called with NULL RecordHeader instance", func)); 
}

int
dl_record_header_new(struct dl_record_header **self, char *key,
    unsigned char *value, int32_t value_len)
{
	struct dl_record_header *record_hdr;
	
	DL_ASSERT(self != NULL, ("RecordHeader instance cannot be NULL."));

	record_hdr = (struct dl_record_header *) dlog_alloc(
	    sizeof(struct dl_record_header));
#ifdef _KERNEL
	DL_ASSERT(record_hdr != NULL, ("Failed allocating RecordHeader.\n"));
#else
	if (record_hdr == NULL)
		goto err_record_hdr;
#endif
	record_hdr->dlrh_key = sbuf_new_auto();
	sbuf_cpy(record_hdr->dlrh_key, key);
	record_hdr->dlrh_value = value;
	record_hdr->dlrh_value_len = value_len;

	*self = record_hdr;
	dl_record_header_assert_integrity(__func__, *self);
	return 0;

#ifndef _KERNEL
err_record_hdr:
	DLOGTR0(PRIO_HIGH, "Failed allocating RecordHeader.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_record_header_delete(struct dl_record_header *self)
{

	DL_ASSERT(self != NULL, ("RecordHeader instance cannot be NULL."));
	sbuf_delete(self->dlrh_key);
	dlog_free(self);
}

int
dl_record_header_decode(struct dl_record_header **self, struct dl_bbuf *source)
{
	struct dl_record_header *record_hdr;
	int rc = 0;

	DL_ASSERT(self != NULL, ("RecordHeader instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	record_hdr = (struct dl_record_header *) dlog_alloc(
	    sizeof(struct dl_record_header));
#ifdef _KERNEL
	DL_ASSERT(record_hdr != NULL,
	    ("Allocation of RecordHeader failed\n"));
#else
	if (record_hdr == NULL)
       		goto err_record_hdr;
#endif

	/* Decode the Message KeyLen */
	// TODO

	/* Decode the Message Key */
	// TODO

	/* Decode the Message ValueLen */
	// TODO
	//
	/* Decode the Message Value */
	// TODO

	if (rc == 0) {
		*self = record_hdr; 
		dl_record_header_assert_integrity(__func__, *self);
		return 0;
	}

#ifndef _KERNEL
err_record_hdr:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding RecordHeader.\n");
	*self = NULL;
	return -1;
}

int
dl_record_header_encode(struct dl_record_header const *self,
   struct dl_bbuf **target)
{

	dl_record_header_assert_integrity(__func__, self);

	/* Allocate and initialise a buffer to encode the response.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	if (dl_bbuf_new(target, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) == 0) {

		return dl_record_header_encode_into(self, *target);
	}

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;

}

int
dl_record_header_encode_into(struct dl_record_header const *self,
   struct dl_bbuf *target)
{
	int rc = 0;

	dl_record_header_assert_integrity(__func__, self);
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the KeyLen */
	rc |= DL_ENCODE_KEY_LEN(target, sbuf_len(self->dlrh_key));

	/* Encode the Key */
	rc |= dl_bbuf_scat(target, self->dlrh_key);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the ValueLen */
	rc |= DL_ENCODE_VALUE_LEN(target, self->dlrh_value_len);
	
	/* Encode the Value */
	rc |= dl_bbuf_bcat(target, self->dlrh_value, self->dlrh_value_len);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	if (rc == 0)	
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}

struct sbuf *
dl_record_header_get_key(struct dl_record_header *self)
{

	dl_record_header_assert_integrity(__func__, self);
	return self->dlrh_key;
}

unsigned char const *
dl_record_header_get_value(struct dl_record_header *self)
{

	dl_record_header_assert_integrity(__func__, self);
	return self->dlrh_value;
}
