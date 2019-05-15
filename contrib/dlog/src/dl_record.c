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
#include <sys/queue.h>
#ifdef _KERNEL
#include <sys/types.h>
#include <sys/libkern.h>
#else
#include <stddef.h>
#include <strings.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_record.h"
#include "dl_utils.h"

// TODO: get_as_varint
#define DL_DECODE_ATTRIBUTES(source, value) dl_bbuf_get_int8(source, value)
#define DL_DECODE_KEY_LEN(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_RECORD_SIZE(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_OFFSET_DELTA(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_TIMESTAMP_DELTA(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_VALUE_LEN(source, value) dl_bbuf_get_int32(source, value)

#define DL_ENCODE_ATTRIBUTES(source) dl_bbuf_put_int8(source, 0)
#define DL_ENCODE_KEY_LEN(source, value) dl_bbuf_put_int32_as_varint(source, value)
#define DL_ENCODE_RECORD_SIZE(source, value) dl_bbuf_put_int32_as_varint(source, value)
#define DL_ENCODE_OFFSET_DELTA(target, value) dl_bbuf_put_int32_as_varint(target, value)
#define DL_ENCODE_TIMESTAMP_DELTA(target, value) dl_bbuf_put_int32_as_varint(target, value)
#define DL_ENCODE_VALUE_LEN(source, value) dl_bbuf_put_int32_as_varint(source, value)

static inline void
#ifdef _KERNEL
dl_record_assert_integrity(const char *func,
#else
dl_record_assert_integrity(const char *func __attribute((unused)),
#endif
    struct dl_record const * const self)
{

	DL_ASSERT(self != NULL,
	    ("%s called with NULL Record instance", func)); 
	DL_ASSERT(self->dlr_key != NULL,
	    ("%s called with NULL dlr_key field", func)); 
	DL_ASSERT(self->dlr_value != NULL,
	    ("%s called with NULL dlr_value field", func)); 
}

int
dl_record_new(struct dl_record ** self, char *key,
    unsigned char *value, int32_t value_len)
{
	struct dl_record *record;
	
	DL_ASSERT(self != NULL, ("Record instance cannot be NULL."));

	record = (struct dl_record *) dlog_alloc(
	    sizeof(struct dl_record));
#ifdef _KERNEL
	DL_ASSERT(record != NULL, ("Failed allocating Record.\n"));
#else
	if (record == NULL)
		goto err_record;
#endif
	record->dlr_timestamp_delta = 0;
	record->dlr_offset_delta = 0;
	record->dlr_key = sbuf_new_auto();
	sbuf_cpy(record->dlr_key, key);
	sbuf_finish(record->dlr_key);
	record->dlr_value_len = value_len;
	record->dlr_value = value;
	STAILQ_INIT(&record->dlr_headers);

	*self = record;
	dl_record_assert_integrity(__func__, *self);
	return 0;

#ifndef _KERNEL
err_record:
	DLOGTR0(PRIO_HIGH, "Failed allocating Record.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_record_delete(struct dl_record *self)
{
	struct dl_record_header *record_hdr, *record_hdr_tmp;

	dl_record_assert_integrity(__func__, self);

	/* Iterate across the RecordHeaders freeing each. */
	STAILQ_FOREACH_SAFE(record_hdr, &self->dlr_headers,
	    dlrh_entries, record_hdr_tmp) {
		
		/* Remove the RecordHeader instance from the Record
		 * and free its memory.
		 */
		STAILQ_REMOVE(&self->dlr_headers, record_hdr,
		    dl_record_header, dlrh_entries);
		dl_record_header_delete(record_hdr);
	}

	sbuf_delete(self->dlr_key);
	dlog_free(self);
}

void
dl_record_set_offset_delta(struct dl_record * const self, int32_t offset_delta)
{

	dl_record_assert_integrity(__func__, self);
	self->dlr_offset_delta = offset_delta;
}

void
dl_record_set_timestamp_delta(struct dl_record * const self,
    int32_t timestamp_delta)
{

	dl_record_assert_integrity(__func__, self);
	self->dlr_timestamp_delta = timestamp_delta;
}

int
dl_record_decode(struct dl_record **self, struct dl_bbuf *source)
{
	struct dl_record *record;
	int rc = 0;

	DL_ASSERT(self != NULL, ("Record instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	record = (struct dl_record *) dlog_alloc(sizeof(struct dl_record));
#ifdef _KERNEL
	DL_ASSERT(record != NULL,
	    ("Allocation of Record failed\n"));
#else
	if (record == NULL)
       		goto err_record;
#endif
	// TODO:

	if (rc == 0) {
		*self = record; 
		dl_record_assert_integrity(__func__, *self);
		return 0;
	}

#ifndef _KERNEL
err_record:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding Record.\n");
	*self = NULL;
	return -1;
}

int
dl_record_encode(struct dl_record const *self, struct dl_bbuf **target)
{

	dl_record_assert_integrity(__func__, self);

	/* Allocate and initialise a buffer to encode the response.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	if (dl_bbuf_new(target, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) == 0) {

		return dl_record_encode_into(self, *target);
	}

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}

int
dl_record_encode_into(struct dl_record const *self, struct dl_bbuf *target)
{
	struct dl_record_header *record_hdr;
   	struct dl_bbuf *record;
	int rc = 0;

	dl_record_assert_integrity(__func__, self);
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));
	
	if (dl_bbuf_new(&record, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) == 0) {

		/* Encode the Attributes (bit 0-7: unused) */
		rc |= DL_ENCODE_ATTRIBUTES(record);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the TimestampDelta */
		rc |= DL_ENCODE_TIMESTAMP_DELTA(record, self->dlr_timestamp_delta);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the OffsetDelta */
		rc |= DL_ENCODE_OFFSET_DELTA(record, self->dlr_offset_delta);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the KeyLen */
		rc |= DL_ENCODE_KEY_LEN(record, sbuf_len(self->dlr_key));

		/* Encode the Key */
		rc |= dl_bbuf_scat(record, self->dlr_key);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the ValueLen */
		rc |= DL_ENCODE_VALUE_LEN(record, self->dlr_value_len);
		
		/* Encode the Value */
		rc |= dl_bbuf_bcat(record, self->dlr_value, self->dlr_value_len);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the Record Headers */
		rc |= dl_bbuf_put_int32_as_varint(record, 0);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Iterate across the Headers encoding each into the target buffer. */
		STAILQ_FOREACH(record_hdr, &self->dlr_headers, dlrh_entries) {

			rc |= dl_record_header_encode_into(record_hdr, record);
		}

		// TODO: [Header] uint32_t number of Headers

		/* Encode the RecordSize into the buffer. */
		rc |= DL_ENCODE_RECORD_SIZE(target, dl_bbuf_pos(record));
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Concat the encoded Record with the target buffer. */
		rc |= dl_bbuf_concat(target, record);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
		dl_bbuf_delete(record);

		if (rc == 0)	
			return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}
