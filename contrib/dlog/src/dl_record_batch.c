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
#include <sys/zlib.h>
#else
#include <stddef.h>
#include <strings.h>
#include <zlib.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_record.h"
#include "dl_record_batch.h"
#include "dl_utils.h"

STAILQ_HEAD(dl_records, dl_record);

struct dl_record_batch {
	struct dl_records dlrb_records;
	int64_t dlrb_first_timestamp;
	int64_t dlrb_max_timestamp;
	int32_t dlrb_nrecords;
};

static const int8_t DL_MESSAGE_MAGIC_BYTE_V2 = 0x02;
static const int8_t DL_MESSAGE_MAGIC_BYTE = DL_MESSAGE_MAGIC_BYTE_V2;
static const int8_t DL_MESSAGE_ATTRIBUTES_GZIP= 0x01;

#ifdef _KERNEL
#define CRC32(data, len) crc32(data, len)
#define CRC32C(data, len) calculate_crc32c(0xFFFFFFFF, data, len)
#else
#define CRC32(data, len) crc32(0, data, len)
#define CRC32C(data, len) crc32(0xFFFFFFFF, data, len) // TODO
#endif

#define DL_DECODE_ATTRIBUTES(source, value) dl_bbuf_get_int8(source, value)
#define DL_DECODE_BASE_OFFSET(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_BASE_SEQUENCE(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_BASE_TIMESTAMP(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_BATCH_LENGTH(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_CRC(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_LAST_OFFSET_DELTA(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_MAGIC(source, value) dl_bbuf_get_int8(source, value)
#define DL_DECODE_MAX_TIMESTAMP(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_PRODUCER_ID(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_PRODUCER_EPOCH(source, value) dl_bbuf_get_int16(source, value)
#define DL_DECODE_PARTITION_LEADER_EPOCH(source, value) \
    dl_bbuf_get_int32(source, value)

#define DL_ENCODE_ATTRIBUTES(source, value) dl_bbuf_put_int16(source, value)
#define DL_ENCODE_BASE_OFFSET(target) dl_bbuf_put_int64(target, 0)
#define DL_ENCODE_BASE_SEQUENCE(target) dl_bbuf_put_int32(target, -1)
#define DL_ENCODE_BASE_TIMESTAMP(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_CRC(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_CRC_AT(target, value, pos) dl_bbuf_put_int32_at(target, value, pos)
#define DL_ENCODE_LENGTH(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_LENGTH_AT(target, value, pos) dl_bbuf_put_int32_at(target, value, pos)
#define DL_ENCODE_LAST_OFFSET_DELTA(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_MAGIC(target) dl_bbuf_put_int8(target, DL_MESSAGE_MAGIC_BYTE)
#define DL_ENCODE_MAX_TIMESTAMP(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_PRODUCER_ID(target) dl_bbuf_put_int64(target, -1)
#define DL_ENCODE_PRODUCER_EPOCH(target) dl_bbuf_put_int16(target, -1)
#define DL_ENCODE_PARTITION_LEADER_EPOCH(source) dl_bbuf_put_int32(source, 0)

static inline void *
dlog_zalloc(void *g __attribute((unused)), unsigned n, unsigned m)
{

	return dlog_alloc(n * m);
}

static inline void
dlog_zfree(void *g __attribute((unused)), void *p)
{

	dlog_free(p);
}

static inline void
#ifdef _KERNEL
dl_record_batch_assert_integrity(const char *func,
#else
dl_record_batch_assert_integrity(const char *func __attribute((unused)),
#endif
    struct dl_record_batch const * const self)
{

	DL_ASSERT(self != NULL,
	    ("%s called with NULL RecordBatch instance", func)); 
}

#ifdef _KERNEL
static inline int
timersub(struct timeval *x, struct timeval *y, struct timeval *result)
{
	DL_ASSERT(x != NULL, ("%s called with NULL x timeval", func)); 
	DL_ASSERT(y != NULL, ("%s called with NULL y timeval", func)); 
	DL_ASSERT(result  != NULL, ("%s called with NULL result timeval", func)); 

	// preserve *y
	struct timeval yy = *y;
	y = &yy;

	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}

	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * tv_usec is certainly positive.
	 */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
#endif

int
dl_record_batch_new(struct dl_record_batch **self)
{
	struct dl_record_batch *record_batch;
	struct timeval now;
	
	DL_ASSERT(self != NULL, ("Record instance cannot be NULL."));

	record_batch = (struct dl_record_batch *) dlog_alloc(
	    sizeof(struct dl_record_batch));
#ifdef _KERNEL
	DL_ASSERT(record_batch != NULL, ("Failed allocating Record.\n"));
#else
	if (record_batch == NULL)
		goto err_record;
#endif
#ifdef _KERNEL
	getmicrotime(&now);
#else
	gettimeofday(&now, NULL);
#endif
	STAILQ_INIT(&record_batch->dlrb_records);
	record_batch->dlrb_first_timestamp =
	    record_batch->dlrb_max_timestamp =
	    (now.tv_sec * 1000 + now.tv_usec / 1000);
	record_batch->dlrb_nrecords = 0;

	*self = record_batch;
	dl_record_batch_assert_integrity(__func__, *self);
	return 0;

#ifndef _KERNEL
err_record:
	DLOGTR0(PRIO_HIGH, "Failed allocating Record.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_record_batch_delete(struct dl_record_batch *self)
{
	struct dl_record *record;

	DL_ASSERT(self != NULL, ("Record instance cannot be NULL."));

	/* Iterate across the RecordHeaders freeing each. */
	STAILQ_FOREACH(record, &self->dlrb_records, dlr_entries) {

		dl_record_delete(record);
	}
	dlog_free(self);
}

int
dl_record_batch_add_record(struct dl_record_batch *self,
    struct dl_record *record)
{
	struct timeval delta, first, now;

	dl_record_batch_assert_integrity(__func__, self);

	/* Update the Record TimestampDelta and the Record LastOffsetDelta. */
#ifdef _KERNEL
	getmicrotime(&now);
#else
	gettimeofday(&now, NULL);
#endif
	if (STAILQ_EMPTY(&self->dlrb_records)) {

		self->dlrb_first_timestamp = (now.tv_sec * 1000 + now.tv_usec / 1000);
		dl_record_set_timestamp_delta(record, 0);
	} else {

		first.tv_sec = self->dlrb_first_timestamp / 1000;
		first.tv_usec = (self->dlrb_first_timestamp % 1000) * 1000;
		timersub(&first, &now, &delta);

		dl_record_set_timestamp_delta(record, (delta.tv_sec * 1000 + delta.tv_usec / 1000));
	}
		
        /* Update the RecordBatch MaxTimestamp */ 
	self->dlrb_max_timestamp = (now.tv_sec * 1000 + now.tv_usec / 1000);

	/* Update the Record OffsetDelta and the RecordBatch LastOffsetDelta. */
	dl_record_set_offset_delta(record, self->dlrb_nrecords++);

	/* Add the Record to the RecordBatch */
	STAILQ_INSERT_HEAD(&self->dlrb_records, record, dlr_entries);

	return 0;
}

int
dl_record_batch_decode(struct dl_record_batch **self, struct dl_bbuf *source)
{
	struct dl_record_batch *record_batch;
	int rc = 0;

	DL_ASSERT(self != NULL, ("Record instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	record_batch = (struct dl_record_batch *) dlog_alloc(
	    sizeof(struct dl_record_batch));
#ifdef _KERNEL
	DL_ASSERT(record_batch != NULL,
	    ("Allocation of Record failed\n"));
#else
	if (record_batch == NULL)
       		goto err_record;
#endif
	// TODO

	if (rc == 0) {
		*self = record_batch; 
		dl_record_batch_assert_integrity(__func__, *self);
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
dl_record_batch_encode(struct dl_record_batch const *self,
   struct dl_bbuf **target)
{
	int rc;

	dl_record_batch_assert_integrity(__func__, self);
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Allocate and initialise a buffer to encode the response.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	rc = dl_bbuf_new(target, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
        if (rc == 0) {

		return dl_record_batch_encode_into(self, *target);
	}
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Allocating autoextending buffer cannot fail."));
#endif
	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}

int
dl_record_batch_encode_into(struct dl_record_batch const *self,
   struct dl_bbuf *target)
{
	struct dl_bbuf *encoded_records, *gzipd;
	struct dl_record *record;
	z_stream stream;
	unsigned char *crc_data;
	uint8_t *compressed;
	uint32_t crcc_val, nencoded = 0;
	int attr_pos, crc_pos, length_pos, after_length_pos;
	int deflate_rc = Z_OK;
	int rc = 0;

	dl_record_batch_assert_integrity(__func__, self);
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	rc |= DL_ENCODE_BASE_OFFSET(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	length_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_LENGTH(target, -1);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	after_length_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_PARTITION_LEADER_EPOCH(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_MAGIC(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Placeholder for the CRC.
	 * The CRC is computed over the data from the attributes to the end
	 * of the batch.
	 */
	crc_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_CRC(target, -1);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	attr_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_ATTRIBUTES(target, DL_MESSAGE_ATTRIBUTES_GZIP);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_LAST_OFFSET_DELTA(target, self->dlrb_nrecords-1);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_BASE_TIMESTAMP(target, self->dlrb_first_timestamp);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_MAX_TIMESTAMP(target, self->dlrb_max_timestamp);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_PRODUCER_ID(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_PRODUCER_EPOCH(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= DL_ENCODE_BASE_SEQUENCE(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Iterate across the Records encoding each. */
	rc |= dl_bbuf_new(&encoded_records, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	if (rc == 0) {	
		STAILQ_FOREACH(record, &self->dlrb_records, dlr_entries) {
		
			rc |= dl_record_encode_into(record, encoded_records);
			nencoded++;
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
		DL_ASSERT(nencoded == self->dlrb_nrecords,
		    ("Number of records doesn't match encoded records."));

		/* Initialise the zlib deflate (LZ77) algorithm.
		 * Specifying a negative window size (-MAX_WBITS) to defalteInit2()
		 * excludes the zlib header (this is an undocumented feature).
		 */ 
		bzero(&stream, sizeof(stream));
		stream.zalloc = dlog_zalloc;
		stream.zfree = dlog_zfree;
		stream.opaque = Z_NULL;

		deflate_rc = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		    -MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
		DL_ASSERT(deflate_rc == Z_OK,
		    ("Error initializing zlib %d", deflate_rc));

		/* As the version of zlib in kernel is sufficiently out of date it
		* does not provide the ability to compute an upper bound for the 
		* compressed data. Therefore, I instead allocate a buffer as big as 
		* the input (uncomoressed data).
		*/
		compressed = (uint8_t *) dlog_alloc(
		sizeof(uint8_t *) * dl_bbuf_pos(encoded_records)); 
#ifdef _KERNEL
		DL_ASSERT(compressed != NULL,
		("Failed allocating buffer for compressed data."));
#endif
		stream.next_in = dl_bbuf_data(encoded_records);
		stream.avail_in = dl_bbuf_pos(encoded_records);
		stream.next_out = compressed;
		stream.avail_out = dl_bbuf_pos(encoded_records);

		/* Compress the encoded Messages using zlib (LZ77/GZIP) using the
		* default compression level. Use Z_NO_FLUSH so that zlib can
		* accumulate data and therefore efficiently compress before
		* writting any output.
		*/
		while (stream.avail_in != 0) {
			deflate_rc = deflate(&stream, Z_NO_FLUSH);
			if (stream.avail_out == 0) {
				/* The compressed MessageSet is larger than the
				* uncompressed version (although rare this can
				* happen). Abbandon sending a compressed Message
				* and proceed wit sending the uncompressed message. 
				*/
				DL_ASSERT(0,
				("Compressed MessageSet > than uncompressed."));
			}
		};

		/* FLush the compressed output. */
		while (deflate_rc == Z_OK) {
			if (stream.avail_out == 0) {
				/* The compressed MessageSet is larger than the
				* uncompressed version (although rare this can
				* happen). Abbandon sending a compressed Message
				* and proceed wit sending the uncompressed message. 
				*/
				DL_ASSERT(0,
				("Compressed MessageSet > than uncompressed."));
			}
			deflate_rc = deflate(&stream, Z_FINISH);
			DL_ASSERT(deflate_rc >= 0,
			    ("Error deflating MessageSet with zlib %d", deflate_rc));
		};

		deflateEnd(&stream);

		/* Allocate a buffer into which a GZIP formated data is written. */
		rc |= dl_bbuf_new(&gzipd, NULL, 1024, DL_BBUF_AUTOEXTEND);

		/* Write out GZIP header as the version of zlib in kernel is
		* significantly out of date and does not support this (updating
		* zlib is fairly laborious and needs some though how to manage.)
		*
		* GZIP header (RFC 1952): 
		* <0x1F>	 		- Identification 1 
		* <0x8B> 			- Identification 2 
		* <0x08>			- Compression method (8 = Defalte)
		* <0x00>			- Flags
		* <0x00><0x00><0x00><0x00>	- Modification TIME (of file) 
		* <0x00>			- Operating System
		*/
		rc |= dl_bbuf_put_uint8(gzipd, 0x1F);
		rc |= dl_bbuf_put_uint8(gzipd, 0x8B);
		rc |= dl_bbuf_put_uint8(gzipd, 8);
		rc |= dl_bbuf_put_uint8(gzipd, 0);
		rc |= dl_bbuf_put_int32(gzipd, 0);
		rc |= dl_bbuf_put_uint8(gzipd, 0);
		rc |= dl_bbuf_put_uint8(gzipd, 0);

		/* Copy the deflate compressed data into the buffer. */
		rc |= dl_bbuf_bcat(gzipd, compressed, stream.total_out);
		dlog_free(compressed);

		/* Write out GZIP trailer.
		*
		* GZIP trailer (RFC 1952):
		*
		* <0x00><0x00><0x00><0x00>	- CRC32 of uncompressed data
		* <0x00><0x00><0x00><0x00>	- ISIZE (size of uncompressed data )
		*/
		rc |= dl_bbuf_put_int32(gzipd,
		    CRC32(dl_bbuf_data(encoded_records), dl_bbuf_pos(encoded_records)));
		rc |= dl_bbuf_put_int32(gzipd, dl_bbuf_pos(encoded_records));
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
		/* Encode the number of records. */
		rc |= dl_bbuf_put_int32(target, self->dlrb_nrecords);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		rc |= dl_bbuf_concat(target, gzipd);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
		dl_bbuf_delete(gzipd);
		dl_bbuf_delete(encoded_records);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
		
		/* Encode the BatchLength. */
		rc |= DL_ENCODE_LENGTH_AT(target,
		    dl_bbuf_pos(target)-after_length_pos, length_pos);
#ifdef _KERNEL
		DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the CRC-32C. */
		crc_data = dl_bbuf_data(target) + attr_pos; 
		crcc_val = CRC32C(crc_data, dl_bbuf_pos(target) - attr_pos);
		
		rc |= DL_ENCODE_CRC_AT(target, crcc_val ^ 0xFFFFFFFF, crc_pos);

		if (rc == 0)	
			return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}
