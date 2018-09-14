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

#include <sys/time.h>
#ifdef _KERNEL
#include <sys/types.h>
#include <sys/libkern.h>
#else
#include <zlib.h>
#include <stddef.h>
#include <strings.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_utils.h"

static const int8_t DL_MESSAGE_MAGIC_BYTE_V0 = 0x00;
static const int8_t DL_MESSAGE_MAGIC_BYTE_V1 = 0x01;
static const int8_t DL_MESSAGE_MAGIC_BYTE = DL_MESSAGE_MAGIC_BYTE_V1;
static const int8_t DL_MESSAGE_ATTRIBUTES = 0x00;
static const int64_t DL_DEFAULT_OFFSET = 0;

#define DL_ATTRIBUTES_SIZE sizeof(int8_t)
#define DL_CRC_SIZE sizeof(int32_t)
#define DL_MAGIC_BYTE_SIZE sizeof(int8_t)
#define DL_MESSAGE_SIZE sizeof(int32_t)
#define DL_OFFSET_SIZE sizeof(int64_t)
#define DL_TIMESTAMP_SIZE sizeof(int64_t)

#ifdef _KERNEL
#define CRC32(data, len) crc32(data, len)
#else
#define CRC32(data, len) crc32(0, data, len)
#endif

static int dl_message_decode(struct dl_message **, struct dl_bbuf *);
static int dl_message_encode(struct dl_message const *, struct dl_bbuf *);

int
dl_message_set_new(struct dl_message_set **self, unsigned char *key,
    int32_t key_len, unsigned char *value, int32_t value_len)
{
	struct dl_message_set *message_set;
	struct dl_message *message;
	
	DL_ASSERT(self != NULL, ("MessageSet instance cannot be NULL."));

	message_set = (struct dl_message_set *) dlog_alloc(
	    sizeof(struct dl_message_set));
#ifdef _KERNEL
	DL_ASSERT(message_set != NULL, ("Failed allocating message set.\n"));
#else
	if (message_set == NULL)
		goto err_message_set;
#endif
	STAILQ_INIT(&message_set->dlms_messages);
	message_set->dlms_nmessages = 1;

	message = (struct dl_message *) dlog_alloc(
	    sizeof(struct dl_message));
#ifdef _KERNEL
	DL_ASSERT(message != NULL, ("Failed allocating message.\n"));
#else
	if (message == NULL) {
		dlog_free(message_set);
		goto err_message_set;
	}
#endif
	message->dlm_key = key;
	message->dlm_key_len = key_len;
	message->dlm_value = value;
	message->dlm_value_len = value_len;

	STAILQ_INSERT_HEAD(&message_set->dlms_messages, message, dlm_entries);

	*self = message_set;
	return 0;

#ifndef _KERNEL
err_message_set:
	DLOGTR0(PRIO_HIGH, "Failed allocating message.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_message_set_delete(struct dl_message_set *self)
{
	struct dl_message const *msg, *msg_tmp;

	DL_ASSERT(self != NULL, ("MessageSet instance cannot be NULL."));

	STAILQ_FOREACH_SAFE(msg, &self->dlms_messages, dlm_entries, msg_tmp) {
		
		/* Remove the Message instance from the MessageSet and free 
		 * its memory.
		 */
		STAILQ_REMOVE(&self->dlms_messages, msg, dl_message,
		    dlm_entries);
		dlog_free(msg);
	}

	dlog_free(self);
}

int
dl_message_set_decode(struct dl_message_set **self, struct dl_bbuf *source)
{
	struct dl_message *message;
	struct dl_message_set *msgset;
	int32_t msg_set_size;
	int rc = 0;

	DL_ASSERT(self != NULL, ("MessageSet instance cannot be NULL."));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
		
	msgset = (struct dl_message_set *) dlog_alloc(
	    sizeof(struct dl_message_set));
#ifdef _KERNEL
	DL_ASSERT(msgset != NULL, ("Failed allocating MessageSet."));
#else
	if (msgset == NULL)
		goto err_message_set;
#endif
	bzero(msgset, sizeof(struct dl_message_set));

	STAILQ_INIT(&msgset->dlms_messages);

	/* Decode the MessageSetSize. */
	rc |= DL_DECODE_MESSAGE_SET_SIZE(source, &msg_set_size);

	if (msg_set_size > dl_bbuf_len(source)-dl_bbuf_pos(source)) {

		DLOGTR2(PRIO_HIGH,
		    "MessageSetSize (%d) is greater than "
		    "remaining buffer (%d).\n", msg_set_size,
		    dl_bbuf_len(source)-dl_bbuf_pos(source)); 
		dlog_free(msgset);
		goto err_message_set;
	}

	/* Decode the MessageSet. */
	while (dl_bbuf_pos(source) < dl_bbuf_len(source)) {

		/* Decode the Message. */
		rc |= dl_message_decode(&message, source);
		if (rc != 0)
			break;

		STAILQ_INSERT_HEAD(&msgset->dlms_messages, message,
		    dlm_entries);
	}

	if (rc == 0) {
		/* Successfully decoded MessageSet. */
		*self = msgset;
		return 0;
	}

err_message_set:
	DLOGTR0(PRIO_HIGH, "Failed decoding MessageSet.\n");
	*self = NULL;
	return -1;
}
		
static int
dl_message_decode(struct dl_message **self, struct dl_bbuf *source)
{
	struct dl_message *message;
	unsigned long crc_value;
	unsigned char *crc_data;
	int32_t msg_crc, size;
	int rc = 0, crc_start_pos;
	int8_t attributes, magic_byte;

	DL_ASSERT(self != NULL, ("Message instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	message = (struct dl_message *) dlog_alloc(sizeof(struct dl_message));
#ifdef _KERNEL
	DL_ASSERT(message != NULL, ("Allocation of dl_message failed\n"));
#else
	if (message == NULL)
       		goto err_message;
#endif
	/* Decode the MessageSet Offset. */
	rc |= DL_DECODE_OFFSET(source, &message->dlm_offset);

	/* Decode the MessageSize. */
	rc |= DL_DECODE_MESSAGE_SIZE(source, &size);
	if (size <= 0) {
		DLOGTR1(PRIO_HIGH, "Invalid Message size (%d)\n", size);
		dlog_free(message);
		goto err_message;
	}

	/* Decode and verify the CRC. */
	rc |= DL_DECODE_CRC(source, &msg_crc);
	crc_start_pos = dl_bbuf_pos(source);

	/* Compute and verify the CRC value. */
	crc_data = dl_bbuf_data(source) + crc_start_pos;
	crc_value = CRC32(crc_data, dl_bbuf_len(source)-crc_start_pos);
	if ((int32_t) crc_value != msg_crc) {
		DLOGTR2(PRIO_HIGH,
		    "Computed CRC (%ld) doess't match value "
		    "recieved value (%d).\n", crc_value, msg_crc);
		dlog_free(message);
		goto err_message;
	}

	/* Decode and verify the MagicByte */
	rc |= DL_DECODE_MAGIC_BYTE(source, &magic_byte);
	if (magic_byte != DL_MESSAGE_MAGIC_BYTE_V0 &&
	    magic_byte != DL_MESSAGE_MAGIC_BYTE_V1) {
		DLOGTR1(PRIO_HIGH, "Invalid MagicByte (%d)\n", magic_byte);
		dlog_free(message);
		goto err_message;
	}

	/* Decode the Attributes */
	rc |= DL_DECODE_ATTRIBUTES(source, &attributes);

	/* The MagicByte determines the MessageSet format v0 or v1. */
	if (magic_byte == DL_MESSAGE_MAGIC_BYTE) {	

		/* Decode the Timestamp */
		rc |= DL_DECODE_TIMESTAMP(source,
		    &message->dlm_timestamp);
	}

	/* Decode the Message Key */
	rc |= dl_decode_bytes(&message->dlm_key, &message->dlm_key_len, source);

	/* Decode the Message Value */
	rc |= dl_decode_bytes(&message->dlm_value, &message->dlm_value_len,
	    source);

	if (rc == 0) {
		*self = message; 
		return 0;
	}

err_message:
	DLOGTR0(PRIO_HIGH, "Failed decoding Message.\n");
	*self = NULL;
	return -1;
}

/**
 * N.B. MessageSets are not preceded by an int32 specifying the length unlike
 * other arrays.
 */
int
dl_message_set_encode(struct dl_message_set const *message_set,
    struct dl_bbuf *target)
{
	struct dl_message const *message;
	int msgset_size_pos, msgset_start, msgset_end;
	int rc = 0;

	DL_ASSERT(message_set != NULL, ("MessageSet cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Add a placeholder for the MessageSetSize. */
	msgset_size_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_MESSAGE_SIZE(target, -1);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Save the position of the start of the MessageSet; this is used
	 * to compute the MessageSetSize once the MessageSet has been
	 * successfully encoded.
	 */
	msgset_start = dl_bbuf_pos(target);
	STAILQ_FOREACH(message, &message_set->dlms_messages, dlm_entries) {

		/* Encode the Message. */
		rc |= dl_message_encode(message, target);
	}

	/* Encode the MessageSetSize into the buffer. */
	msgset_end = dl_bbuf_pos(target);
	rc |= DL_ENCODE_MESSAGE_SIZE_AT(target, (msgset_end-msgset_start),
	    msgset_size_pos);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding MessageSet.\n");
	return -1;
}

static int
dl_message_encode(struct dl_message const *message, struct dl_bbuf *target)
{
	unsigned long crc_value, timestamp;
	unsigned char *crc_data;
	int rc = 0, size_pos, crc_pos, crc_start_pos;

	DL_ASSERT(message != NULL, ("Message cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the Message Offset into the target buffer. */
	rc |= DL_ENCODE_OFFSET(target, DL_DEFAULT_OFFSET);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Placeholder for the size of the encoded Message. */
	size_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_MESSAGE_SIZE(target, -1);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Placeholder for the CRC computed over the encoded Message. */
	crc_pos = dl_bbuf_pos(target);
	rc |= DL_ENCODE_CRC(target, -1);
	crc_start_pos = dl_bbuf_pos(target);
	
	/* Encode the MagicByte */
	rc |= DL_ENCODE_MAGIC_BYTE(target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	/* Encode the Attributes */
	rc |= DL_ENCODE_ATTRIBUTES(target, DL_MESSAGE_ATTRIBUTES);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	/* Encode the Timestamp */
#ifdef _KERNEL
#ifdef __APPLE__
	int32_t secs, msecs;

	clock_get_calendar_microtime(&secs, &msecs);
	timestamp = (secs * 1000) + msecs;
#else
	struct timeval tv;

	getmicrotime(&tv);
	timestamp = (tv.tv_sec *1000) + (tv.tv_usec/1000);
#endif
#else
	timestamp = time(NULL);
#endif
	rc |= DL_ENCODE_TIMESTAMP(target, timestamp);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	/* Encode the Key */
	rc |= dl_encode_bytes(message->dlm_key, message->dlm_key_len, target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	/* Encode the Value */
	rc |= dl_encode_bytes(message->dlm_value, message->dlm_value_len,
	    target);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the MessageSize. */
	rc |= DL_ENCODE_MESSAGE_SIZE_AT(target, dl_bbuf_pos(target)-crc_pos,
	    size_pos);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	/* Encode the CRC. */
	crc_data = dl_bbuf_data(target) + crc_start_pos; 
	crc_value = CRC32(crc_data, dl_bbuf_pos(target)-crc_start_pos);

	rc |= DL_ENCODE_CRC_AT(target, crc_value, crc_pos);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif
	
	if (rc == 0)	
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding Message.\n");
	return -1;
}
