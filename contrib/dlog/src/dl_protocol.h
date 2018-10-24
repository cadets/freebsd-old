/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DL_PROTOCOL_H
#define _DL_PROTOCOL_H

#include "dl_bbuf.h"
#include "dl_primitive_types.h"

#define DLOG_API_V1 1
#define DLOG_API_VERSION DLOG_API_V1

#define DLOG_MESSAGE_V0 0
#define DLOG_MESSAGE_V1 1

// Topic names should have a maximum length
// so that when persisted to the filesystem they
// don't exceed the maximum allowable path length
#define DL_MAX_TOPIC_NAME_LEN 249
#define DL_MAX_CLIENT_ID_LEN 249
#define DL_MTU 102400

#define DL_DECODE_ATTRIBUTES(source, value) dl_bbuf_get_int8(source, value)
#define DL_DECODE_API_KEY(target, value) dl_bbuf_get_int16(target, value)
#define DL_DECODE_API_VERSION(target, value) dl_bbuf_get_int16(target, value)
#define DL_DECODE_CLIENT_ID(source, target) dl_decode_string(source, target)
#define DL_DECODE_CORRELATION_ID(target, value) dl_bbuf_get_int32(target, value)
#define DL_DECODE_CRC(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_ERROR_CODE(source, value) dl_bbuf_get_int16(source, value)
#define DL_DECODE_HIGH_WATERMARK(target, value) dl_bbuf_get_int64(target, value)
#define DL_DECODE_MAGIC_BYTE(source, value) dl_bbuf_get_int8(source, value)
#define DL_DECODE_MAX_WAIT_TIME(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_MESSAGE_SIZE(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_MESSAGE_SET_SIZE(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_MIN_BYTES(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_OFFSET(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_PARTITION(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_REPLICA_ID(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_REQUIRED_ACKS(source, value) dl_bbuf_get_int16(source, value);
#define DL_DECODE_TIMEOUT(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_TIMESTAMP(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_THROTTLE_TIME(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_TOPIC_NAME(source, target) dl_decode_string(source, target)

#define DL_ENCODE_ATTRIBUTES(target, value) dl_bbuf_put_int8(target, value)
#define DL_ENCODE_API_KEY(target, value) dl_bbuf_put_int16(target, value)
#define DL_ENCODE_API_VERSION(target, value) dl_bbuf_put_int16(target, value)
#define DL_ENCODE_CLIENT_ID(target, source) dl_encode_string(target, source)
#define DL_ENCODE_CORRELATION_ID(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_CRC(source, value) dl_bbuf_put_int32(source, value)
#define DL_ENCODE_CRC_AT(source, value, at) dl_bbuf_put_int32_at(source, value, at)
#define DL_ENCODE_ERROR_CODE(target, value) dl_bbuf_put_int16(target, value)
#define DL_ENCODE_HIGH_WATERMARK(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_MAGIC_BYTE(target) dl_bbuf_put_int8(target, DL_MESSAGE_MAGIC_BYTE)
#define DL_ENCODE_MAX_WAIT_TIME(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_MAX_BYTES(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_MESSAGE_SIZE(source, value) dl_bbuf_put_int32(source, value)
#define DL_ENCODE_MESSAGE_SIZE_AT(source, value, at) \
	dl_bbuf_put_int32_at(source, value, at)
#define DL_ENCODE_MESSAGE_SET_SIZE(source, value) dl_bbuf_put_int32(source, value)
#define DL_ENCODE_MESSAGE_SET_SIZE_AT(source, value, at) \
	dl_bbuf_put_int32_at(source, value, at)
#define DL_ENCODE_MIN_BYTES(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_OFFSET(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_PARTITION(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_REPLICA_ID(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_REQUIRED_ACKS(target, value) dl_bbuf_put_int16(target, value)
#define DL_ENCODE_TIMEOUT(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_TIMESTAMP(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_THROTTLE_TIME(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_TOPIC_NAME(target, source) dl_encode_string(target, source)

/* ApiKey
 * Note: Only the Produce, Fetch and Offset APIs are currently implemented.
 */
enum dl_api_key {
	DL_PRODUCE_API_KEY = 0,
	DL_FETCH_API_KEY = 1,
	DL_OFFSET_API_KEY = 2,
};
typedef enum dl_api_key dl_api_key;

#endif
