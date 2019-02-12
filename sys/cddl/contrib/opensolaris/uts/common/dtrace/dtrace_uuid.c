/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Marcel Moolenaar
 * Copyright (c) 2016 Robert N. M. Watson
 * Copyright (c) 2018 Graeme Jenkinson
 * All rights reserved.
 *
 * Portions of this software were developed by BAE Systems, the University of
 * Cambridge Computer Laboratory, and Memorial University under DARPA/AFRL
 * contract FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent
 * Computing (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/uuid.h>

#include <dtrace_endian.h>
#include <dtrace_sha1.c>

#define	DTRACE_UUID_NODE_LEN		_UUID_NODE_LEN
#define	DTRACE_SHA_DIGEST_LENGTH	DTRACE_SHA1_RESULTLEN

/* We use an alternative, more convenient representation in the generator. */
struct dtrace_uuid_private {
	union {
		uint64_t	ll;		/* internal. */
		struct {
			uint32_t	low;
			uint16_t	mid;
			uint16_t	hi;
		} x;
	} time;
	uint16_t	seq;			/* Big-endian. */
	uint16_t	node[DTRACE_UUID_NODE_LEN>>1];
};



static void
dtrace_uuid_generate_nil(struct uuid *store)
{

	dtrace_bzero(store, sizeof(*store));
}

/*
 * Compute a SHA-1-based namespace UUID.  Inputs are the UUID of the namespace
 * and canonical name within that namespace.
 */
static void
dtrace_uuid_generate_version5(struct uuid *store, const struct uuid *namespace,
    const void *name, size_t name_len)
{
	struct uuid uuid, uuid_namespace;
	struct dtrace_sha1_ctxt sha1_ctxt;
	union {
		uint8_t		uint8[DTRACE_SHA_DIGEST_LENGTH];
		uint16_t	uint16[DTRACE_SHA_DIGEST_LENGTH / 2];
		uint32_t	uint32[DTRACE_SHA_DIGEST_LENGTH / 4];
	} md;

	/*
	 * RFC: Convert the name to a canonical sequence of octets (as defined
	 * by the standards or conventions of its name space); put the name
	 * space ID in network byte order.
	 *
	 * NB: We assume caller places name in suitable byte order.
	 */
	uuid_namespace = *namespace;
	uuid_namespace.time_low = dtrace_be32toh(uuid_namespace.time_low);
	uuid_namespace.time_mid = dtrace_be16toh(uuid_namespace.time_mid);
	uuid_namespace.time_hi_and_version =
	    dtrace_be16toh(uuid_namespace.time_hi_and_version);

	/*
	 * RFC: Compute the hash of the name space ID concatenated with the
	 * name.
	 */
	DTraceSHA1Init(&sha1_ctxt);
	DTraceSHA1Update(&sha1_ctxt, (const uint8_t *)&uuid_namespace,
	    sizeof(uuid_namespace));
	DTraceSHA1Update(&sha1_ctxt, (const uint8_t *)name, name_len);
	DTraceSHA1Final((uint8_t *)&md, &sha1_ctxt);

	/*
	 * RFC: Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the appropriate 4-bit version number
	 * from Section 4.1.3.
	 */
  	md.uint8[6] = (md.uint8[6] & 0x0F) | 0x50;

	/*
	 * RFC: Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
  	md.uint8[8] = (md.uint8[8] & 0x3F) | 0x80;

	dtrace_bcopy(&md, &uuid, sizeof(struct uuid));

	/*
	 * RFC: Convert the resulting UUID to network byte order.
	 */
	uuid.time_low = dtrace_htobe32(uuid.time_low);
	uuid.time_mid = dtrace_htobe16(uuid.time_mid);
	uuid.time_hi_and_version = dtrace_htobe16(uuid.time_hi_and_version);
	*store = uuid;
}
