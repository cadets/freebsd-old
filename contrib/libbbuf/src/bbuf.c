/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#ifdef __APPLE__
#include <mach/vm_param.h>
#else
#include <sys/param.h>
#endif

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#else
#include <assert.h>
#include <stddef.h>
#include <strings.h>
#endif

#include "bbuf.h"

struct bbuf {
	unsigned char *bb_data;
	int bb_flags;
	size_t bb_pos;
	size_t bb_limit;
	size_t bb_capacity;
};

#if _KERNEL
#define BBUF_ASSERT(exp, msg)	KASSERT(exp, msg)
#else
#define BBUF_ASSERT(exp, msg)	assert(exp)
#endif

/*!
 * Wrapper for __builtin_clz to mitigate undefined behaviour for zero values.
 *
 * Zeroes need one byte on the wire, so we return 31 leading zeroes.
 *
 * \param[in] Value
 * \return    Leading zeroes
 */
#define clz(value) \
  ((value) ? __builtin_clz(value) : 31)

static const int BBUF_USRFLAGMASK = (BBUF_AUTOEXTEND | BBUF_FIXEDLEN |  BBUF_BIGENDIAN | BBUF_LITTLEENDIAN);
static const int BBUF_MINEXTENDSIZE = 16;
static const int BBUF_MAXEXTENDSIZE = PAGE_SIZE;
static const int BBUF_MAXEXTENDINC = PAGE_SIZE;

/*! Mapping: most-significant bit ==> packed size */
static const size_t
bb_VARINT_SIZE_MAP[] = {
  1, 1, 1, 1, 1, 1, 1, 2,
  2, 2, 2, 2, 2, 2, 3, 3,
  3, 3, 3, 3, 3, 4, 4, 4,
  4, 4, 4, 4, 5, 5, 5, 5,
  5, 5, 5, 6, 6, 6, 6, 6,
  6, 6, 7, 7, 7, 7, 7, 7,
  7, 8, 8, 8, 8, 8, 8, 8,
  9, 9, 9, 9, 9, 9, 9, 10
};

static int bbuf_extend(struct bbuf *, int);
static int bbuf_extendsize(int);

#ifdef _KERNEL
static inline void
bbuf_assert_integrity(const char *func, struct bbuf *self)
#else
static inline void
bbuf_assert_integrity(const char *func __attribute((unused)),
    struct bbuf const * const self)
#endif
{

	BBUF_ASSERT(self != NULL, ("%s called with NULL bbuf instance", func));
	BBUF_ASSERT(self->bb_data != NULL,
	    ("%s called with unititialised of corrupt bbuf", func)); 
	BBUF_ASSERT(self->bb_pos <= self->bb_capacity,
	    ("wrote past the end of the bbuf (%zu >= %zu)",
	    self->bb_pos, self->bb_capacity)); 
}

static int
bbuf_extendsize(int len)
{
	int newlen = BBUF_MINEXTENDSIZE;

	BBUF_ASSERT(len > 0, ("New buffer length cannot be <= 0."));

	while (newlen < len) {
		if (newlen < BBUF_MAXEXTENDSIZE)
			newlen *= 2;
		else
			newlen += BBUF_MAXEXTENDINC;
	}

	BBUF_ASSERT(newlen > 0, ("New buffer length cannot be <= 0."));
	return newlen;
}

static int
bbuf_extend(struct bbuf *self, int addlen)
{
	unsigned char *newbuf;
	int newlen;
	
	bbuf_assert_integrity(__func__, self);

	newlen = bbuf_extendsize(self->bb_capacity + addlen);
	newbuf = (unsigned char *) bbuf_alloc(newlen);
#ifdef _KERNEL
	BBUF_ASSERT(newbuf != NULL, ("Failed to reallocate bbuf.\n"));
	{
#else
	if (newbuf != NULL) {
#endif
		bcopy(self->bb_data, newbuf, self->bb_capacity);
		bbuf_free(self->bb_data);
		self->bb_data = newbuf;
		self->bb_capacity = newlen;
		self->bb_limit = newlen;
		bbuf_assert_integrity(__func__, self);
		return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed to reallocate bbuf.\n");
	return -1;	
}

void
bbuf_delete(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
        if ((self->bb_flags & BBUF_EXTERNBUF) == 0)
		bbuf_free(self->bb_data);
	bbuf_free(self);
}

int
bbuf_new(struct bbuf **self, unsigned char *buf, size_t capacity, int flags)
{
	struct bbuf *newbuf;

	BBUF_ASSERT(capacity >= 0,
	    ("attempt to create a bbuf of negative length (%zu)",
	    capacity));
	BBUF_ASSERT((flags & ~BBUF_USRFLAGMASK) == 0,
	    ("%s called with invalid flags", __func__));

	flags &= BBUF_USRFLAGMASK;

	newbuf = (struct bbuf *) bbuf_alloc(sizeof(struct bbuf));
#ifdef _KERNEL
	BBUF_ASSERT(newbuf != NULL, ("Failed to allocate bbuf.\n"));
	{
#else
	if (newbuf != NULL) {
#endif
		newbuf->bb_flags = flags;
		newbuf->bb_capacity = capacity;
		newbuf->bb_limit = capacity;
		newbuf->bb_pos = 0;

		if (buf == NULL)  {
			newbuf->bb_data = (unsigned char *) bbuf_alloc(
			    capacity);
#ifdef _KERNEL
			BBUF_ASSERT(newbuf->bb_data != NULL,
			    ("Failed to allocate bbuf.\n"));
			{
#else
			if (newbuf->bb_data == NULL) {

				bbuf_free(newbuf);
				goto err;
#endif
			}
		} else {
			newbuf->bb_data = buf;
			newbuf->bb_flags |=
			    (BBUF_EXTERNBUF | BBUF_FIXEDLEN);
		}
			
		/* bbuf constructed successfully. */
		*self = newbuf;
		return 0;
	}

#ifndef _KERNEL
err:	
	DLOGTR0(PRIO_HIGH, "Failed to allocate bbuf.\n");
	*self = NULL;
	return -1;
#endif
}

int
bbuf_new_auto(struct bbuf **buffer)
{

	return bbuf_new(buffer, NULL, BBUF_MINEXTENDSIZE,
	    BBUF_AUTOEXTEND);
}

int
bbuf_bcat(struct bbuf *self, unsigned char const * const source, size_t len)
{
	int add_len;

	bbuf_assert_integrity(__func__, self);

	if (self->bb_pos + len > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			add_len = (self->bb_pos + len) -
			    self->bb_capacity;
			if (bbuf_extend(self, add_len) != 0)
				return -1;
		} else {
			return -1;
		}	
	}

	bcopy(source, &self->bb_data[self->bb_pos], len);
	self->bb_pos += len;
	return 0;
}

int
bbuf_scat(struct bbuf *self, struct sbuf *source)
{
	bbuf_assert_integrity(__func__, self);
	BBUF_ASSERT(source != NULL, ("Source sbuf cannot be NULL"));

	bbuf_bcat(self, (unsigned char *) sbuf_data(source),
	    sbuf_len(source));
	return 0;
}

void
bbuf_clear(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
	self->bb_pos = 0;
}

int
bbuf_concat(struct bbuf *self, struct bbuf *source)
{

	bbuf_assert_integrity(__func__, self);
	bbuf_assert_integrity(__func__, source);

	if (self->bb_pos + source->bb_pos >
	    self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, source->bb_capacity) != 0)
				return -1;
		} else {
			return -1;
		}	
	}
	bcopy(source->bb_data,
	    &self->bb_data[self->bb_pos], source->bb_pos);
	self->bb_pos += source->bb_pos;
	return 0;
}

unsigned char *
bbuf_data(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
	return self->bb_data;
}

bbuf_flags
bbuf_get_flags(struct bbuf const *self)
{

	bbuf_assert_integrity(__func__, self);
	return self->bb_flags;
}

int
bbuf_flip(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
	self->bb_limit = self->bb_pos;
	self->bb_pos = 0;
	return 0;
}

size_t
bbuf_len(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
	return self->bb_limit;
}

size_t
bbuf_pos(struct bbuf *self)
{

	bbuf_assert_integrity(__func__, self);
	return self->bb_pos;
}

int
bbuf_get_int8(struct bbuf * const self, int8_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(int8_t)) <= self->bb_limit) {

		*value = self->bb_data[self->bb_pos++];
		return 0;
	}
	return -1;
}

int
bbuf_get_uint8(struct bbuf * const self, uint8_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(uint8_t)) <= self->bb_limit) {

		*value = self->bb_data[self->bb_pos++];
		return 0;
	}
	return -1;
}

int
bbuf_get_int16(struct bbuf * const self, int16_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(int16_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8)); 
		}
		return 0;
	}
	return -1;
}

int
bbuf_get_uint16(struct bbuf * const self, uint16_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(uint16_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8)); 
		}
		return 0;
	}
	return -1;
}

int
bbuf_get_int32(struct bbuf * const self, int32_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(int32_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			*value =
			    ((((uint32_t) self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
		}
		return 0;
	}
	return -1;
}

int
bbuf_get_uint32(struct bbuf * const self, uint32_t * const value)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(uint32_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
		}
		return 0;
	}
	return -1;
}

int
bbuf_get_int64(struct bbuf * const self, int64_t * const value)
{
	uint32_t l, h;

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(int64_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			h =
			    ((((uint32_t) self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
			l = 
			    ((((uint32_t) self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
			*value = (((uint64_t) h) << 32L) |
			    (((uint64_t) l) & 0xFFFFFFFFL);
		} else {
			l =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
			h =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
			*value = (((uint64_t) h) << 32L) |
			    (((uint64_t) l) & 0xFFFFFFFFL);
		}
		return 0;
	}
	return -1;
}

int
bbuf_get_uint64(struct bbuf * const self, uint64_t * const value)
{
	uint32_t l, h;

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (self->bb_pos + sizeof(uint64_t)) <= self->bb_limit) {

		if (self->bb_flags & BBUF_BIGENDIAN) {
			h =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
			l = 
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 24) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 0));
			*value = (((uint64_t) h) << 32L) |
			    (((long) l) & 0xFFFFFFFFL);
		} else {
			l =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
			h =
			    (((self->bb_data[self->bb_pos++] & 0xFF) << 0) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 8) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 16) |
			    ((self->bb_data[self->bb_pos++] & 0xFF) << 24));
			*value = (((uint64_t) h) << 32L) |
			    (((uint64_t) l) & 0xFFFFFFFFL);
		}
		return 0;
	}
	return -1;
}


int
bbuf_put_int8_at(struct bbuf *self, int8_t value, size_t pos)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (pos + sizeof(int8_t)) > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, (int) sizeof(int8_t)) != 0)
				return -1;
		} else {
			return -1;
		}
	}
	self->bb_data[pos++] = value;
	return 0;
}

int
bbuf_put_int8(struct bbuf *self, int8_t value)
{

	bbuf_assert_integrity(__func__, self);
	if (bbuf_put_int8_at(self, value, self->bb_pos) == 0) {

		self->bb_pos += sizeof(int8_t);	
		return 0;
	}
	return -1;
}

int
bbuf_put_uint8_at(struct bbuf *self, uint8_t value, size_t pos)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (pos + sizeof(uint8_t)) > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, (int) sizeof(uint8_t)) != 0)
				return -1;
		} else {
			return -1;
		}
	}
	self->bb_data[pos++] = value;
	return 0;
}

int
bbuf_put_uint8(struct bbuf *self, uint8_t value)
{

	bbuf_assert_integrity(__func__, self);
	if (bbuf_put_int8_at(self, value, self->bb_pos) == 0) {

		self->bb_pos += sizeof(int8_t);	
		return 0;
	}
	return -1;
}

int
bbuf_put_int16_at(struct bbuf *self, int16_t value, size_t pos)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (pos + sizeof(int16_t)) > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, (int) sizeof(int16_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (self->bb_flags & BBUF_BIGENDIAN) {
		self->bb_data[pos++] = (value >> 8) & 0xFF;
		self->bb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->bb_data[pos++] = (value >> 0) & 0xFF;
		self->bb_data[pos++] = (value >> 8) & 0xFF;
	}
	return 0;
}

int
bbuf_put_int16(struct bbuf *self, int16_t value)
{

	bbuf_assert_integrity(__func__, self);
	if (bbuf_put_int16_at(self, value, self->bb_pos) == 0) {

		self->bb_pos += sizeof(int16_t);	
		return 0;
	}
	return -1;
}

int
bbuf_put_int32_at(struct bbuf *self, int32_t value, size_t pos)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (pos + sizeof(int32_t)) > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, (int) sizeof(int32_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (self->bb_flags & BBUF_BIGENDIAN) {
		self->bb_data[pos++] = (value >> 24) & 0xFF;
		self->bb_data[pos++] = (value >> 16) & 0xFF;
		self->bb_data[pos++] = (value >> 8) & 0xFF;
		self->bb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->bb_data[pos++] = (value >> 0) & 0xFF;
		self->bb_data[pos++] = (value >> 8) & 0xFF;
		self->bb_data[pos++] = (value >> 16) & 0xFF;
		self->bb_data[pos++] = (value >> 24) & 0xFF;
	}
	return 0;
}

int
bbuf_put_int32(struct bbuf *self, int32_t value)
{

	bbuf_assert_integrity(__func__, self);
	if (bbuf_put_int32_at(self, value, self->bb_pos) == 0) {

		self->bb_pos += sizeof(int32_t);	
		return 0;
	}
	return -1;
}

int
bbuf_put_int32_as_varint(struct bbuf *self, int32_t value)
{
	size_t packed_len;
	uint8_t packed_value[5];

	bbuf_assert_integrity(__func__, self);

	/* zig-zag encode the signed value */
	int32_t zigzag_value = (value << 1) ^ (value >> 31);		

	packed_len = bb_VARINT_SIZE_MAP[31 - clz(zigzag_value)];

	/* varint encode the value. */
	size_t size = 0; uint32_t temp = zigzag_value;
	if (temp & 0xFFFFFF80U) {
		packed_value[size++] = temp | 0x80;
		temp >>= 7;
		if (temp & 0xFFFFFF80U) {
			packed_value[size++] = temp | 0x80;
			temp >>= 7;
			if (temp & 0xFFFFFF80U) {
				packed_value[size++] = temp | 0x80;
				temp >>= 7;
				if (temp & 0xFFFFFF80U) {
					packed_value[size++] = temp | 0x80;
					temp >>= 7;
				}
			}
		}
	}
	packed_value[size++] = temp;

	/* Copy the varint encoded value into ther bbuf */
	return bbuf_bcat(self, packed_value, packed_len);
}

int
bbuf_put_int64_at(struct bbuf *self, int64_t value, size_t pos)
{

	bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (pos + sizeof(int64_t)) > self->bb_capacity) {

		if (self->bb_flags & BBUF_AUTOEXTEND) {

			if (bbuf_extend(self, (int) sizeof(int64_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}

	if (self->bb_flags & BBUF_BIGENDIAN) {
		self->bb_data[pos++] = (value >> 56) & 0xFF;
		self->bb_data[pos++] = (value >> 48) & 0xFF;
		self->bb_data[pos++] = (value >> 40) & 0xFF;
		self->bb_data[pos++] = (value >> 32) & 0xFF;
		self->bb_data[pos++] = (value >> 24) & 0xFF;
		self->bb_data[pos++] = (value >> 16) & 0xFF;
		self->bb_data[pos++] = (value >> 8) & 0xFF;
		self->bb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->bb_data[pos++] = (value >> 0) & 0xFF;
		self->bb_data[pos++] = (value >> 8) & 0xFF;
		self->bb_data[pos++] = (value >> 16) & 0xFF;
		self->bb_data[pos++] = (value >> 24) & 0xFF;
		self->bb_data[pos++] = (value >> 32) & 0xFF;
		self->bb_data[pos++] = (value >> 40) & 0xFF;
		self->bb_data[pos++] = (value >> 48) & 0xFF;
		self->bb_data[pos++] = (value >> 56) & 0xFF;
	}
	return 0;
}

int
bbuf_put_int64(struct bbuf *self, int64_t value)
{

	bbuf_assert_integrity(__func__, self);
	if (bbuf_put_int64_at(self, value, self->bb_pos) == 0) {

		self->bb_pos += sizeof(int64_t);	
		return 0;
	}
	return -1;
}

