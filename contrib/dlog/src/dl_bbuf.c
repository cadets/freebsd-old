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

#ifdef __APPLE__
#include <mach/vm_param.h>
#else
#include <sys/param.h>
#endif

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
#include "dl_utils.h"

struct dl_bbuf {
	unsigned char *dlb_data;
	int dlb_flags;
	int dlb_pos;
	int dlb_limit;
	int dlb_capacity;
};

static const int DL_BBUF_USRFLAGMASK = (DL_BBUF_AUTOEXTEND | DL_BBUF_FIXEDLEN |  DL_BBUF_BIGENDIAN | DL_BBUF_LITTLEENDIAN);
static const int DL_BBUF_MINEXTENDSIZE = 16;
static const int DL_BBUF_MAXEXTENDSIZE = PAGE_SIZE;
static const int DL_BBUF_MAXEXTENDINC = PAGE_SIZE;

static void dl_bbuf_assert_integrity(const char *, struct dl_bbuf *);
static int dl_bbuf_extend(struct dl_bbuf *, int);
static int dl_bbuf_extendsize(int);

#ifdef _KERNEL
static inline void
dl_bbuf_assert_integrity(const char *func, struct dl_bbuf *self)
#else
static inline void
dl_bbuf_assert_integrity(const char *func __attribute((unused)),
    struct dl_bbuf *self)
#endif
{

	DL_ASSERT(self != NULL, ("%s called with NULL dl_buf instance", func)); 
	DL_ASSERT(self->dlb_data != NULL,
	    ("%s called with unititialised of corrupt dl_buf", func)); 
	DL_ASSERT(self->dlb_pos <= self->dlb_capacity,
	    ("wrote past the end of the dl_buf (%d >= %d)",
	    self->dlb_pos, self->dlb_capacity)); 
}

static int
dl_bbuf_extendsize(int len)
{
	int newlen = DL_BBUF_MINEXTENDSIZE;

	DL_ASSERT(len > 0, ("New buffer length cannot be <= 0."));

	while (newlen < len) {
		if (newlen < DL_BBUF_MAXEXTENDSIZE)
			newlen *= 2;
		else
			newlen += DL_BBUF_MAXEXTENDINC;
	}

	DL_ASSERT(newlen > 0, ("New buffer length cannot be <= 0."));
	return newlen;
}

static int
dl_bbuf_extend(struct dl_bbuf *self, int addlen)
{
	unsigned char *newbuf;
	int newlen;
	
	dl_bbuf_assert_integrity(__func__, self);

	newlen = dl_bbuf_extendsize(self->dlb_capacity + addlen);
	newbuf = (unsigned char *) dlog_alloc(newlen);
#ifdef _KERNEL
	DL_ASSERT(newbuf != NULL, ("Failed to reallocate dl_bbuf.\n"));
	{
#else
	if (newbuf != NULL) {
#endif
		bcopy(self->dlb_data, newbuf, self->dlb_capacity);
		dlog_free(self->dlb_data);
		self->dlb_data = newbuf;
		self->dlb_capacity = newlen;
		self->dlb_limit = newlen;
		dl_bbuf_assert_integrity(__func__, self);
		return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed to reallocate dl_bbuf.\n");
	return -1;	
}

void
dl_bbuf_delete(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
        if ((self->dlb_flags & DL_BBUF_EXTERNBUF) == 0)
		dlog_free(self->dlb_data);
	dlog_free(self);
}

int
dl_bbuf_new(struct dl_bbuf **self, unsigned char *buf, int capacity, int flags)
{
	struct dl_bbuf *newbuf;

	DL_ASSERT(capacity >= 0,
	    ("attempt to create a dl_buf of negative length (%d)",
	    capacity));
	DL_ASSERT((flags & ~DL_BBUF_USRFLAGMASK) == 0,
	    ("%s called with invalid flags", __func__));

	flags &= DL_BBUF_USRFLAGMASK;

	newbuf = (struct dl_bbuf *) dlog_alloc(sizeof(struct dl_bbuf));
#ifdef _KERNEL
	DL_ASSERT(newbuf != NULL, ("Failed to allocate dl_buf.\n"));
	{
#else
	if (newbuf != NULL) {
#endif
		newbuf->dlb_flags = flags;
		newbuf->dlb_capacity = capacity;
		newbuf->dlb_limit = capacity;
		newbuf->dlb_pos = 0;

		if (buf == NULL)  {
			newbuf->dlb_data = (unsigned char *) dlog_alloc(
			    capacity);
#ifdef _KERNEL
			DL_ASSERT(newbuf->dlb_data != NULL,
			    ("Failed to allocate dl_bbuf.\n"));
			{
#else
			if (newbuf->dlb_data == NULL) {

				dlog_free(newbuf);
				goto err;
#endif
			}
		} else {
			newbuf->dlb_data = buf;
			newbuf->dlb_flags |=
			    (DL_BBUF_EXTERNBUF | DL_BBUF_FIXEDLEN);
		}
			
		/* dl_bbuf constructed successfully. */
		*self = newbuf;
		return 0;
	}

#ifndef _KERNEL
err:	
	DLOGTR0(PRIO_HIGH, "Failed to allocate dl_bbuf.\n");
	*self = NULL;
	return -1;
#endif
}

int
dl_bbuf_new_auto(struct dl_bbuf **buffer)
{

	return dl_bbuf_new(buffer, NULL, DL_BBUF_MINEXTENDSIZE,
	    DL_BBUF_AUTOEXTEND);
}

int
dl_bbuf_bcat(struct dl_bbuf *self, unsigned char const * const source, int len)
{
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);

	if (self->dlb_pos + len > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			add_len = (self->dlb_pos + len) -
			    self->dlb_capacity;
			if (dl_bbuf_extend(self, add_len) != 0)
				return -1;
		} else {
			return -1;
		}	
	}

	bcopy(source, &self->dlb_data[self->dlb_pos], len);
	self->dlb_pos += len;
	self->dlb_data[self->dlb_pos]=0;
	return 0;
}

int
dl_bbuf_scat(struct dl_bbuf *self, struct sbuf *source)
{
	dl_bbuf_assert_integrity(__func__, self);
	DL_ASSERT(source != NULL, ("Source sbuf cannot be NULL"));

	dl_bbuf_bcat(self, (unsigned char *)  sbuf_data(source),
	    sbuf_len(source));
	return 0;
}

void
dl_bbuf_clear(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	self->dlb_pos = 0;
}

int
dl_bbuf_concat(struct dl_bbuf *self, struct dl_bbuf *source)
{

	dl_bbuf_assert_integrity(__func__, self);
	dl_bbuf_assert_integrity(__func__, source);

	if (self->dlb_pos + source->dlb_pos >
	    self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, source->dlb_capacity) != 0)
				return -1;
		} else {
			return -1;
		}	
	}
	bcopy(source->dlb_data,
	    &self->dlb_data[self->dlb_pos], source->dlb_pos);
	self->dlb_pos += source->dlb_pos;
	return 0;
}

unsigned char *
dl_bbuf_data(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_data;
}

dl_bbuf_flags
dl_bbuf_get_flags(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_flags;
}

int
dl_bbuf_flip(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	self->dlb_limit = self->dlb_pos;
	self->dlb_pos = 0;
	return 0;
}

int
dl_bbuf_len(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_limit;
}

int
dl_bbuf_pos(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_pos;
}

int
dl_bbuf_get_int8(struct dl_bbuf *self, int8_t * const value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(int8_t)) <= self->dlb_limit) {

		*value = self->dlb_data[self->dlb_pos++];
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_uint8(struct dl_bbuf *self, uint8_t * const value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(uint8_t)) <= self->dlb_limit) {

		*value = self->dlb_data[self->dlb_pos++];
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int16(struct dl_bbuf *self, int16_t *value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(int16_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8)); 
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_uint16(struct dl_bbuf *self, uint16_t *value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(uint16_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8)); 
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int32(struct dl_bbuf *self, int32_t *value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(int32_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_uint32(struct dl_bbuf *self, uint32_t *value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(uint32_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int64(struct dl_bbuf *self, int64_t *value)
{
	int l, h;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(int64_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			h =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
			l = 
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
			*value = (((uint64_t) h) << 32L) |
			    (((long) l) & 0xFFFFFFFFL);
		} else {
			l =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
			h =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
			*value = (((uint64_t) h) << 32L) |
			    (((uint64_t) l) & 0xFFFFFFFFL);
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_uint64(struct dl_bbuf *self, uint64_t *value)
{
	int l, h;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (self->dlb_pos + sizeof(uint64_t)) <= self->dlb_limit) {

		if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
			h =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
			l = 
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 24) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 0));
			*value = (((uint64_t) h) << 32L) |
			    (((long) l) & 0xFFFFFFFFL);
		} else {
			l =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
			h =
			    (((self->dlb_data[self->dlb_pos++] & 0xFF) << 0) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 8) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 16) |
			    ((self->dlb_data[self->dlb_pos++] & 0xFF) << 24));
			*value = (((uint64_t) h) << 32L) |
			    (((uint64_t) l) & 0xFFFFFFFFL);
		}
		return 0;
	}
	return -1;
}


int
dl_bbuf_put_int8_at(struct dl_bbuf *self, int8_t value, int pos)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(int8_t)) > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, (int) sizeof(int8_t)) != 0)
				return -1;
		} else {
			return -1;
		}
	}
	self->dlb_data[pos++] = value;
	return 0;
}

int
dl_bbuf_put_int8(struct dl_bbuf *self, int8_t value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int8_at(self, value, self->dlb_pos) == 0) {

		self->dlb_pos += sizeof(int8_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_uint8_at(struct dl_bbuf *self, uint8_t value, int pos)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(uint8_t)) > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, (int) sizeof(uint8_t)) != 0)
				return -1;
		} else {
			return -1;
		}
	}
	self->dlb_data[pos++] = value;
	return 0;
}

int
dl_bbuf_put_uint8(struct dl_bbuf *self, uint8_t value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int8_at(self, value, self->dlb_pos) == 0) {

		self->dlb_pos += sizeof(int8_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int16_at(struct dl_bbuf *self, int16_t value, int pos)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(int16_t)) > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, (int) sizeof(int16_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int16(struct dl_bbuf *self, int16_t value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int16_at(self, value, self->dlb_pos) == 0) {

		self->dlb_pos += sizeof(int16_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int32_at(struct dl_bbuf *self, int32_t value, int pos)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(int32_t)) > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, (int) sizeof(int32_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
		self->dlb_data[pos++] = (value >> 24) & 0xFF;
		self->dlb_data[pos++] = (value >> 16) & 0xFF;
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
		self->dlb_data[pos++] = (value >> 16) & 0xFF;
		self->dlb_data[pos++] = (value >> 24) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int32(struct dl_bbuf *self, int32_t value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int32_at(self, value, self->dlb_pos) == 0) {

		self->dlb_pos += sizeof(int32_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int64_at(struct dl_bbuf *self, int64_t value, int pos)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(int64_t)) > self->dlb_capacity) {

		if (self->dlb_flags & DL_BBUF_AUTOEXTEND) {

			if (dl_bbuf_extend(self, (int) sizeof(int64_t)) != 0)
			    return -1;
		} else {
			return -1;
		}
	}

	if (self->dlb_flags & DL_BBUF_BIGENDIAN) {
		self->dlb_data[pos++] = (value >> 56) & 0xFF;
		self->dlb_data[pos++] = (value >> 48) & 0xFF;
		self->dlb_data[pos++] = (value >> 40) & 0xFF;
		self->dlb_data[pos++] = (value >> 32) & 0xFF;
		self->dlb_data[pos++] = (value >> 24) & 0xFF;
		self->dlb_data[pos++] = (value >> 16) & 0xFF;
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
	} else {
		self->dlb_data[pos++] = (value >> 0) & 0xFF;
		self->dlb_data[pos++] = (value >> 8) & 0xFF;
		self->dlb_data[pos++] = (value >> 16) & 0xFF;
		self->dlb_data[pos++] = (value >> 24) & 0xFF;
		self->dlb_data[pos++] = (value >> 32) & 0xFF;
		self->dlb_data[pos++] = (value >> 40) & 0xFF;
		self->dlb_data[pos++] = (value >> 48) & 0xFF;
		self->dlb_data[pos++] = (value >> 56) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int64(struct dl_bbuf *self, int64_t value)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int64_at(self, value, self->dlb_pos) == 0) {

		self->dlb_pos += sizeof(int64_t);	
		return 0;
	}
	return -1;
}

