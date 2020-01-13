/*-
 * Copyright (c) 2019-2018 (Graeme Jenkinson)
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

#ifndef _BBUF_H
#define _BBUF_H

#include <sys/types.h>
#include <sys/sbuf.h>

#ifndef _KERNEL
#include <stdint.h>
#include <syslog.h>
#include <pthread.h>
#endif

typedef void * (* bbuf_malloc_func)(unsigned long);
typedef void (* bbuf_free_func)(void *);

enum bbuf_flags {
	BBUF_AUTOEXTEND = 0x01 << 0,
	BBUF_FIXEDLEN = 0x01 << 1,
	BBUF_EXTERNBUF = 0x01 << 2,
	BBUF_BIGENDIAN = 0x01 << 3,
	BBUF_LITTLEENDIAN = 0x01 << 4
};
typedef enum bbuf_flags bbuf_flags;

struct bbuf;

#ifdef _KERNEL
#define DLOGTR0(event_mask, format) \
	log(event_mask, format)
#define DLOGTR1(event_mask, format, p1) \
	log(event_mask, format, p1)
#define DLOGTR2(event_mask, format, p1, p2) \
	log(event_mask, format, p1, p2)
#define DLOGTR3(event_mask, format, p1, p2, p3) \
	log(event_mask, format, p1, p2, p3)
#define DLOGTR4(event_mask, format, p1, p2, p3, p4) \
	log(event_mask, format, p1, p2, p3, p4)
#define DLOGTR5(event_mask, format, p1, p2, p3, p4, p5) \
	log(event_mask, format, p1, p2, p3, p4, p5)
#define DLOGTR6(event_mask, format, p1, p2, p3, p4, p5, p6) \
	log(event_mask, format, p1, p2, p3, p4, p5, p6)
#else
#define DLOGTR0(event_mask, format) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self())
#define DLOGTR1(event_mask, format, p1) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1)
#define DLOGTR2(event_mask, format, p1, p2) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1, p2)
#define DLOGTR3(event_mask, format, p1, p2, p3) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1, p2, p3)
#define DLOGTR4(event_mask, format, p1, p2, p3, p4) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1, p2, p3, p4)
#define DLOGTR5(event_mask, format, p1, p2, p3, p4, p5) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1, p2, p3, p4, p5)
#define DLOGTR6(event_mask, format, p1, p2, p3, p4, p5, p6) \
	syslog(event_mask, "[%08X] " format, (uint32_t) pthread_self(), \
	p1, p2, p3, p4, p5, p66)
#endif /* KERNEL */

#define PRIO_HIGH   3 //LOG_ERR
#define PRIO_NORMAL 5 //LOG_NOTICE
#define PRIO_LOW    7 //LOG_DEBUG

extern const bbuf_malloc_func bbuf_alloc;
extern const bbuf_free_func bbuf_free;

extern void bbuf_delete(struct bbuf *);
extern int bbuf_new(struct bbuf **, unsigned char *, size_t, int);
extern int bbuf_new_auto(struct bbuf **);
extern int bbuf_bcat(struct bbuf *, unsigned char const * const, size_t);
extern int bbuf_bcat_aligned(struct bbuf *, unsigned char const * const,
    size_t, size_t);
extern int bbuf_scat(struct bbuf *, struct sbuf *);
extern void bbuf_clear(struct bbuf *);
extern int bbuf_concat(struct bbuf *, struct bbuf *);
extern unsigned char * bbuf_data(struct bbuf *);
extern bbuf_flags bbuf_get_flags(struct bbuf const *);
extern int bbuf_flip(struct bbuf *);
extern int bbuf_get_int8(struct bbuf * const, int8_t * const);
extern int bbuf_get_uint8(struct bbuf * const, uint8_t * const);
extern int bbuf_get_int16(struct bbuf * const, int16_t * const);
extern int bbuf_get_uint16(struct bbuf * const, uint16_t * const);
extern int bbuf_get_int32(struct bbuf * const, int32_t * const);
extern int bbuf_get_uint32(struct bbuf * const, uint32_t * const);
extern int bbuf_get_int64(struct bbuf * const, int64_t * const);
extern int bbuf_get_uint64(struct bbuf * const, uint64_t * const);
extern size_t bbuf_len(struct bbuf *);
extern size_t bbuf_pos(struct bbuf *);
extern size_t bbuf_pos_aligned(struct bbuf *, size_t);
extern int bbuf_put_int8(struct bbuf *, int8_t);
extern int bbuf_put_int8_at(struct bbuf *, int8_t, size_t);
extern int bbuf_put_uint8(struct bbuf *, uint8_t);
extern int bbuf_put_uint8_at(struct bbuf *, uint8_t, size_t);
extern int bbuf_put_int16(struct bbuf *, int16_t);
extern int bbuf_put_int16_at(struct bbuf *, int16_t, size_t);
extern int bbuf_put_int32(struct bbuf *, int32_t);
extern int bbuf_put_int32_as_varint(struct bbuf *, int32_t);
extern int bbuf_put_int32_at(struct bbuf *, int32_t, size_t);
extern int bbuf_put_int64(struct bbuf *, int64_t);
extern int bbuf_put_int64_at(struct bbuf *, int64_t, size_t);

#endif
