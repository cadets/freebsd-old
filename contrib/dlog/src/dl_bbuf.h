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

#ifndef _DL_BBUF_H
#define _DL_BBUF_H

#include <sys/types.h>
#include <sys/sbuf.h>

#ifndef _KERNEL
#include <stdint.h>
#endif

enum dl_bbuf_flags {
	DL_BBUF_AUTOEXTEND = 0x01 << 0,
	DL_BBUF_FIXEDLEN = 0x01 << 1,
	DL_BBUF_EXTERNBUF = 0x01 << 2,
	DL_BBUF_BIGENDIAN = 0x01 << 3,
	DL_BBUF_LITTLEENDIAN = 0x01 << 4
};
typedef enum dl_bbuf_flags dl_bbuf_flags;

struct dl_bbuf;

extern void dl_bbuf_delete(struct dl_bbuf *);
extern int dl_bbuf_new(struct dl_bbuf **, unsigned char *, int, int);
extern int dl_bbuf_new_auto(struct dl_bbuf **);
extern int dl_bbuf_bcat(struct dl_bbuf *, unsigned char const * const, int);
extern int dl_bbuf_scat(struct dl_bbuf *, struct sbuf *);
extern void dl_bbuf_clear(struct dl_bbuf *);
extern int dl_bbuf_concat(struct dl_bbuf *, struct dl_bbuf *);
extern unsigned char * dl_bbuf_data(struct dl_bbuf *);
extern dl_bbuf_flags dl_bbuf_get_flags(struct dl_bbuf *);
extern int dl_bbuf_flip(struct dl_bbuf *);
extern int dl_bbuf_get_int8(struct dl_bbuf *, int8_t * const);
extern int dl_bbuf_get_uint8(struct dl_bbuf *, uint8_t * const);
extern int dl_bbuf_get_int16(struct dl_bbuf *, int16_t *);
extern int dl_bbuf_get_uint16(struct dl_bbuf *, uint16_t *);
extern int dl_bbuf_get_int32(struct dl_bbuf *, int32_t *);
extern int dl_bbuf_get_uint32(struct dl_bbuf *, uint32_t *);
extern int dl_bbuf_get_int64(struct dl_bbuf *, int64_t *);
extern int dl_bbuf_get_uint64(struct dl_bbuf *, uint64_t *);
extern int dl_bbuf_len(struct dl_bbuf *);
extern int dl_bbuf_pos(struct dl_bbuf *);
extern int dl_bbuf_put_int8(struct dl_bbuf *, int8_t);
extern int dl_bbuf_put_int8_at(struct dl_bbuf *, int8_t, int);
extern int dl_bbuf_put_uint8(struct dl_bbuf *, uint8_t);
extern int dl_bbuf_put_uint8_at(struct dl_bbuf *, uint8_t, int);
extern int dl_bbuf_put_int16(struct dl_bbuf *, int16_t);
extern int dl_bbuf_put_int16_at(struct dl_bbuf *, int16_t, int);
extern int dl_bbuf_put_int32(struct dl_bbuf *, int32_t);
extern int dl_bbuf_put_int32_at(struct dl_bbuf *, int32_t, int);
extern int dl_bbuf_put_int64(struct dl_bbuf *, int64_t);
extern int dl_bbuf_put_int64_at(struct dl_bbuf *, int64_t, int);

#endif
