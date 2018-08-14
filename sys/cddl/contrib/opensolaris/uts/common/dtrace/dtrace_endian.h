/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Thomas Moestl <tmm@FreeBSD.org>
 * Copyright (c) 2018 Graeme Jenkinson <gcj21@cl.cam.ac.uk>
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
 * $FreeBSD$
 */

#ifndef _DTRACE_ENDIAN_H_
#define _DTRACE_ENDIAN_H_

#include <sys/cdefs.h>
#include <sys/_types.h>

#include <sys/dtrace_endian.h>

#ifndef _UINT8_T_DECLARED
typedef	__uint8_t	uint8_t;
#define	_UINT8_T_DECLARED
#endif
 
#ifndef _UINT16_T_DECLARED
typedef	__uint16_t	uint16_t;
#define	_UINT16_T_DECLARED
#endif
 
#ifndef _UINT32_T_DECLARED
typedef	__uint32_t	uint32_t;
#define	_UINT32_T_DECLARED
#endif
 
#ifndef _UINT64_T_DECLARED
typedef	__uint64_t	uint64_t;
#define	_UINT64_T_DECLARED
#endif
 
/*
 * General byte order swapping functions.
 */
#define	dtrace_bswap16(x)	__dtrace_bswap16(x)
#define	dtrace_bswap32(x)	__dtrace_bswap32(x)
#define	dtrace_bswap64(x)	__dtrace_bswap64(x)

/*
 * Host to big endian, host to little endian, big endian to host, and little
 * endian to host byte order functions as detailed in byteorder(9).
 */
#if _BYTE_ORDER == _LITTLE_ENDIAN
#define	dtrace_htobe16(x)	dtrace_bswap16((x))
#define	dtrace_htobe32(x)	dtrace_bswap32((x))
#define	dtrace_htobe64(x)	dtrace_bswap64((x))
#define	dtrace_htole16(x)	((uint16_t)(x))
#define	dtrace_htole32(x)	((uint32_t)(x))
#define	dtrace_htole64(x)	((uint64_t)(x))

#define	dtrace_be16toh(x)	dtrace_bswap16((x))
#define	dtrace_be32toh(x)	dtrace_bswap32((x))
#define	dtrace_be64toh(x)	dtrace_bswap64((x))
#define	dtrace_le16toh(x)	((uint16_t)(x))
#define	dtrace_le32toh(x)	((uint32_t)(x))
#define	dtrace_le64toh(x)	((uint64_t)(x))
#else /* _BYTE_ORDER != _LITTLE_ENDIAN */
#define	dtrace_htobe16(x)	((uint16_t)(x))
#define	dtrace_htobe32(x)	((uint32_t)(x))
#define	dtrace_htobe64(x)	((uint64_t)(x))
#define	dtrace_htole16(x)	dtrace_bswap16((x))
#define	dtrace_htole32(x)	dtrace_bswap32((x))
#define	dtrace_htole64(x)	dtrace_bswap64((x))

#define	dtrace_be16toh(x)	((uint16_t)(x))
#define	dtrace_be32toh(x)	((uint32_t)(x))
#define	dtrace_be64toh(x)	((uint64_t)(x))
#define	dtrace_le16toh(x)	dtrace_bswap16((x))
#define	dtrace_le32toh(x)	dtrace_bswap32((x))
#define	dtrace_le64toh(x)	dtrace_bswap64((x))
#endif /* _BYTE_ORDER == _LITTLE_ENDIAN */

/* Alignment-agnostic encode/decode bytestream to/from little/big endian. */

static __inline uint16_t
dtrace_be16dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return ((p[0] << 8) | p[1]);
}

static __inline uint32_t
dtrace_be32dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return (((unsigned)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static __inline uint64_t
dtrace_be64dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return (((uint64_t)dtrace_be32dec(p) << 32) | dtrace_be32dec(p + 4));
}

static __inline uint16_t
dtrace_le16dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return ((p[1] << 8) | p[0]);
}

static __inline uint32_t
dtrace_le32dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return (((unsigned)p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);
}

static __inline uint64_t
dtrace_le64dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return (((uint64_t)dtrace_le32dec(p + 4) << 32) | dtrace_le32dec(p));
}

static __inline void
dtrace_be16enc(void *pp, uint16_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = (u >> 8) & 0xff;
	p[1] = u & 0xff;
}

static __inline void
dtrace_be32enc(void *pp, uint32_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = (u >> 24) & 0xff;
	p[1] = (u >> 16) & 0xff;
	p[2] = (u >> 8) & 0xff;
	p[3] = u & 0xff;
}

static __inline void
dtrace_be64enc(void *pp, uint64_t u)
{
	uint8_t *p = (uint8_t *)pp;

	dtrace_be32enc(p, (uint32_t)(u >> 32));
	dtrace_be32enc(p + 4, (uint32_t)(u & 0xffffffffU));
}

static __inline void
dtrace_le16enc(void *pp, uint16_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = u & 0xff;
	p[1] = (u >> 8) & 0xff;
}

static __inline void
dtrace_le32enc(void *pp, uint32_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = u & 0xff;
	p[1] = (u >> 8) & 0xff;
	p[2] = (u >> 16) & 0xff;
	p[3] = (u >> 24) & 0xff;
}

static __inline void
dtrace_le64enc(void *pp, uint64_t u)
{
	uint8_t *p = (uint8_t *)pp;

	dtrace_le32enc(p, (uint32_t)(u & 0xffffffffU));
	dtrace_le32enc(p + 4, (uint32_t)(u >> 32));
}

#endif	/* _DTRACE_ENDIAN_H_ */
