/*-
 * Copyright (c) 2014
 *	Netflix Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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
#ifndef _SYS_SOCKBUF_TLS_H_
#define _SYS_SOCKBUF_TLS_H_
#include <sys/types.h>

struct tls_record_layer {
	uint8_t  tls_type;
	uint8_t  tls_vmajor;
	uint8_t  tls_vminor;
	uint16_t tls_length;	
	uint8_t  tls_data[0];
} __attribute__ ((packed));

#define TLS_MAX_MSG_SIZE_V10_2	16384
#define TLS_MAX_PARAM_SIZE	1024	/* Max key/mac/iv in sockopt */
#define TLS_AEAD_GCM_LEN	4

/* Type values for the record layer */
#define TLS_RLTYPE_APP		23

/*
 * Constants for the Socket Buffer TLS state flags (sb_tls_flags).
 */
#define	SB_TLS_ACTIVE		0x0001	/* set if SO_CRYPT_TLS is enabled. */
#define	SB_TLS_CRY_INI		0x0002  /* state being initialized */
#define	SB_TLS_RECV_SIDE	0x0004	/* rx (decrypt/decapsulate) */
#define	SB_TLS_SEND_SIDE	0x0008	/* tx (encrypt/encapsulate) */

/*
 * Alert protoocol
 */
struct tls_alert_protocol {
	uint8_t	level;
	uint8_t desc;
} __attribute__ ((packed)); 

/*
 * AEAD nonce for GCM data.
 */
struct tls_nonce_data {
	uint8_t fixed[TLS_AEAD_GCM_LEN];
	uint64_t seq;
} __attribute__ ((packed)); 

/*
 * AEAD added data format per RFC.
 */
struct tls_aead_data {
	uint64_t seq;	/* In network order */
	uint8_t type;
	uint8_t  tls_vmajor;
	uint8_t  tls_vminor;
	uint16_t tls_length;	
} __attribute__ ((packed));

/*
 * Stream Cipher MAC input not sent on wire
 * but put into the MAC.
 */
struct tls_mac_data {
	uint64_t seq;
	uint8_t type;
	uint8_t  tls_vmajor;
	uint8_t  tls_vminor;
	uint16_t tls_length;	
} __attribute__ ((packed));

/* Not used but here is the layout
 * of what is on the wire for
 * a TLS record that is a stream cipher.
 *
struct tls_ss_format {
	uint8_t IV[record_iv_len]; TLS pre 1.1 this is missing.
	uint8_t content[len];
	uint8_t MAC[maclen];
	uint8_t padding[padlen];
	uint8_t padlen;
};
*
* We don't support in-kernel pre-1.1 TLS so if the
* user requests that, we error during SO_TLS_ENABLE.
* Each pad byte in padding must contain the same value
* as padlen. Also note that content <-> padlen should
* be mod 0 to the blocklen of the cipher. I am guessing
* the IV is a length of the multiple of the cipher as
* well.
*/

#define TLS_MAJOR_VER_ONE	3
#define TLS_MINOR_VER_ZERO	1	/* 3, 1 */
#define TLS_MINOR_VER_ONE	2	/* 3, 2 */
#define TLS_MINOR_VER_TWO	3	/* 3, 3 */

struct sockopt;
struct uio;

/* For TCP_TLS_ENABLE */
struct tls_so_enable {
	const uint8_t *hmac_key;
	const uint8_t *crypt;
	const uint8_t *iv;
	uint32_t crypt_algorithm; /* e.g. CRYPTO_AES_CBC */
	uint32_t mac_algorthim;	  /* e.g. CRYPTO_SHA2_256_HMAC */
	uint32_t key_size;	  /* Length of the key */
	int hmac_key_len;
	int crypt_key_len;
	int iv_len;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
};

struct tls_kern_params {
	uint8_t *hmac_key;
	uint8_t *crypt;
	uint8_t *iv;
	uint16_t hmac_key_len;
	uint16_t crypt_key_len;
	uint16_t iv_len;
	uint16_t sb_maxlen;
	uint8_t sb_tls_vmajor;
	uint8_t sb_tls_vminor;
	uint8_t sb_tls_hlen;
	uint8_t sb_tls_tlen;
	uint8_t sb_tls_bs;
};

#define SBTLS_T_TYPE_OCFW		1	/* Open Crypto Framework */
#define SBTLS_T_TYPE_BSSL		2	/* Boring SSL */
#define SBTLS_T_TYPE_INTELISA_GCM	3	/* Intel ISA AES GCM */

#define SBTLS_INTELISA_AEAD_TAGLEN	16
#define SBTLS_INTELISA_CBC_TAGLEN	16
#ifdef _KERNEL

#include <sys/malloc.h>

MALLOC_DECLARE(M_TLSSOBUF);

#define SBTLS_API_VERSION 4

struct sbtls_info;
struct iovec;

struct sbtls_crypto_backend {
	LIST_ENTRY(sbtls_crypto_backend) next;
	void (*setup_cipher) (struct sbtls_info *tls, int *err);
	int (*try) (struct socket *so,
	    struct tls_so_enable *en, int *error);
	void (*clean_cipher) (struct sbtls_info *tls, void *cipher);
	int prio;
	int api_version;
	int use_count;                  /* dev testing */
	const char *name;
};

struct sbtls_info {
	int	(*sb_tls_crypt)(struct sbtls_info *tls,
	    struct tls_record_layer *hdr, uint8_t *trailer,
	    struct iovec *src, struct iovec *dst, int iovcnt,
	    uint64_t seqno);
	void *cipher;
	struct tls_kern_params sb_params;
	uint16_t sb_tsk_instance;	/* For task selection */
	struct sbtls_crypto_backend *be;/* backend crypto impl. */
	uint8_t t_type; 	 	/* Flags indicating type of encode */
	uint8_t taglen;                 /* for CBC tag padding */
} __aligned(CACHE_LINE_SIZE);


#ifndef KERN_TLS
#include "opt_kern_tls.h"
#endif

#ifndef KERN_TLS

/* TLS stubs so we can compile kernels without options KERN_TLS */

static inline int
sbtls_crypt_tls_enable(struct socket *so,
    struct tls_so_enable *en)
{
	return (ENOTSUP);
}

static inline void
sbtlsdestroy(struct sockbuf *sb)
{
}

static inline int
sbtls_frame(struct mbuf **m, struct sbtls_info *tls, int *enqueue_cnt,
    uint8_t record_type)
{
	return (ENOTSUP);
}

static inline void
sbtls_enqueue(struct mbuf *m, struct socket *so, int page_count)
{
}

static inline void
sbtls_seq(struct sockbuf *sb, struct mbuf *m)
{
}
#else

int sbtls_crypto_backend_register(struct sbtls_crypto_backend *be);
int sbtls_crypto_backend_deregister(struct sbtls_crypto_backend *orig_be);
int sbtls_crypt_tls_enable(struct socket *so, struct tls_so_enable *en);
void sbtlsdestroy(struct sockbuf *sb);
struct sbtls_info *sbtls_init_sb_tls(struct socket *so,
    struct tls_so_enable *en, size_t cipher_len);
void sbtls_free_tls(struct sbtls_info *tls);
int sbtls_frame(struct mbuf **m, struct sbtls_info *tls, int *enqueue_cnt,
    uint8_t record_type);
void sbtls_seq(struct sockbuf *sb, struct mbuf *m);
void sbtls_enqueue(struct mbuf *m, struct socket *so, int page_count);


#endif /* KERN_TLS */
#endif /* _KERNEL */
#endif /* _SYS_SOCKBUF_TLS_H_ */
