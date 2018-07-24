/* crypto/bio/bss_sock.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
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
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <errno.h>
#define USE_SOCKETS
#include "cryptlib.h"

#ifndef OPENSSL_NO_SOCK

# include <openssl/bio.h>

# ifdef WATT32
#  define sock_write SockWrite  /* Watt-32 uses same names */
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockbuf_tls.h>
#include <crypto/cryptodev.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    sock_write,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets, */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,
};

BIO_METHOD *BIO_s_socket(void)
{
    return (&methods_sockp);
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int sock_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return (1);
}

static int sock_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if (a->init) {
            SHUTDOWN2(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return (1);
}

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return (ret);
}

static int send_ctrl_message(int fd, unsigned char record_type,
        const void *data, size_t length)
{
    struct msghdr msg = {0};
    int cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(cmsg_len)];
    struct iovec msg_iov;   /* Vector of data to send/receive into */

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
#if defined(TCP_TLS_ENABLE)
    cmsg->cmsg_level = IPPROTO_TCP;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
#endif
    cmsg->cmsg_len = CMSG_LEN(cmsg_len);
    *((unsigned char *)CMSG_DATA(cmsg)) = record_type;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = (void *)data;
    msg_iov.iov_len = length;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret;

    clear_socket_error();
    if (BIO_should_offload_tx_ctrl_msg_flag(b)) {
        unsigned char record_type = (unsigned char)(uintptr_t)b->ptr;

#ifdef SSL_DEBUG
        printf("\nsending ctrl msg, type = %d, len = %d\n", record_type, inl);
#endif
        BIO_clear_offload_tx_ctrl_msg_flag(b);
        ret = send_ctrl_message(b->num, record_type, in, inl);
        if (ret >= 0) {
            ret = inl;
        }
    } else {
#ifdef SSL_DEBUG
        printf("\nsending data msg %p %d\n", b, b->flags);
#endif
        ret = writesocket(b->num, in, inl);
    }
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return (ret);
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
#if defined(TCP_TLS_ENABLE)
    struct tls_so_enable *tls_en;
#endif

    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
#if defined(TCP_TLS_ENABLE)
    case BIO_CTRL_SET_OFFLOAD_TX:
	tls_en = ptr;
	ret = setsockopt(b->num, IPPROTO_TCP, TCP_TLS_ENABLE,
			 tls_en, sizeof(*tls_en));
#ifdef SSL_DEBUG
        printf("\nAttempt to offload...");
#endif
        if (!ret) {
            BIO_set_offload_tx_flag(b);
#ifdef SSL_DEBUG
            printf("Success %p %p\n", b, &(b->flags));
#endif
        } else {
#ifdef SSL_DEBUG
            printf("Failed ret=%ld\n", ret);
#endif
        }
        break;
     case BIO_CTRL_GET_OFFLOAD_TX:
         return BIO_should_offload_tx_flag(b);
     case BIO_CTRL_SET_OFFLOAD_TX_CTRL_MSG:
         BIO_set_offload_tx_ctrl_msg_flag(b);
	 b->ptr = (void *)num;
         ret = 0;
         break;
     case BIO_CTRL_CLEAR_OFFLOAD_TX_CTRL_MSG:
         BIO_clear_offload_tx_ctrl_msg_flag(b);
         ret = 0;
         break;
#endif
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = sock_write(bp, str, n);
    return (ret);
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

# if defined(OPENSSL_SYS_WINDOWS) && 0/* more microsoft stupidity? perhaps
                                       * not? Ben 4/1/99 */
        if ((i == -1) && (err == 0))
            return (1);
# endif

        return (BIO_sock_non_fatal_error(err));
    }
    return (0);
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_NETWARE)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif

#  if 0                         /* This appears to always be an error */
#   if defined(WSAENOTCONN)
    case WSAENOTCONN:
#   endif
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return (1);
        /* break; */
    default:
        break;
    }
    return (0);
}

#endif                          /* #ifndef OPENSSL_NO_SOCK */
