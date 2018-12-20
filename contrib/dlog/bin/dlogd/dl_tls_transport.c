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

#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <strings.h>
#include <stddef.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_config.h"
#include "dl_poll_reactor.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_transport.h"
#include "dl_tls_transport.h"
#include "dl_utils.h"

struct dl_tls_transport {
	BIO *dlt_tls_bio;
	SSL_CTX *dlt_tls_ctx;
};

/* Flags preventing negotiation of SSLv2 or v3 and
 * compression (See CRIME attack).
 */
static const long DLT_TLS_FLAGS = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
    SSL_OP_NO_COMPRESSION;

static const int DLT_TLS_POLL_TIMEOUT = 2000;

static dl_event_handler_handle dl_tls_get_transport_fd(void *);
static void dl_tls_transport_hdlr(void *, int, int);

static int dl_tls_transport_connect(struct dl_transport *,
    const char * const, const int);
static void dl_tls_transport_delete(struct dl_transport *);
static int dl_tls_transport_get_fd(struct dl_transport *);
static void dl_tls_transport_init(void) __attribute__((constructor));
static int dl_tls_transport_read_msg(struct dl_transport *,
    struct dl_bbuf **);
static int dl_tls_transport_send_request(struct dl_transport *,
    struct dl_bbuf const *);

#define CONST_CAST2(TOTYPE,FROMTYPE,X) ((__extension__(union {FROMTYPE _q; TOTYPE _nq;})(X))._nq)
#define CONST_CAST(TYPE,X) CONST_CAST2 (TYPE, const TYPE, (X))

static inline void
dl_tls_transport_check_integrity(struct dl_tls_transport *self)
{

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
	DL_ASSERT(self->dlt_tls_ctx != NULL,
	    ("Transport TSL context cannot be NULL"));
}

static void
dl_tls_transport_init(void)
{

	DLOGTR0(PRIO_LOW, "Initializing OpenSSL library\n");

	/* Initialise the libcrypto and libssl libraries:
	 * see: https://wiki.openssl.org.index.php/Library_Initialization
	 * SSL_library_init always returns 1, therefore, ignore
	 * the return code.
	 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	(void) SSL_library_init();
#else
	(void) OPENSSL_init_ssl(0, NULL);
#endif

	/* Load error strings from libcrypto and lib ssl. */
	SSL_load_error_strings();
}

static void
dl_tls_transport_delete(struct dl_transport *self)
{

	dl_tls_transport_check_integrity(self->dlt_tls);

	dl_poll_reactor_unregister(&self->dlt_event_hdlr);
	BIO_ssl_shutdown(self->dlt_tls->dlt_tls_bio);
	BIO_free_all(self->dlt_tls->dlt_tls_bio);
	SSL_CTX_free(self->dlt_tls->dlt_tls_ctx);
	dlog_free(self->dlt_tls);
}

static int
dl_tls_transport_connect(struct dl_transport *self,
    const char * const hostname, const int port)
{
	SSL *ssl;
	int rc;

	dl_tls_transport_check_integrity(self->dlt_tls);
	DL_ASSERT(hostname != NULL, "Hostname to connect to cannot be NULL");

	self->dlt_tls->dlt_tls_bio = BIO_new_ssl_connect(
	    self->dlt_tls->dlt_tls_ctx);
	if (self->dlt_tls->dlt_tls_bio == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed creating new OpenSSL connectopn\n");
		return -1;
	}

	int fd, flags = 1;
	BIO_get_fd(self->dlt_tls->dlt_tls_bio, &fd);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

	/* Configure the hostname and port to connect to.
	 * (Note: These functions always return 1).
	 */
	BIO_set_conn_hostname(self->dlt_tls->dlt_tls_bio,
	    CONST_CAST(char *, hostname));
	BIO_set_conn_int_port(self->dlt_tls->dlt_tls_bio,
	    CONST_CAST(int *, &port));

	/* Setting SSL_MODE_AUTO_RETRY prevents the application from having
	 * to retry reads/writes in cases where the underlying transport
	 * is itself blocking.
	 */
	BIO_get_ssl(self->dlt_tls->dlt_tls_bio, &ssl);
	DL_ASSERT(ssl != NULL,
	    ("SSL pointer of transport BIO cannot be NULL"));
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* Negociate ciphers from the "high" encryption cipher suite,
	 * that is key lengths >= 128 bits.
	 */
	rc = SSL_set_cipher_list(ssl,
	    "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
	if (rc == 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to configure \"high\" cipher suite %d\n", rc);
		BIO_free_all(self->dlt_tls->dlt_tls_bio);
		return -1;
	}

	/* Configure OpenSSL to use non-blocking I/O. */
	BIO_set_nbio(self->dlt_tls->dlt_tls_bio, 1);

	/* Perform the non-blocking connect.
	 * (The underlying socket fd is polled for completion of the
	 * TCP three-way handshake. Before proceeding to undertake
	 * the TLS handshake.)
	 */
	rc = BIO_do_connect(self->dlt_tls->dlt_tls_bio);
	if (rc == 0 || (rc == -1 && errno == EINPROGRESS)) {

		self->dlt_event_hdlr.dleh_instance = self;
		self->dlt_event_hdlr.dleh_get_handle = dl_tls_get_transport_fd;
		self->dlt_event_hdlr.dleh_handle_event = dl_tls_transport_hdlr;

		dl_poll_reactor_register(&self->dlt_event_hdlr,
			POLLERR | POLLOUT | POLLHUP);
	}

	return rc;
}

static int
dl_tls_transport_read_msg(struct dl_transport *self,
    struct dl_bbuf **target)
{
	struct pollfd fds;
	const unsigned char *buffer;
	int32_t msg_size;
	int fd, rc, total = 0;
	
	dl_tls_transport_check_integrity(self->dlt_tls);
	DL_ASSERT(self->dlt_tls->dlt_tls_bio != NULL,
	    ("Transport TSL bio cannot be NULL"));
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");
	
retry_read_length:
	/* Read the size of the request or response to process. */
	rc = BIO_read(self->dlt_tls->dlt_tls_bio, &msg_size, sizeof(msg_size));
	if (rc <= 0) {
		if (BIO_should_retry(self->dlt_tls->dlt_tls_bio) != 0) {

			/* Poll on the socket until it is ready to retry. */
			BIO_get_fd(self->dlt_tls->dlt_tls_bio, &fd);

			fds.fd = fd;
			fds.events = POLLIN;
			rc = poll(&fds, 1, DLT_TLS_POLL_TIMEOUT);
			if (rc == -1) {

				DLOGTR1(PRIO_HIGH,
					"Error whilst polling on socket (%d)\n",
					errno);
			} else if (rc == 0) {

				/* Timeout whilst waiting on socket. */
				DLOGTR0(PRIO_NORMAL,
					"Timed out whilst attempting to resend.\n");
			} else {

				/* Socket is ready to write, retry. */
				goto retry_read_length;
			}
		}

		return -1;
	} else {
		DL_ASSERT(rc == sizeof(msg_size),
		    ("Number of bytes read does not match message size"));

		/* Successfully read the message size, now read the
		 * remainder of the message.
		 */
	 
		/* Convert the MessageSize from big endian into host
		 * endianess.
		 */
		msg_size = be32toh(msg_size);
		//DLOGTR1(PRIO_LOW, "Reading %d bytes...\n", msg_size);

		buffer = dlog_alloc(sizeof(unsigned char) * msg_size);
		if (buffer == NULL) {

			DLOGTR0(PRIO_HIGH,
			    "Error allocating buffer to store the message");
			return -1;
		}

		rc = dl_bbuf_new(target, NULL, msg_size,
			DL_BBUF_FIXEDLEN | DL_BBUF_BIGENDIAN);
		if (rc != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error allocating buffer to store the message");
			dlog_free(buffer);
			return -1;
		}

		while (total < msg_size) {
retry_read_msg:
			rc = BIO_read(self->dlt_tls->dlt_tls_bio, buffer,
			    msg_size-total);
			if (rc <= 0) {
				if (BIO_should_retry(
				    self->dlt_tls->dlt_tls_bio) != 0) {

					/* Poll on the socket until it is ready to retry. */
					BIO_get_fd(
					    self->dlt_tls->dlt_tls_bio, &fd);

					fds.fd = fd;
					fds.events = POLLIN;
					rc = poll(&fds, 1,
					    DLT_TLS_POLL_TIMEOUT);
					if (rc == -1) {

						DLOGTR1(PRIO_HIGH,
						    "Error whilst polling on "
						    "socket (%d)\n", errno);
					} else if (rc == 0) {

						/* Timeout whilst waiting on socket. */
						DLOGTR0(PRIO_NORMAL,
						  "Timed out whilst "
						  "attempting to resend.\n");
					} else {

						/* Socket is ready to read,
						 * retry.
						 */
						goto retry_read_msg;
					}
				}
			} else {

				total += rc;
				//DLOGTR2(PRIO_LOW,
				//    "\tRead %d characters; expected %d\n",
			//	    rc, msg_size);
				rc = dl_bbuf_bcat(*target, buffer, rc);
			}
		}
		dlog_free(buffer);

		/* Flip the target buffer allowing clients to read values
		 * from the beginning.
		 */
		dl_bbuf_flip(*target);

		/* Update the Producer statistics. */
		dl_producer_stats_bytes_received(self->dlt_producer, msg_size);
		return msg_size;
	}
}

static int
dl_tls_transport_send_request(struct dl_transport *self,
    const struct dl_bbuf *buffer)
{
	BIO *bio, *bio_buf;
	struct pollfd fds;
	int fd, rc;

	dl_tls_transport_check_integrity(self->dlt_tls);
	DL_ASSERT(self->dlt_tls->dlt_tls_bio != NULL,
	    ("Transport TSL bio cannot be NULL"));
	DL_ASSERT(buffer != NULL, "Buffer to send cannot be NULL");

	/* Create a BIO to buffer the write of the length of the buffer
	 * and it's contents.
	 */
	bio_buf = BIO_new(BIO_f_buffer());
	if (bio_buf == NULL) {

		DLOGTR0(PRIO_HIGH, "Error allocating BIO buffer\n");
		return -1;
	}

	rc = BIO_set_write_buffer_size(bio_buf, dl_bbuf_pos(buffer));
	if (rc == 0) {

		DLOGTR0(PRIO_HIGH, "Error setting BIO rite buffer size\n");
		/* Free the BIO used to buffer the request. */
		BIO_free(bio_buf);
		return -1;
	}
	
	bio = BIO_push(bio_buf, self->dlt_tls->dlt_tls_bio);
	if (bio == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "BIO_push in TlsTransport send_request failed\n");
		/* Free the BIO used to buffer the request. */
		BIO_free(bio_buf);
		return -1;
	}

	/* Convert the length of the buffer from host endianess to
	 * big endian.
	 */
	//DLOGTR1(PRIO_LOW, "Sending request (bytes= %u)\n",
	//    dl_bbuf_pos(buffer));

	rc = BIO_write(bio_buf, dl_bbuf_data(buffer), dl_bbuf_pos(buffer));
	if (rc <= 0) {

		DLOGTR0(PRIO_HIGH,
		    "BIO_write in TlsTransport send_request failed\n");
		/* Free the BIO used to buffer the request. */
		BIO_free(bio_buf);
		return -1;
	}

retry_flush:
	/* Flush the buffered data. */
	rc = BIO_flush(bio);
	if (rc <= 0) {
		
		if (BIO_should_retry(bio) != 0) {

			/* Poll on the socket until it is ready to retry. */
			BIO_get_fd(self->dlt_tls->dlt_tls_bio, &fd);

			fds.fd = fd;
			fds.events = POLLOUT;
			rc = poll(&fds, 1, DLT_TLS_POLL_TIMEOUT);
			if (rc == -1) {

				DLOGTR1(PRIO_HIGH,
				    "Error whilst polling on socket (%d)\n",
				    errno);
			} else if (rc == 0) {

				/* Timeout whilst waiting on socket. */
				DLOGTR0(PRIO_NORMAL,
				    "Timed out whilst attempting to resend.\n");
			} else {

				/* Socket is ready to write, retry. */
				goto retry_flush;
			}
		}

		DLOGTR0(PRIO_HIGH,
		    "BIO_flush in TlsTransport send_request failed\n");

		/* Free the BIO used to buffer the request. */
		BIO_free(bio_buf);
		return -1;
	}

	/* Update the Producer statistics. */
	dl_producer_stats_bytes_sent(self->dlt_producer,
	    dl_bbuf_pos(buffer));

	/* Free the BIO used to buffer the request. */
	BIO_free(bio_buf);

	return 0;
}

static void 
dl_tls_transport_hdlr(void *instance, int fd, int revents)
{
	struct dl_transport * const self = instance;
	struct dl_response_header *hdr;
	struct dl_bbuf *buffer;
	socklen_t len = sizeof(int);
	int rc, err = 0;
	
	dl_tls_transport_check_integrity(self->dlt_tls);

	if (revents & (POLLHUP | POLLERR)) {

		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (err == ECONNREFUSED) {
			DLOGTR0(PRIO_LOW, "Connection refused\n");
		}
		
		dl_producer_stats_tcp_connect(self->dlt_producer, false);
		dl_producer_down(self->dlt_producer);
		return;
	}

	if (revents & POLLIN) {

		rc = dl_transport_read_msg(self, &buffer);
		if (rc == 0) {

			/* No data to read. */
		} if (rc > 0) {

			/* Deserialise the response header. */
			if (dl_response_header_decode(&hdr, buffer) == 0) {
				//DLOGTR1(PRIO_LOW,
				//    "Got response id = : %d\n",
				//    hdr->dlrsh_correlation_id);

				/* Process the received response. */
				dl_producer_response(self->dlt_producer,
				    hdr);

				/* Free the response header
				 * TODO: implement dl_response_header_delete(header);
				 */
				dlog_free(hdr);
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Error decoding response header.\n");
			}

			/* Free the buffer in which the raw response was
			 * returned by the transport.
			 */
			dl_bbuf_delete(buffer);
		} else {

			/* Server disconnected. */
			dl_producer_stats_tcp_connect(self->dlt_producer,
			    false);
			dl_producer_down(self->dlt_producer);
			return;

		}
	}

	if (revents & POLLOUT) {

		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (rc == 0) {
			if (err == 0) {
				DLOGTR0(PRIO_LOW, "TCP Connected\n");
				dl_producer_stats_tcp_connect(self->dlt_producer,
				    true);

				/* Perform the SSL handshake.
				 * The BIO is non-blocking therefore it isxi
				 * necessary to poll for the successful
				 * completion of the handshake.
				 */
				rc = BIO_do_handshake(
				    self->dlt_tls->dlt_tls_bio);
				if (rc == 1) {
					/* Handshake has completed
					 * successsfuly.
					 */
					DLOGTR0(PRIO_LOW,
					    "TLS handshake succssful\n");

					/* Re-register the handler to trigger
					* when data is read to read
					* to when HANGUP or ERR is detected.
					*/
					dl_poll_reactor_unregister(
					    &self->dlt_event_hdlr);
					dl_poll_reactor_register(
					    &self->dlt_event_hdlr,
					    POLLIN|POLLHUP|POLLERR);

					dl_producer_stats_tls_connect(
					    self->dlt_producer, true);
					dl_producer_up(self->dlt_producer);
				} else if (rc == -1 &&
				    BIO_should_retry(
					self->dlt_tls->dlt_tls_bio) != 0) {

					DLOGTR0(PRIO_LOW,
					    "TLS handshake in progress\n");
					sleep(1);
				} else {
					DLOGTR0(PRIO_HIGH,
					    "Error establishing TLS handshake\n");
					dl_producer_stats_tcp_connect(
					    self->dlt_producer, false);
					dl_producer_down(self->dlt_producer);
				}
			} 
		} else {
			dl_producer_stats_tcp_connect(self->dlt_producer,
			    false);
			dl_producer_down(self->dlt_producer);
		}
	}
}

static dl_event_handler_handle
dl_tls_get_transport_fd(void *instance)
{
	struct dl_transport const * const self = instance;

	dl_tls_transport_check_integrity(self->dlt_tls);
	return dl_transport_get_fd(self);
}

static int
dl_tls_transport_get_fd(struct dl_transport *self)
{
	int fd;

	dl_tls_transport_check_integrity(self->dlt_tls);
	DL_ASSERT(self->dlt_tls->dlt_tls_bio != NULL,
	    ("Transport TSL bio cannot be NULL"));
	
	BIO_get_fd(self->dlt_tls->dlt_tls_bio, &fd);
	return fd;
}

int
dl_tls_transport_new(struct dl_transport **self, struct dl_producer *producer,
    nvlist_t *props)
{
	struct dl_transport *transport;
	struct dl_tls_transport *tls;
	SSL_METHOD *method;
	char *privkey_file, *client_file, *cacert_file, *password;
	int rc;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
	DL_ASSERT(producer != NULL, ("Producer instance cannot be NULL"));
	DL_ASSERT(props != NULL, ("Properties instance cannot be NULL"));
      
       	rc = dl_transport_new(&transport, dl_tls_transport_delete,
	    dl_tls_transport_connect, dl_tls_transport_read_msg,
	    dl_tls_transport_send_request, dl_tls_transport_get_fd,
	    producer);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to instatiate TlsTransport super class\n");
		goto err_tls_ctor;
	}

	transport->dlt_tls = tls = (struct dl_tls_transport *) dlog_alloc(
	    sizeof(struct dl_tls_transport));
	if (tls == NULL) {
 
		DLOGTR0(PRIO_HIGH, "Failed to allocate transport instance\n");
		goto err_tls_ctor;
	}
	bzero(tls, sizeof(struct dl_tls_transport));

	method = SSLv23_method();
	if (method == NULL) {


		DLOGTR0(PRIO_HIGH, "Failed to initialize the TLS method\n");
		goto err_tls_free;
	}

	tls->dlt_tls_ctx = SSL_CTX_new(method);
	if (tls->dlt_tls_ctx == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed to initialize the TLS context\n");
		goto err_tls_free;
	}
	
	SSL_CTX_set_verify(tls->dlt_tls_ctx,
	    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(tls->dlt_tls_ctx, 4);

	SSL_CTX_set_options(tls->dlt_tls_ctx, DLT_TLS_FLAGS);
	
	if (nvlist_exists_string(props, DL_CONF_CLIENT_FILE)) {
		client_file = nvlist_get_string(props, DL_CONF_CLIENT_FILE);
	} else {
		client_file = DL_DEFAULT_CLIENT_FILE;
	}

	rc = SSL_CTX_use_certificate_file(tls->dlt_tls_ctx, client_file,
	    SSL_FILETYPE_PEM);
	if (rc != 1) {

		DLOGTR2(PRIO_HIGH,
		    "Failed to configure TLS client certificate file %s "
		    "(%s)\n", client_file,
		     ERR_error_string(ERR_get_error(), NULL));
		goto err_tls_ctx_free;
	}

	if (nvlist_exists_string(props, DL_CONF_USER_PASSWORD)) {
		password = nvlist_get_string(props, DL_CONF_USER_PASSWORD);
	} else {
		password = DL_DEFAULT_USER_PASSWORD;
	}

	SSL_CTX_set_default_passwd_cb_userdata(tls->dlt_tls_ctx, password);

	if (nvlist_exists_string(props, DL_CONF_PRIVATEKEY_FILE)) {
		privkey_file = nvlist_get_string(props,
		    DL_CONF_PRIVATEKEY_FILE);
	} else {
		privkey_file = DL_DEFAULT_PRIVATEKEY_FILE;
	}

	rc = SSL_CTX_use_PrivateKey_file(tls->dlt_tls_ctx, privkey_file,
	    SSL_FILETYPE_PEM);
	if (rc != 1) {

		DLOGTR2(PRIO_HIGH,
		    "Failed to configure TLS PrivateKey file %s (%s)\n",
		     privkey_file, ERR_error_string(ERR_get_error(), NULL));
		goto err_tls_ctx_free;
	}

	rc = SSL_CTX_check_private_key(tls->dlt_tls_ctx);
	if (rc == 0) {

		DLOGTR1(PRIO_HIGH,
		    "Mismatch between cLient's private key and "
		     "certificate (%s)\n",
		     ERR_error_string(ERR_get_error(), NULL));
		goto err_tls_ctx_free;
	}

	/* Specify the locations at which CA certificates for verification
	 * are located (in not NULL a file of CA certificated in PEM
	 * format).
	 */
	if (nvlist_exists_string(props, DL_CONF_CACERT_FILE)) {
		cacert_file = nvlist_get_string(props, DL_CONF_CACERT_FILE);
	} else {
		cacert_file = DL_DEFAULT_CACERT_FILE;
	}

	rc = SSL_CTX_load_verify_locations(tls->dlt_tls_ctx, cacert_file,
	    NULL);
	if(rc == 0) {

		DLOGTR2(PRIO_HIGH,
		    "Failed to configure TLS CA cert location %s (%s)\n",
		    cacert_file, ERR_error_string(ERR_get_error(), NULL));
		goto err_tls_ctx_free;
	}

	dl_tls_transport_check_integrity(tls);
	*self = transport;
	return 0;

err_tls_ctx_free:
	SSL_CTX_free(tls->dlt_tls_ctx);

err_tls_free:
	dlog_free(tls);

err_tls_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating TlsTransport instance\n");
	*self = NULL;
	return -1;
}
