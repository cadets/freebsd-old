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

#ifndef _DL_CONFIG_H
#define _DL_CONFIG_H

#include <sys/nv.h>

#include "dl_response.h" 

/* TODO: Remove this? */
typedef void (* dl_response_func) (struct dl_response const * const);

struct dl_broker_config {
	nvlist_t *dlbc_props;
};

struct dl_client_config {
	dl_response_func dlcc_on_response;
	nvlist_t *dlcc_props;
};

struct dl_client_config_desc {
	dl_response_func dlcc_on_response;
	void * dlcc_packed_nvlist;
	size_t dlcc_packed_nvlist_len;
};

#define DL_CONF_CLIENTID "client.id"
#define DL_CONF_BROKER "client.broker"
#define DL_CONF_BROKER_PORT "broker.port"
#define DL_CONF_TORESEND "resend.to_resend"
#define DL_CONF_RESENDTIMEOUT "resend.timeout"
#define DL_CONF_RESENDPERIOD "resend.period"
#define DL_CONF_TOPIC "client.topic"
#define DL_CONF_PRIVATEKEY_FILE "tls.privatekey.file"
#define DL_CONF_CLIENT_FILE "tls.client.file"
#define DL_CONF_CACERT_FILE "tls.cacert.file"
#define DL_CONF_USER_PASSWORD "tls.user.password"
#define DL_CONF_TLS_ENABLE "tls.enable"

#define DL_DEFAULT_CLIENTID "dlog"
#define DL_DEFAULT_BROKER "127.0.0.1"
#define DL_DEFAULT_BROKER_PORT 9092
#define DL_DEFAULT_TORESEND true 
#define DL_DEFAULT_RESENDTIMEOUT 30
#define DL_DEFAULT_RESENDPERIOD 2
#define DL_DEFAULT_TOPIC "test" 
#define DL_DEFAULT_PRIVATEKEY_FILE "client.pem"
#define DL_DEFAULT_CLIENT_FILE "client.pem"
#define DL_DEFAULT_CACERT_FILE "cacert.pem"
#define DL_DEFAULT_USER_PASSWORD "password"
#define DL_DEFAULT_TLS_ENABLE false

#endif
