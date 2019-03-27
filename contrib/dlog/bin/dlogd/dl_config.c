/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#include <sys/nv.h>
#include <sys/types.h>

#include <ucl.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_utils.h"

/* Global singleton dlogd configuration */
extern nvlist_t *dlogd_props;

int
dl_config_new(char *conf_file, int debug_lvl)
{
	struct ucl_parser* parser;
	ucl_object_t *top, *cur, *obj, *t, *topics_obj = NULL;
	ucl_object_iter_t it, tit = NULL;
	char *topic_name;
	nvlist_t *topics;
	int nelements;

	/* Create a new nvlist to store producer configuration. */
	dlogd_props = nvlist_create(0);

	nvlist_add_number(dlogd_props, DL_CONF_DEBUG_LEVEL, debug_lvl);

	/* Instatiate libucl parser to parse the dlogd config file. */
	parser = ucl_parser_new(0);
	if (parser == NULL) {

		DLOGTR0(PRIO_HIGH, "Error creating libucl parser\n");
		goto err;
	}
	
	if (!ucl_parser_add_file(parser, conf_file)) {

		DLOGTR0(PRIO_HIGH, "Failed to parse config file\n");
		/* Free the libucl parser. */	
		ucl_parser_free(parser);
		goto err;
	}

	/* Obtain a reference to the top object */
	top = ucl_parser_get_object(parser);
	if (top == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to obtain reference to libucl object\n");
		goto err_free_libucl;
	}

	/* Iterate over the object */
	it = ucl_object_iterate_new(top);
	while ((obj = ucl_object_iterate_safe(it, true)) != NULL) {

		/* Parse each the configuration item. */
		if (strcmp(ucl_object_key(obj), DL_CONF_CLIENTID) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_CLIENTID,
			    ucl_object_tostring_forced(obj));
		} else  if (strcmp(ucl_object_key(obj), DL_CONF_PRIVATEKEY_FILE) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_PRIVATEKEY_FILE,
			    ucl_object_tostring_forced(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_CLIENT_FILE) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_CLIENT_FILE,
			    ucl_object_tostring_forced(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_CACERT_FILE) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_CACERT_FILE,
			    ucl_object_tostring_forced(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_USER_PASSWORD) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_USER_PASSWORD,
			    ucl_object_tostring_forced(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_TLS_ENABLE) == 0) {

			nvlist_add_bool(dlogd_props, DL_CONF_TLS_ENABLE,
			    ucl_object_toboolean(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_TORESEND) == 0) {

			nvlist_add_bool(dlogd_props, DL_CONF_TORESEND,
			    ucl_object_toboolean(obj));
		} else if (strcmp(ucl_object_key(obj),
		    DL_CONF_REQUEST_QUEUE_LEN) == 0) {

			nvlist_add_number(dlogd_props, DL_CONF_REQUEST_QUEUE_LEN,
			    ucl_object_toint(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_NELEMENTS) == 0) {
	
			nelements = ucl_object_toint(obj);
			if (nelements >= 0 )
				nvlist_add_number(dlogd_props, DL_CONF_NELEMENTS,
				    nelements);
		} else if (strcmp(ucl_object_key(obj), DL_CONF_LOG_PATH) == 0) {

			nvlist_add_string(dlogd_props, DL_CONF_LOG_PATH,
			    ucl_object_tostring_forced(obj));
		} else if (strcmp(ucl_object_key(obj), DL_CONF_TOPICS) == 0) {

			topics_obj = obj;
		} else {
			DLOGTR1(PRIO_HIGH,
			   "Unrecongised configuration: %s\n",
			   ucl_object_key(obj));
		}
	}
		
	/* Check whether topics to manage have been configured */
	if (topics_obj == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "No topics configured for dlog to manage\n");
		goto err_free_libucl;
	}
		
	/* Parse the configured topics. */
	topics = nvlist_create(0);
	it = ucl_object_iterate_reset(it, topics_obj);
	while ((cur = ucl_object_iterate_safe(it, true)) != NULL) {

		topic_name = ucl_object_key(cur);

		/* Iterate over the values of a key */
		nvlist_t *topic = nvlist_create(0);
		while ((t = ucl_iterate_object(cur, &tit, true))) {

			if (strcmp(ucl_object_key(t), DL_CONF_BROKER) == 0) {
			
				nvlist_add_string(topic, DL_CONF_BROKER,
				    ucl_object_tostring_forced(t));
			} else if (strcmp(ucl_object_key(t), DL_CONF_BROKER_PORT) == 0) {

				nvlist_add_number(topic, DL_CONF_BROKER_PORT,
				    ucl_object_toint(t));
			} else {
				DLOGTR1(PRIO_HIGH,
				    "Unrecongised configuration: %s\n",
				    ucl_object_key(t));
			}
		}
		nvlist_add_nvlist(topics, topic_name, topic);
	}
	nvlist_add_nvlist(dlogd_props, DL_CONF_TOPICS, topics);

	ucl_object_iterate_free(it);

	ucl_object_unref(top);

	/* Free the libucl parser. */	
	ucl_parser_free(parser);

	if (debug_lvl > 1) {
		DLOGTR0(PRIO_NORMAL, "Configuration:\n");
		nvlist_dump(dlogd_props, STDOUT_FILENO);
	}

	return 0;

err_free_libucl:
	/* Free the libucl parser. */	
	ucl_parser_free(parser);

err:
	return -1;	
}
