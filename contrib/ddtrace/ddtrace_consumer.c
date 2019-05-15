/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <dt_impl.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <libgen.h>
#include <libutil.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifdef PRIVATE_RDKAFKA 
#include <private/rdkafka/rdkafka.h>
#else
#include <librdkafka/rdkafka.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_utils.h"

extern int dt_consume_cpu(dtrace_hdl_t *, FILE *, int, dtrace_bufdesc_t *, boolean_t,
    dtrace_consumer_t *, void *);

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static int dtc_buffered_handler(const dtrace_bufdata_t *, void *);
static int dtc_setup_rx_topic(char *, char *, char *, char *, char *,
    char *, int64_t);
static int dtc_setup_tx_topic(char *, char *, char *, char *, char *,
    char *);
static int dtc_message_process(dtrace_hdl_t *, rd_kafka_message_t *);

static char const * const DTC_TRACE_KEY = "ddtrace";
static char const * const DTC_EPROBE_KEY = "eprobe";
static char const * const DTC_FORMAT_KEY = "format";
static char const * const DTC_PROBE_KEY = "probe";
static char const * const DTC_NFORMAT_KEY = "nformat";
static char const * const DTC_NPROBE_KEY = "nprobe";
static char const * const DTC_PIDFILE = "/var/run/ddtracec.pid";

static char *dtc_pname;
static int dtc_status = 0;
static int dtc_debug = 0;
static volatile int dtc_intr_flag = 0;
static rd_kafka_t *dtc_rx_hdl;
static rd_kafka_t *dtc_tx_hdl;
static rd_kafka_topic_t *dtc_tx_topic;
static rd_kafka_topic_partition_list_t *dtc_rx_topics;

static inline void 
dtc_usage(FILE * fp)
{

	(void) fprintf(fp,
	    "Usage: %s -b brokers [-df] "
	    "-i input_topic [-o output_topic] "
	    "[-c client_certificate] [-a ca_cert] [-p password] "
	    "[-k private_key] [-q poll_interval]\n", dtc_pname);

	(void) fprintf(fp, "\n"
	    "\t-d\t--debug\t\t Increase debug output\n"
	    "\t-f\t--frombeginning\t Read from beginning of input topic\n"
	    "\t-b\t--brokers\t Kafka broker connection string\n"
	    "\t-i\t--intopic\t Kafka topic to read from\n"
	    "\t-o\t--outtopic\t Kafka topic to write to\n"
	    "\t-a\t--cacert\t CA_cert path (for TLS support)\n"
	    "\t-c\t--clientcert\t Client certificate path (for TLS support)\n"
	    "\t-p\t--password\t Password for private key (for TLS support)\n"
	    "\t-q\t--poll\t\t Kafka poll interval (in us)\n"
	    "\t-k\t--privkey\t Private key (for TLS support)\n"
	    "\t-s\t\t\t DTrace script.\n"
	    "All remaining arguments will be passed to DTrace.\n");
}

/*ARGSUSED*/
static inline void
dtc_intr(int signo)
{
	DLOGTR1(PRIO_NORMAL, "Stopping %s...\n", dtc_pname);
	dtc_intr_flag = 1;
}
	
/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{

	return (DTRACE_CONSUME_THIS);
}
	
/*ARGSUSED*/
static int
chewrec(const dtrace_probedata_t * data, const dtrace_recdesc_t * rec,
    void * arg)
{
	dtrace_actkind_t act;
	uintptr_t addr;

	/* Check if the final record has been processed. */
	if (rec == NULL) {

		return (DTRACE_CONSUME_NEXT); 
	}

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	if (act == DTRACEACT_EXIT) {
		dtc_status = *((uint32_t *) addr);
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS); 
}

static int 
dtc_message_process(dtrace_hdl_t *dtp, rd_kafka_message_t *rkmessage)
{
	dtrace_bufdesc_t buf;
	static char **formats;
	static int nformat = 0;

	DL_ASSERT(dtp != NULL, (""));
	DL_ASSERT(rkmessage != NULL, (""));

	if (rkmessage->key != NULL) {
		if (strncmp(rkmessage->key, DTC_TRACE_KEY, rkmessage->key_len) == 0) {
			
			dtrace_consumer_t con;
			
			if (dtc_debug > 2)
				DLOGTR0(PRIO_LOW, "Received target trace records\n");

			/* Allocate a buffer into which the trace data is copied. */
			bzero(&buf, sizeof(dtrace_bufdesc_t));
			buf.dtbd_data = dt_zalloc(dtp, rkmessage->len);
			if (buf.dtbd_data != NULL) {

				memcpy(buf.dtbd_data, rkmessage->payload, rkmessage->len);
				buf.dtbd_size = rkmessage->len;
				/* TODO: The cpu to which the buffer relates should
				* be carried in the message from the target perhaps
				* as part of the key.
				*/ 
				buf.dtbd_cpu = 0;

				/* Consume the received buffer */
				con.dc_consume_probe = chew;
				con.dc_consume_rec = chewrec;
				con.dc_put_buf = NULL;
				con.dc_get_buf = NULL;

				/* TODO: drops also need to be carried along with the data */
				if (dt_consume_cpu(dtp, NULL, 0, &buf, false, &con, NULL) != 0) {

				}

				/* Free the buffer. */
				free(buf.dtbd_data);
			} else {
				DLOGTR0(PRIO_HIGH, "Error allocating trace buffer\n");
				return -1;
			}
		} else if (strncmp(rkmessage->key, DTC_EPROBE_KEY, rkmessage->key_len) == 0 &&
		    rkmessage->len >= sizeof(dtrace_eprobedesc_t)) {

			if (dtp->dt_edesc != NULL && dtp->dt_pdesc != NULL) {

				dtrace_eprobedesc_t *eprobe;

				eprobe = malloc(rkmessage->len);
				if (eprobe != NULL) {

					/* Copy the eprobedesc in the newly cllocated memory
					 * and add in to the dt_edesc array.
					 */
					bzero(eprobe, rkmessage->len);
					memcpy(eprobe, rkmessage->payload, rkmessage->len);
					dtp->dt_edesc[eprobe->dtepd_epid] = eprobe;

					if (dtc_debug > 2) {
					
						dtrace_probedesc_t *probe = dtp->dt_pdesc[eprobe->dtepd_epid];

						DLOGTR5(PRIO_LOW, "Received metadata for eprobe (id = %u):  %s:%s:%s:%s\n",
						    probe->dtpd_id, probe->dtpd_provider,
						    probe->dtpd_mod, probe->dtpd_func,
						    probe->dtpd_name);
					}

					/* For each record description in the enabling categorise
					 * the format string and install into the
					 * dtrace handle formats and str_data arrays.
					 */
					for (int i = 0; i < eprobe->dtepd_nrecs; i++) {

						dtrace_recdesc_t *rec = &eprobe->dtepd_rec[i];

						switch (rec->dtrd_action) {
						case DTRACEACT_DIFEXPR:
							dtp->dt_strdata[rec->dtrd_format - 1] =
							    formats[rec->dtrd_format - 1];
							break;
						case DTRACEACT_PRINTA:
							//result = dtrace_printa_create(dtp, formats[rec->dtrd_format - 1]);
							dtp->dt_formats[rec->dtrd_format - 1] =
							    dtrace_printa_create(dtp, formats[rec->dtrd_format - 1]);
							break;
						default:
							//result = dtrace_printf_create(dtp, formats[rec->dtrd_format - 1]);
							dtp->dt_formats[rec->dtrd_format - 1] =
							    dtrace_printf_create(dtp, formats[rec->dtrd_format - 1]);
							break;
						}
					}
				} else {
					DLOGTR0(PRIO_HIGH, "Error allocating eprobe\n");
				}
			} else {
				DLOGTR0(PRIO_HIGH, "Error edesc/pdesc arrays not initialised\n");
			}
		} else if (strncmp(rkmessage->key, DTC_NFORMAT_KEY, rkmessage->key_len) == 0) {

			int maxformat = *((int *) rkmessage->payload);

			if (dtc_debug > 2)
				DLOGTR1(PRIO_LOW,
				    "Target indicated number of formats: %d\n", maxformat);

			dtp->dt_maxformat = dtp->dt_maxstrdata = maxformat;

			dtp->dt_formats = malloc(maxformat * sizeof(void *));
			if (dtp->dt_formats != NULL) {

				bzero(dtp->dt_formats, maxformat * sizeof(void *));

				dtp->dt_strdata = malloc(maxformat * sizeof(char *));
				if (dtp->dt_strdata != NULL) {

					bzero(dtp->dt_strdata, maxformat * sizeof(char *));

					/* Allocate a formats array on the stack.
					 * This is used temporarily to stor the formats
					 * until the eprobedesc metadata is received from
					 * the target.
					 */
					formats = malloc(maxformat * sizeof(char *));
					if (formats != NULL) {

						bzero(dtp->dt_strdata, maxformat * sizeof(char *));
					} else {
						free(dtp->dt_strdata);
						dtp->dt_strdata = NULL;

						free(dtp->dt_formats);
						dtp->dt_formats = NULL;
						DLOGTR0(PRIO_HIGH, "Error allocating formats array\n");
					}
				} else {
					free(dtp->dt_formats);
					dtp->dt_formats = NULL;
					DLOGTR0(PRIO_HIGH, "Error allocating formats array\n");
				}
			} else {
				DLOGTR0(PRIO_HIGH, "Error allocating formats array\n");
			}
		} else if (strncmp(rkmessage->key, DTC_FORMAT_KEY, rkmessage->key_len) == 0) {

			if (dtc_debug > 2)
				DLOGTR1(PRIO_LOW, "Received target format key: %s\n", rkmessage->payload);

			if (formats != NULL) {

				char *fmt;

				/* Allocate memory for the received format and copy it
				 * into the memory allocated on the stack.
				 * When the eprobedesc metadata is received these
				 * raw formats are categorised and installed in the
				 * dtarce handle formats and str_data arrays.
				 */
				fmt = malloc(rkmessage->len);
				if (fmt != NULL) {

					memcpy(fmt, rkmessage->payload, rkmessage->len);
					formats[nformat++] = fmt;
				} else {
					DLOGTR0(PRIO_HIGH, "Error allocating format string\n");
				}
			} else {
				DLOGTR0(PRIO_HIGH, "Error formats array not initialised");
			}
		} else if (strncmp(rkmessage->key, DTC_NPROBE_KEY, rkmessage->key_len) == 0) {

			int npid = *((int *) rkmessage->payload);

			if (dtc_debug > 1)
				DLOGTR1(PRIO_LOW, "Target indicated number of probes: %d\n", npid);

			dtp->dt_maxprobe = npid;
			dtp->dt_pdesc = malloc(npid * sizeof(dtrace_probedesc_t *));
			if (dtp->dt_pdesc != NULL) {

				bzero(dtp->dt_pdesc, npid * sizeof(dtrace_probedesc_t *));
				dtp->dt_edesc = malloc(npid * sizeof(dtrace_eprobedesc_t *));
				if (dtp->dt_edesc == NULL) {

					DLOGTR0(PRIO_HIGH, "Error allocating epdesc array\n");
					free(dtp->dt_pdesc);
					dtp->dt_pdesc = NULL;
				}
				bzero(dtp->dt_edesc, npid * sizeof(dtrace_eprobedesc_t *));
			} else {
				DLOGTR0(PRIO_HIGH, "Error allocating pdesc array\n");
			}
		} else if (strncmp(rkmessage->key, DTC_PROBE_KEY, rkmessage->key_len) == 0 &&
		    rkmessage->len == sizeof(dtrace_probedesc_t)) {

			dtrace_probedesc_t *probe;

			if (dtp->dt_pdesc != NULL) {

				probe = malloc(sizeof(dtrace_probedesc_t));
				if (probe != NULL) {

					/* Copy the probedesc into the newly allocated memory
					 * and insert into the dt_pdesc array.
					 */
					bzero(probe, sizeof(dtrace_probedesc_t));
					memcpy(probe, rkmessage->payload, sizeof(dtrace_probedesc_t));
					dtp->dt_pdesc[probe->dtpd_id] = probe;

					if (dtc_debug > 2) {
						DLOGTR5(PRIO_LOW,
						    "Received metadata for probe (id = %u):  i"
						    "%s:%s:%s:%s\n",
						    probe->dtpd_id, probe->dtpd_provider,
						    probe->dtpd_mod, probe->dtpd_func,
						    probe->dtpd_name);
					}
				} else {
					DLOGTR0(PRIO_HIGH, "Error allocating probe\n");
				}
			} else {
				DLOGTR0(PRIO_HIGH, "Error pdesc array not initialised\n");
			}
		} else {
			/* If the Message key indicates that the message was not
			 * produced by Distribted DTrace, processing the message can
			 * have dire consequences as libdtrace implicitly trusts the
			 * buffers that it processes.
			 */
			DLOGTR2(PRIO_LOW,
			    "%s: key of Kafka message %s is invalid\n",
			    dtc_pname, rkmessage->key);
		}
	} else {

		DLOGTR1(PRIO_LOW, "%s: key of Kafka message is NULL\n",
		    dtc_pname);
	}
	return 0;
}

static int
dtc_buffered_handler(const dtrace_bufdata_t *buf_data, void *arg)
{
	rd_kafka_topic_t *tx_topic = (rd_kafka_topic_t *) arg;
	static struct dl_bbuf *output_buf = NULL;
	size_t buf_len;

	DL_ASSERT(tx_topic != NULL, ("Transmit topic cannot be NULL"));
	

	/* '{' indicates the start of the JSON message.
	 * Allocate a buffer into which the message is written.
	 */
	if (buf_data->dtbda_buffered[0] == '{') {

		if (dtc_debug > 1)
			DLOGTR0(PRIO_LOW, "Start of JSON message\n");

		DL_ASSERT(output_buf == NULL,
		    ("Output buffer should be NULL at the start of message."));
		dl_bbuf_new_auto(&output_buf) ;
	} 

	/* Buffer the received data until the end of the JSON message 
	 * is received.
	 * */
	buf_len = strlen(buf_data->dtbda_buffered);
	dl_bbuf_bcat(output_buf, buf_data->dtbda_buffered, buf_len);

	/* '}' indicates the end of the JSON message.
	 * Allocate a buffer into which the message is written.
	 */
	if (buf_data->dtbda_buffered[0] == '}') {

		if (dtc_debug > 1)
			DLOGTR0(PRIO_LOW, "End of JSON message\n");
retry:
		if (rd_kafka_produce(
			/* Topic object */
			tx_topic,
			/* Use builtin partitioner to select partition*/
			RD_KAFKA_PARTITION_UA,
			/* Make a copy of the payload. */
			RD_KAFKA_MSG_F_COPY,
			/* Message payload (value) and length */
			dl_bbuf_data(output_buf),
			dl_bbuf_pos(output_buf),
			/* Optional key and its length */
			NULL, 0,
			/* Message opaque, provided in
			* delivery report callback as
			* msg_opaque. */
			NULL) == -1) {
			/**
			* Failed to *enqueue* message for producing.
			*/
			DLOGTR2(PRIO_HIGH,
			    "%% Failed to produce to topic %s: %s\n",
			    rd_kafka_topic_name(tx_topic),
			    rd_kafka_err2str(rd_kafka_last_error()));

			/* Poll to handle delivery reports */
			if (rd_kafka_last_error() ==
			    RD_KAFKA_RESP_ERR__QUEUE_FULL) {
				/* If the internal queue is full, wait for
				 * messages to be delivered and then retry.
				 * The internal queue represents both
				 * messages to be sent and messages that have
				 * been sent or failed, awaiting their
				 * delivery report callback to be called.
				 *
				 * The internal queue is limited by the
				 * configuration property
				 * queue.buffering.max.messages */
				rd_kafka_poll(dtc_tx_hdl, 1000 /*block for max 1000ms*/);
				goto retry;
			}
		} else {
			if (dtc_debug > 0) {
				DLOGTR2(PRIO_LOW,
			    	    "%% Enqueued message (%zu bytes) for topic %s\n",
			    	    dl_bbuf_pos(output_buf), rd_kafka_topic_name(tx_topic));
			}
		}

		/* Free the buffer for the start of the next JSON message */
		dl_bbuf_delete(output_buf);
		output_buf = NULL;
	}
	return 0;
}

static int
dtc_setup_rx_topic(char *topic_name, char *brokers, char *ca_cert,
    char *client_cert, char *priv_key, char *password, int64_t start_offset)
{
	rd_kafka_conf_t *conf;
	char errstr[512];

	DL_ASSERT(topic_name != NULL,
	    ("Receive topic name cannot be NULL"));
	DL_ASSERT(brokers != NULL,
	    ("Receive topic brokers cannot be NULL"));

	/* Setup the Kafka topic used for receiving DTrace records. */
	conf = rd_kafka_conf_new();
	if (conf == NULL) {

		DLOGTR2(PRIO_HIGH, "%s: failed to create Kafka conf: %s\n",
		    dtc_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_err;
	}

	if (rd_kafka_conf_set(conf, "client.id", dtc_pname,
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "socket.nagle.disable", "true",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	/* Set bootstrap broker(s) as a comma-separated list of
         * host or host:port (default port 9092).
         * librdkafka will use the bootstrap brokers to acquire the full
         * set of brokers from the cluster.
	 */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "enable.auto.commit", "true",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "auto.commit.interval.ms", "1000",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "enable.auto.offset.store", "true",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "auto.offset.reset", "earliest",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "check.crcs", "true",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "group.id", dtc_pname,
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	if (ca_cert != NULL && client_cert != NULL && priv_key != NULL &&
	    password != NULL) {
		/* Configure TLS support:
		 * https://github.com/edenhill/librdkafka/wiki/Using-SSL-with-librdkafka
		*/
		if (rd_kafka_conf_set(conf, "metadata.broker.list", brokers,
		    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "security.protocol", "ssl",
		    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.ca.location", ca_cert,
		    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.certificate.location",
		    client_cert, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.key.location", priv_key,
		    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.key.password", password,
		    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_rx_topic_new_err;
		}
	}

	/* Create the Kafka consumer.
	 * The configuration instance does not need to be freed after
	 * this succeeds.
	 */
	if (!(dtc_rx_hdl = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr,
	    sizeof(errstr)))) {

		DLOGTR2(PRIO_HIGH, "%s: failed to create Kafka consumer: %s\n",
		    dtc_pname, errstr);
		goto configure_rx_topic_new_err;
	}

	/* Redirect rd_kafka_poll() to consumer_poll() */
	if (rd_kafka_poll_set_consumer(dtc_rx_hdl) != RD_KAFKA_RESP_ERR_NO_ERROR) {

		DLOGTR2(PRIO_HIGH, "%s: failed setting consumer_poll(): %s\n",
		    dtc_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_new_err;
	}

	/* Create a new topic/parition list for the Consumer */
	if ((dtc_rx_topics = rd_kafka_topic_partition_list_new(1)) == NULL) {

		DLOGTR2(PRIO_HIGH,
		    "%s: failed creating topic/parition list for Kafka consumer: %s\n",
		    dtc_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_new_err;
	}

	/* Add the topic to the parition list and set the offset.
	 * TODO: It is unclear from the C API whether the call can fail.
	 */
	rd_kafka_topic_partition_list_add(dtc_rx_topics, topic_name, 0)->offset = start_offset;

	if (rd_kafka_assign(dtc_rx_hdl, dtc_rx_topics) != RD_KAFKA_RESP_ERR_NO_ERROR) {

		DLOGTR2(PRIO_HIGH, "%s: failed to assign topic to Kafka consumer: %s\n",
		    dtc_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_partlist_err;
	}

	return 0;

configure_rx_topic_partlist_err:
	rd_kafka_topic_partition_list_destroy(dtc_rx_topics);
	
configure_rx_topic_new_err:
	rd_kafka_destroy(dtc_rx_hdl);

configure_rx_topic_conf_err:
	rd_kafka_conf_destroy(conf);

configure_rx_topic_err:
	return -1;
}

static int
dtc_setup_tx_topic(char *topic_name, char *brokers, char *ca_cert,
    char *client_cert, char *priv_key, char *password)
{
	rd_kafka_conf_t *conf;
	char errstr[512];

	DL_ASSERT(topic_name != NULL,
	    ("Transmit topic name cannot be NULL"));
	DL_ASSERT(brokers != NULL,
	    ("Receive topic brokers cannot be NULL"));

	/* Setup the Kafka topic used for receiving DTrace records. */
	conf = rd_kafka_conf_new();
	if (conf == NULL) {

		DLOGTR2(PRIO_HIGH, "%s: failed to create Kafka conf: %s\n",
		    dtc_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_tx_topic_err;
	}

       	/* Set bootstrap broker(s) as a comma-separated list of
         * host or host:port (default port 9092).
         * librdkafka will use the bootstrap brokers to acquire the full
         * set of brokers from the cluster.
	 */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_tx_topic_conf_err;
        }

	if (rd_kafka_conf_set(conf, "compression.codec", "gzip",
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

		DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_tx_topic_conf_err;
	}

	if (rd_kafka_conf_set(conf, "socket.nagle.disable", "true",
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_tx_topic_new_err;
        }

	if (rd_kafka_conf_set(conf, "linger.ms", "10",
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

		DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_tx_topic_conf_err;
	}

	if (ca_cert != NULL && client_cert != NULL && priv_key != NULL &&
	    password != NULL) {
		/* Configure TLS support:
		* https://github.com/edenhill/librdkafka/wiki/Using-SSL-with-librdkafkaxi
		*/
		if (rd_kafka_conf_set(conf, "metadata.broker.list", brokers,
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "security.protocol", "ssl",
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.ca.location", ca_cert,
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.certificate.location", client_cert,
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.key.location", priv_key,
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}

		if (rd_kafka_conf_set(conf, "ssl.key.password", password,
		errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

			DLOGTR1(PRIO_HIGH, "%s\n", errstr);
			goto configure_tx_topic_new_err;
		}
	}

	/* Create the Kafka producer.
	 * The configuration instance does not need to be freed after
	 * this succeeds.
	 */
	if (!(dtc_tx_hdl = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr,
	    sizeof(errstr)))) {

		DLOGTR2(PRIO_HIGH,
		    "%s: failed to create Kafka consumer: %s\n",
		    dtc_pname, errstr);
		goto configure_tx_topic_conf_err;
	}

	if (!(dtc_tx_topic = rd_kafka_topic_new(dtc_tx_hdl, topic_name, NULL))) {

		DLOGTR3(PRIO_HIGH,
		    "%s: failed to create Kafka topic %s: %s\n",
		    dtc_pname, topic_name,
		    rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_tx_topic_new_err;
	}

	return 0;

configure_tx_topic_new_err:
	rd_kafka_destroy(dtc_tx_hdl);

configure_tx_topic_conf_err:
	rd_kafka_conf_destroy(conf);

configure_tx_topic_err:
	return -1;
}

/*
 * Prototype distributed dtrace agent.
 * The agent recieves DTrace records from an Apache Kafka topic and prints
 * them using libdtrace.
 */
int
main(int argc, char *argv[])
{
	dtrace_hdl_t *dtp;
	int c, err, ret = 0, script_argc = 0;
	char *brokers, *rx_topic_name = NULL;
	char *tx_topic_name = NULL, *client_cert = NULL;
	char *ca_cert = NULL, *priv_key = NULL, *password = NULL;
	char **script_argv;
	int64_t start_offset = RD_KAFKA_OFFSET_STORED;
	useconds_t poll_period = 100000; /* 100ms */
	static struct option dtc_options[] = {
		{"brokers", required_argument, 0, 'b'},
		{"cacert", required_argument, NULL, 'a'},
		{"clientcert", required_argument, NULL, 'c'},
		{"debug", no_argument, NULL, 'd'},
		{"frombeginning", no_argument, NULL, 'f'},
		{"intopic", required_argument, NULL, 'i'},
		{"outtopic", required_argument, NULL, 'o'},
		{"password", required_argument, NULL, 'p'},
		{"poll", required_argument, NULL, 'q'},
		{"privkey", required_argument, NULL, 'k'},
		{0, 0, 0, 0}
	};
	struct pidfh *pfh;
	pid_t pid;

	dtc_pname = basename(argv[0]); 	

	/** Allocate space required for any arguments being passed to the
	 *  D-language script.
	 */
	script_argv = (char **) malloc(sizeof(char *) * argc);
	if (script_argv == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "%s: failed to allocate script arguments\n", dtc_pname);
		exit(EXIT_FAILURE);
	}

	while ((c = getopt_long(argc, argv, "a:b:c:dfi:k:o:p:q:s:",
	    dtc_options, NULL)) != -1) {
		switch (c) {
		case 'a':
			/* CA certifcate file for TLS */
			ca_cert = optarg;
			break;
		case 'b':
			/* Kafka broker string */
			brokers = optarg;
			break;
		case 'c':
			/* Client certificate file for TLS */
			client_cert = optarg;
			break;
		case 'd':
			/* Debug flag */
			dtc_debug++;
			break;
		case 'f':
			/* Kafla offset from beginning of topic */
			start_offset = RD_KAFKA_OFFSET_BEGINNING;
			break;
		case 'i':
			/* Kafla input topic */
			rx_topic_name = optarg;
			break;
		case 'k':
			/* Client private key file for TLS */
			priv_key = optarg;
			break;
		case 'o':
			/* Kafla output topic */
			tx_topic_name = optarg;
			break;
		case 'p':
			/* Client private key password for TLS */
			password = optarg;
			break;
		case 'q':
			/* Poll period (us) */
			sscanf(optarg, "%ul", &poll_period);
			break;
		case '?':
			/* FALLTHROUGH */
		default:
			dtc_usage(stderr);
			ret = -1;
			goto free_script_args;
			break;
		}
	};
	
	/* Pass the remaining command line arguments to the DTrace script. */
	script_argv[script_argc++] = dtc_pname;
	while (optind < argc) {
		script_argv[script_argc++] = argv[optind++];
	}

	if (brokers == NULL || rx_topic_name == NULL) {

		dtc_usage(stderr);
		ret = -1;
		goto free_script_args;
	}

	/* Daemonise */
	if (dtc_debug == 0 && daemon(0, 0) == -1) {

		DLOGTR0(PRIO_HIGH, "Failed registering dlogd as daemon\n");
		ret = -1;
		goto free_script_args;
	}

	/* Create a pid file for the dlogd daemon. */
	pfh = pidfile_open(DTC_PIDFILE, 0600, &pid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			errx(EXIT_FAILURE,
			    "Daemon already running, pid: %d", pid);
		}
		DLOGTR0(PRIO_HIGH, "Cannot open or create pid file\n");
	}

	if (dtc_debug > 0) {

		/* Configure syslog to copy error messages to stderr. */
		openlog(dtc_pname, LOG_PERROR, LOG_USER);
	} else { 
		if (daemon(0, 0) == -1) {

			pidfile_remove(pfh);
			errx(EXIT_FAILURE,
			    "Failed registering dlogd as daemon\n");
		}
	}

	/* Write the pid */
	pidfile_write(pfh);

	DLOGTR1(PRIO_LOW, "%s daemon starting...\n", dtc_pname);

	if (dtc_setup_rx_topic(rx_topic_name, brokers, ca_cert, client_cert,
	    priv_key, password, start_offset) != 0){

		DLOGTR1(PRIO_HIGH, "Failed to setup receive topic %s\n",
		    rx_topic_name);
		ret = -1;
		goto free_script_args;
	}

	if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {

		DLOGTR2(PRIO_HIGH, "%s: failed to initialize dtrace %s",
		    dtc_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		ret = -1;
		goto destroy_rx_kafka;
	}
	DLOGTR1(PRIO_LOW, "%s: dtrace initialized\n", dtc_pname);

	/* If the transmit topic name is configured create a new tranmitting
	 * topic and register a buffered handler to write to this
	 * topic with dtrace.
	 */
        if (tx_topic_name != NULL) {	
		if (dtc_setup_tx_topic(tx_topic_name, brokers, ca_cert,
		    client_cert, priv_key, password) != 0) {
	
			ret = -1;
			goto destroy_dtrace;
		}

		if (dtrace_handle_buffered(dtp, dtc_buffered_handler,
		    dtc_tx_topic) == -1) {

			DLOGTR2(PRIO_HIGH,
			    "%s: failed registering dtrace "
			    "buffered handler %s",
			    dtc_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
			ret = -1;
			goto destroy_tx_kafka;
		}
	}

	while (dtc_intr_flag == 0) {
		rd_kafka_message_t *rkmessage;

		while (dtc_intr_flag == 0 &&
		    (rkmessage = rd_kafka_consumer_poll(dtc_rx_hdl, poll_period/1000)) != NULL) {

			if (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) {

				dtc_message_process(dtp, rkmessage);
			} else {
				DLOGTR1(PRIO_HIGH,
				    "%% Failed to consume from topic: %s\n",
				    rd_kafka_err2str(rd_kafka_last_error()));
			}

			rd_kafka_message_destroy(rkmessage);
		};
	};

destroy_tx_kafka:
	if (tx_topic_name != NULL) {	

		/* Flush the output topic waiting a maximum of 10 seconds. */
		rd_kafka_flush(dtc_tx_hdl, 10*1000);

		/* Destroy the Kafka transmit topic */
		DLOGTR1(PRIO_LOW, "%s: destroy kafka transmit topic\n",
		    dtc_pname);
		rd_kafka_topic_destroy(dtc_tx_topic);

		/* Destroy the Kafka transmit handle. */
		DLOGTR1(PRIO_LOW, "%s: destroy kafka transmit handle\n",
		    dtc_pname);
		rd_kafka_destroy(dtc_tx_hdl);
	}

destroy_dtrace:
	/* Destroy dtrace the handle. */
	DLOGTR1(PRIO_LOW, "%s: closing dtrace\n", dtc_pname);
	dtrace_close(dtp);

destroy_rx_kafka:
	DLOGTR1(PRIO_LOW, "%s: destroy kafka receive topic\n", dtc_pname);

	rd_kafka_consumer_close(dtc_rx_hdl);

	/* Destroy the Kafka receive topic */
	rd_kafka_topic_partition_list_destroy(dtc_rx_topics);

	/* Destroy the Kafka recieve handle. */
	DLOGTR1(PRIO_LOW, "%s: destroy kafka receive handle\n", dtc_pname);
	rd_kafka_destroy(dtc_rx_hdl);

	/* Let background threads clean up and terminate cleanly. */
	int run = 5;
	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
		printf("Waiting for librdkafka to decommission\n");
	if (run <= 0)
		rd_kafka_dump(stdout, dtc_rx_hdl);

	pidfile_remove(pfh);
free_script_args:	

	/* Free the memory used to hold the script arguments. */	
	free(script_argv);

	DLOGTR1(PRIO_LOW, "%s daemon stopped.\n", dtc_pname);

	return ret;
}
