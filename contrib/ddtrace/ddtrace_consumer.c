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

#include <stdbool.h>
#include <dt_impl.h>
#include <errno.h>
#include <libgen.h>
#include <rdkafka/rdkafka.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_utils.h"

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static int dtc_get_buf(dtrace_hdl_t *, int, dtrace_bufdesc_t **);
static void dtc_put_buf(dtrace_hdl_t *, dtrace_bufdesc_t *b);
static int dtc_buffered_handler(const dtrace_bufdata_t *, void *);
static int dtc_setup_rx_topic(char *, char *);
static int dtc_setup_tx_topic(char *, char *);
static int dtc_register_daemon(void);

static char *g_pname;
static int g_status = 0;
static volatile int g_intr = 0;
static rd_kafka_t *rx_rk;
static rd_kafka_t *tx_rk;
static rd_kafka_topic_t *tx_topic;
static rd_kafka_topic_t *rx_topic;

static char const * const DTC_PIDFILE = "/var/run/ddtracec.pid";

static inline void 
dtc_usage(FILE * fp)
{

	(void) fprintf(fp,
	    "Usage: %s -b brokers -d -i input_topic"
	    "[-o output_topic] -s script [-x]\n", g_pname);
}

/*ARGSUSED*/
static inline void
dtc_intr(int signo)
{
	DLOGTR1(PRIO_NORMAL, "Stopping %s...\n", g_pname);
	g_intr = 1;
}
	
/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
#ifndef NDEBUG
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	dtrace_eprobedesc_t *ed = data->dtpda_edesc;
	processorid_t cpu = data->dtpda_cpu;

	DLOGTR1(PRIO_LOW, "dtpd->id = %u\n", pd->dtpd_id);
	DLOGTR1(PRIO_LOW, "dtepd->id = %u\n", ed->dtepd_epid);
	DLOGTR1(PRIO_LOW, "dtpd->func = %s\n", pd->dtpd_func);
	DLOGTR1(PRIO_LOW, "dtpd->name = %s\n", pd->dtpd_name);
#endif

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

#ifndef NDEBUG
	DLOGTR1(PRIO_LOW, "chewrec %p\n", rec);
	DLOGTR1(PRIO_LOW, "dtrd_action %u\n", rec->dtrd_action);
	DLOGTR1(PRIO_LOW, "dtrd_size %u\n", rec->dtrd_size);
	DLOGTR1(PRIO_LOW, "dtrd_alignment %u\n", rec->dtrd_alignment);
	DLOGTR1(PRIO_LOW, "dtrd_format %u\n", rec->dtrd_format);
	DLOGTR1(PRIO_LOW, "dtrd_arg  %lu\n", rec->dtrd_arg);
	DLOGTR1(PRIO_LOWPRIO_LOi, "dtrd_uarg  %lu\n", rec->dtrd_uarg);
#endif

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	if (act == DTRACEACT_EXIT) {
		g_status = *((uint32_t *) addr);
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS); 
}

static int
dtc_get_buf(dtrace_hdl_t *dtp, int cpu, dtrace_bufdesc_t **bufp)
{
	dtrace_optval_t size;
	dtrace_bufdesc_t *buf;
	rd_kafka_message_t *rkmessage;
	int partition = 0;
	
	DL_ASSERT(dtp != NULL, ("DTrace handle cannot be NULL"));
	DL_ASSERT(buf != NULL, ("Buffer instance to free cannot be NULL"));

	buf = dt_zalloc(dtp, sizeof(*buf));
	if (buf == NULL)
		return -1;

	/* Non-blocking poll of the log. */
	rd_kafka_poll(rx_rk, 0);

	rkmessage = rd_kafka_consume(rx_topic, partition, 0);
	if (rkmessage != NULL) {

		if (!rkmessage->err && rkmessage->len > 0) {

			DLOGTR2(PRIO_LOW, "%s: message in log %zu\n",
			     g_pname, rkmessage->len);

			buf->dtbd_data = dt_zalloc(dtp, rkmessage->len);
			if (buf->dtbd_data == NULL) {

				dt_free(dtp, buf);
				return -1;
			}
			buf->dtbd_size = rkmessage->len;
			buf->dtbd_cpu = cpu;

			memcpy(buf->dtbd_data, rkmessage->payload,
			    rkmessage->len);
		} else {
			if (rkmessage->err ==
			    RD_KAFKA_RESP_ERR__PARTITION_EOF) {
				DLOGTR1(PRIO_HIGH,
				    "%s: no message in log\n", g_pname);
			}
		}

		rd_kafka_message_destroy(rkmessage);
	}

	*bufp = buf;
	return 0;
}

static void
dtc_put_buf(dtrace_hdl_t *dtp, dtrace_bufdesc_t *buf)
{

	DL_ASSERT(dtp != NULL, ("DTrace handle cannot be NULL"));
	DL_ASSERT(buf != NULL, ("Buffer instance to free cannot be NULL"));
	DL_ASSERT(buf->dtbd_data != NULL,
	    ("Buffer data pointer cannot be NULL"));

	dt_free(dtp, buf->dtbd_data);
	dt_free(dtp, buf);
}

static int
dtc_buffered_handler(const dtrace_bufdata_t *buf_data, void *arg)
{
	rd_kafka_topic_t *tx_topic = (rd_kafka_topic_t *) arg;
	static struct dl_bbuf *output_buf = NULL;
	size_t buf_len;
	int rc;

	DL_ASSERT(tx_topic != NULL, ("Transmit topic cannot be NULL"));

	buf_len = strlen(buf_data->dtbda_buffered);

	/* '{' indicates the start of the JSON message.
	 * Allocate a buffer into which the message is written.
	 */
	if (buf_data->dtbda_buffered[0] == '{') {

		DLOGTR0(PRIO_LOW, "Start of JSON message\n");
		dl_bbuf_new_auto(&output_buf) ;
	} 

	/* Buffer the received data until the end of the JSON message 
	 * is received.
	 * */
	dl_bbuf_bcat(output_buf, buf_data->dtbda_buffered, buf_len);

	/* '}' indicates the start of the JSON message.
	 * Allocate a buffer into which the message is written.
	 */
	if (buf_data->dtbda_buffered[0] == '}') {

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
			rd_kafka_topic_name(rx_topic),
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
				rd_kafka_poll(tx_rk, 1000 /*block for max 1000ms*/);
				goto retry;
			}
		} else {
			DLOGTR2(PRIO_LOW,
			    "%% Enqueued message (%zd bytes) for topic %s\n",
			    buf_len, rd_kafka_topic_name(tx_topic));
		}

		/* Free the buffer for the start of the next JSON message */
		dl_bbuf_delete(output_buf);
		output_buf = NULL;
	}
	return 0;
}

static int
dtc_setup_rx_topic(char *topic_name, char *brokers)
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
		    g_pname, rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_err;
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

	if (rd_kafka_conf_set(conf, "group.id", g_pname,
	    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {

                DLOGTR1(PRIO_HIGH, "%s\n", errstr);
		goto configure_rx_topic_new_err;
        }

	/* Create the Kafka consumer.
	 * The configuration instance does not need to be freed after
	 * this succeeds.
	 */
	if (!(rx_rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr,
	    sizeof(errstr)))) {

		DLOGTR2(PRIO_HIGH, "%s: failed to create Kafka consumer: %s\n",
		    g_pname, errstr);
		goto configure_rx_topic_new_err;
	}

	if (!(rx_topic = rd_kafka_topic_new(rx_rk, topic_name, NULL))) {

		DLOGTR3(PRIO_HIGH,
		    "%s: failed to create Kafka topic %s: %s\n",
		    g_pname, topic_name,
		    rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_rx_topic_new_err;
	}

	return 0;

configure_rx_topic_new_err:
	rd_kafka_destroy(rx_rk);

configure_rx_topic_conf_err:
	rd_kafka_conf_destroy(conf);

configure_rx_topic_err:
	return -1;

}

static int
dtc_setup_tx_topic(char *topic_name, char *brokers)
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
		    g_pname, rd_kafka_err2str(rd_kafka_last_error()));
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

	/* Create the Kafka producer.
	 * The configuration instance does not need to be freed after
	 * this succeeds.
	 */
	if (!(tx_rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr,
	    sizeof(errstr)))) {

		DLOGTR2(PRIO_HIGH,
		    "%s: failed to create Kafka consumer: %s\n",
		    g_pname, errstr);
		goto configure_tx_topic_conf_err;
	}

	if (!(tx_topic = rd_kafka_topic_new(tx_rk, topic_name, NULL))) {

		DLOGTR3(PRIO_HIGH,
		    "%s: failed to create Kafka topic %s: %s\n",
		    g_pname, topic_name,
		    rd_kafka_err2str(rd_kafka_last_error()));
		goto configure_tx_topic_new_err;
	}

	return 0;

configure_tx_topic_new_err:
	rd_kafka_destroy(tx_rk);

configure_tx_topic_conf_err:
	rd_kafka_conf_destroy(conf);

configure_tx_topic_err:
	return -1;
}

static void
dtc_close_pidfile(void)
{

	/* Unlink the dlogd pid file. */	
	DLOGTR0(PRIO_LOW, "Unlinking dlogd pid file\n");
	if (unlink(DTC_PIDFILE) == -1 && errno != ENOENT)
		DLOGTR0(PRIO_HIGH,
		    "Error unlinking ddtrace_consumer pid file\n");
}

static int
dtc_register_daemon(void)
{
	FILE * pidfile;
	struct sigaction act;
	int fd;
	pid_t pid;

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = dtc_intr;
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);

	if ((pidfile = fopen(DTC_PIDFILE, "a")) == NULL) {
	
		DLOGTR0(PRIO_HIGH,
		    "Failed to open pid file for DDTrace consumer\n");
		return (-1);
	}

	/* Attempt to lock the pid file; if a lock is present, exit. */
	fd = fileno(pidfile);
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to lock pid file for DDTrace consumer\n");
		return (-1);
	}

	pid = getpid();
	ftruncate(fd, 0);
	if (fprintf(pidfile, "%u\n", pid) < 0) {

		/* Should not start the daemon. */
		DLOGTR0(PRIO_HIGH,
		    "Failed write pid file for DDTrace consumer\n");
	}

	fflush(pidfile);
	atexit(dtc_close_pidfile);
	return 0;
}

/*
 * Prototype distributed dtrace agent.
 * The agent recieves DTrace records from an Apache Kafka topic and prints
 * them using libdtrace.
 */
int
main(int argc, char *argv[])
{
	dtrace_consumer_t con;
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	dtrace_hdl_t *dtp;
	FILE *fp = NULL;
	int64_t start_offset = RD_KAFKA_OFFSET_STORED;
	int c, err, partition = 0, ret = 0, script_argc = 0;
	char *args, *brokers = NULL, *rx_topic_name = NULL;
	char *tx_topic_name = NULL;
	char **script_argv;
	int fds[2];
	bool debug = false;

	g_pname = basename(argv[0]); 	

	/** Allocate space required for any arguments being passed to the
	 *  D-language script.
	 */
	script_argv = (char **) malloc(sizeof(char *) * argc);
	if (script_argv == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "%s: failed to allocate script arguments\n", g_pname);
		exit(EXIT_FAILURE);
	}

	opterr = 0;
	for (optind = 0; optind < argc; optind++) {
		while ((c = getopt(argc, argv, "b:di:o:s:x")) != -1) {
			switch(c) {
			case 'b':
				brokers = optarg;
				break;
			case 'd':
				debug = true;
				break;
			case 'i':
				rx_topic_name = optarg;
				break;
			case 'o':
				tx_topic_name = optarg;
				break;
			case 's':
				if ((fp = fopen(optarg, "r")) == NULL) {

					DLOGTR2(PRIO_HIGH,
					    "%s: failed to open script file "
					    "%s\n", optarg, g_pname);
					ret = -1;
					goto free_script_args;
				}
				break;
			case 'x': 
				start_offset = RD_KAFKA_OFFSET_BEGINNING;
				break;
			case '?':
			default:
				dtc_usage(stderr);
				ret = -1;
				goto free_script_args;
			}
		}

		if (optind < argc)
			script_argv[script_argc++] = argv[optind];
	}

	if (brokers == NULL || rx_topic_name == NULL || fp == NULL) {

		dtc_usage(stderr);
		ret = -1;
		goto free_script_args;
	}

	/* Daemonise */
	if (debug == false && daemon(0, 0) == -1) {

		DLOGTR0(PRIO_HIGH, "Failed registering dlogd as daemon\n");
		ret = -1;
		goto free_script_args;
	}
	
	DLOGTR1(PRIO_LOW, "%s daemon starting...\n", g_pname);

	if (dtc_register_daemon() != 0) {

		DLOGTR0(PRIO_HIGH, "Failed registering dlogd as daemon\n");
		ret = -1;
		goto free_script_args;
	}

	if (dtc_setup_rx_topic(rx_topic_name, brokers) != 0){

		DLOGTR1(PRIO_HIGH, "Failed to setup receive topic %s\n",
		    rx_topic_name);
		ret = -1;
		goto free_script_args;
	}

	if (rd_kafka_consume_start(rx_topic, partition, start_offset) == -1) {

		DLOGTR2(PRIO_HIGH, "%s: failed to start consuming: %s\n",
		    g_pname, rd_kafka_err2str(rd_kafka_last_error()));
		if (errno == EINVAL) {
	        	DLOGTR1(PRIO_HIGH,
			    "%s: broker based offset storage "
			    "requires a group.id, "
			    "add: -X group.id=yourGroup\n", g_pname);
		}
		ret = -1;
		goto destroy_rx_kafka;
	}
	
	con.dc_consume_probe = chew;
	con.dc_consume_rec = chewrec;
	con.dc_put_buf = dtc_put_buf;
	con.dc_get_buf = dtc_get_buf;

	if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {

		DLOGTR2(PRIO_HIGH, "%s: failed to initialize dtrace %s",
		    g_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		ret = -1;
		goto destroy_rx_kafka;
	}
	DLOGTR1(PRIO_LOW, "%s: dtrace initialized\n", g_pname);

	/* Configure dtrace.
	 * Trivially small buffers can be configured as trace collection
	 * does not occure locally.
	 * Desctructive tracing prevents dtrace from being terminated
	 * (though this shouldn't happen as tracing is nver enabled).
	 */
	(void) dtrace_setopt(dtp, "aggsize", "4k");
	(void) dtrace_setopt(dtp, "bufsize", "4k");
	(void) dtrace_setopt(dtp, "bufpolicy", "switch");
	(void) dtrace_setopt(dtp, "destructive", "1");
	DLOGTR1(PRIO_LOW, "%s: dtrace options set\n", g_pname);

	if ((prog = dtrace_program_fcompile(dtp, fp,
	    DTRACE_C_PSPEC | DTRACE_C_CPP, script_argc, script_argv)) == NULL) {

		DLOGTR2(PRIO_HIGH, "%s: failed to compile dtrace program %s",
		    g_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		ret = -1;
		goto destroy_dtrace;
	}
	DLOGTR1(PRIO_LOW, "%s: dtrace program compiled\n", g_pname);
	
	(void) fclose(fp);
	
	if (dtrace_program_exec(dtp, prog, &info) == -1) {

		DLOGTR2(PRIO_HIGH, "%s: failed to enable dtrace probes %s",
		    g_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		ret = -1;
		goto destroy_dtrace;
	}
	DLOGTR1(PRIO_LOW, "%s: dtrace probes enabled\n", g_pname);

	/* If the transmit topic name is configured create a new tranmitting
	 * topic and register a buffered handler to write to this
	 * topic with dtrace.
	 */
        if (tx_topic_name != NULL) {	
		if (dtc_setup_tx_topic(tx_topic_name, brokers)
		    != 0) {
	
			ret = -1;
			goto destroy_dtrace;
		}

		if (dtrace_handle_buffered(dtp, dtc_buffered_handler,
		    tx_topic) == -1) {

			DLOGTR2(PRIO_HIGH,
			    "%s: failed registering dtrace "
			    "buffered handler %s",
			    g_pname, dtrace_errmsg(dtp, dtrace_errno(dtp)));
			ret = -1;
			goto destroy_tx_kafka;
		}
	}

	int done = 0;
	do {
		if (!done || !g_intr)
			sleep(1);	

		if (done || g_intr) {
			done = 1;
		}

		/* Poll to handle delivery reports. */
		rd_kafka_poll(tx_rk, 0);

		switch (dtrace_work_detached(dtp, NULL, &con, rx_topic)) {
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_OKAY:
			break;
		case DTRACE_WORKSTATUS_ERROR:
		default:
			if (dtrace_errno(dtp) != EINTR) 
				DLOGTR2(PRIO_HIGH, "%s : %s", g_pname,
				    dtrace_errmsg(dtp, dtrace_errno(dtp)));
				done = 1;
			break;
		}

	} while (!done);


destroy_tx_kafka:
	rd_kafka_flush(tx_rk, 10*1000);

	if (tx_topic_name != NULL) {	
		/* Destroy the Kafka transmit topic */
		DLOGTR1(PRIO_LOW, "%s: destroy kafka transmit topic\n",
		    g_pname);
		rd_kafka_topic_destroy(tx_topic);

		/* Destroy the Kafka transmit handle. */
		DLOGTR1(PRIO_LOW, "%s: destroy kafka transmit handle\n",
		    g_pname);
		rd_kafka_destroy(tx_rk);
	}

destroy_dtrace:
	/* Destroy dtrace the handle. */
	DLOGTR1(PRIO_LOW, "%s: closing dtrace\n", g_pname);
	dtrace_close(dtp);

destroy_rx_kafka:
	DLOGTR1(PRIO_LOW, "%s: destroy kafka receive topic\n", g_pname);

	rd_kafka_consume_stop(rx_rk, partition);

	/* Destroy the Kafka receive topic */
	rd_kafka_topic_destroy(rx_topic);

	/* Destroy the Kafka recieve handle. */
	DLOGTR1(PRIO_LOW, "%s: destroy kafka receive handle\n", g_pname);
	rd_kafka_destroy(rx_rk);

	/* Let background threads clean up and terminate cleanly. */
	int run = 5;
	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
		printf("Waiting for librdkafka to decommission\n");
	if (run <= 0)
		rd_kafka_dump(stdout, rx_rk);

free_script_args:	
	/* Free the memory used to hold the script arguments. */	
	free(script_argv);

	return ret;
}
