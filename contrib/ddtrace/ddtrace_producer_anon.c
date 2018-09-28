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

#include <sys/types.h>
#include <sys/nv.h>

#include <dt_impl.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "dlog.h"
#include "dl_config.h"

static char *g_pname;
static int g_status = 0;
static int g_intr;
static dtrace_hdl_t *g_dtp;

static inline void 
usage(FILE * fp)
{

	(void) fprintf(fp, "Usage: %s -t topic\n", g_pname);
}

/*ARGSUSED*/
static void
intr(int signo)
{

	g_intr = 1;
}
	
/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	dtrace_eprobedesc_t *ed = data->dtpda_edesc;
	processorid_t cpu = data->dtpda_cpu;

	fprintf(stdout, "dtpd->id = %u\n", pd->dtpd_id);
	fprintf(stdout, "dtepd->id = %u\n", ed->dtepd_epid);
	fprintf(stdout, "dtpd->func = %s\n", pd->dtpd_func);
	fprintf(stdout, "dtpd->name = %s\n", pd->dtpd_name);

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

	fprintf(stdout, "chewrec %p\n", rec);
	fprintf(stdout, "dtrd_action %u\n", rec->dtrd_action);
	fprintf(stdout, "dtrd_size %u\n", rec->dtrd_size);
	fprintf(stdout, "dtrd_alignment %u\n", rec->dtrd_alignment);
	fprintf(stdout, "dtrd_format %u\n", rec->dtrd_format);
	fprintf(stdout, "dtrd_arg  %lu\n", rec->dtrd_arg);
	fprintf(stdout, "dtrd_uarg  %lu\n", rec->dtrd_uarg);

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	if (act == DTRACEACT_EXIT) {
		g_status = *((uint32_t *) addr);
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS); 
}

/*PRINTFLIKE1*/
static void
dfatal(const char *fmt, ...)
{
#if !defined(illumos) && defined(NEED_ERRLOC)
        char *p_errfile = NULL;
        int errline = 0;
#endif
        va_list ap;

        va_start(ap, fmt);

        (void) fprintf(stderr, "%s: ", g_pname);
        if (fmt != NULL)
                (void) vfprintf(stderr, fmt, ap);

        va_end(ap);

        if (fmt != NULL && fmt[strlen(fmt) - 1] != '\n') {
                (void) fprintf(stderr, ": %s\n",
                    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
        } else if (fmt == NULL) {
                (void) fprintf(stderr, "%s\n",
                    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
        }
#if !defined(illumos) && defined(NEED_ERRLOC)
        dt_get_errloc(g_dtp, &p_errfile, &errline);
        if (p_errfile != NULL)
                printf("File '%s', line %d\n", p_errfile, errline);
#endif

        /*
         * Close the DTrace handle to ensure that any controlled processes are
         * correctly restored and continued.
         */
        dtrace_close(g_dtp);

        exit(EXIT_FAILURE);
}

/*
 * Prototype distributed dtrace agent.
 * The agent reveices D-Language scripts from a Apache Kafka topic. For each
 * script a new processes is forked. The process compiles the D-Language script
 * and sends the resulting DOF file to the kernel for execution. Results are
 * returned through another Apache Kafka topic.
 */
int
main(int argc, char *argv[])
{
	struct dl_client_config_desc *client_conf;
	dtrace_consumer_t con;
	nvlist_t *props;
	char *topic_name;
	size_t packed_len;
	int dlog, rc, c, err;
	char errstr[512], konarg[13];

	g_pname = basename(argv[0]); 	

	if (argc == 1) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	opterr = 0;
	while ((c = getopt(argc, argv, "t:")) != -1) {
		switch(c) {
		case 't':
			topic_name = optarg;
			break;
		case '?':
		default:
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (topic_name == NULL) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	dlog = open("/dev/dlog", O_RDWR);
	if (dlog == -1) {
		fprintf(stderr, "%s failed to open dev dlog: %d\n",
		    g_pname, errno);
		exit(EXIT_FAILURE);
	}

	props = nvlist_create(0);
	if (props == NULL) {
		fprintf(stderr, "%s failed to create nvlist : %d\n",
		    g_pname, errno);
		close(dlog);
		exit(EXIT_FAILURE);
	}

	nvlist_add_string(props, DL_CONF_TOPIC, topic_name);

	client_conf = (struct dl_client_config_desc *) malloc(
	    sizeof(struct dl_client_config_desc));
	if (client_conf == NULL) {
		fprintf(stderr, "%s failed to allocate client config: %d\n",
		    g_pname, errno);
		nvlist_destroy(props);
		close(dlog);
		exit(EXIT_FAILURE);
	}

	client_conf->dlcc_packed_nvlist = nvlist_pack(props, &packed_len); 
	client_conf->dlcc_packed_nvlist_len = packed_len;

	rc = ioctl(dlog, DLOGIOC_PRODUCER, &client_conf);	
	if (rc != 0) {
		fprintf(stderr, "%s failed to create producer: %d\n",
		    g_pname, errno);
		nvlist_destroy(props);
		close(dlog);
		exit(EXIT_FAILURE);
	}

	con.dc_consume_probe = chew;
	con.dc_consume_rec = chewrec;
	con.dc_put_buf = NULL; 
	con.dc_get_buf = NULL;

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		fprintf(stderr, "%s failed to initialize dtrace: %s\n",
		    g_pname, dtrace_errmsg(g_dtp, err));
		exit(EXIT_FAILURE);
	}
	fprintf(stdout, "%s: dtrace initialized\n", g_pname);

	(void) dtrace_setopt(g_dtp, "aggsize", "4m");
	(void) dtrace_setopt(g_dtp, "bufsize", "4m");
	(void) dtrace_setopt(g_dtp, "bufpolicy", "switch");
	sprintf(konarg, "%d", dlog);
	(void) dtrace_setopt(g_dtp, "konarg", konarg);
	//(void) dtrace_setopt(g_dtp, "grabanon", "1");
	printf("%s: dtrace options set\n", g_pname);

/*
	dtrace_prog_t * prog;
	if ((prog = dtrace_program_fcompile(g_dtp, fp,
		DTRACE_C_PSPEC, 0, NULL)) == NULL) {
		dfatal("failed to compile dtrace program: %s\n", script);
	}
	fprintf(stdout, "%s: dtrace program compiled\n", g_pname);

	dtrace_prog_t * prog;
	if ((prog = dtrace_program_strcompile(g_dtp, script,
		DTRACE_PROBESPEC_NAME, DTRACE_C_PSPEC, 0, NULL)) == NULL) {
		dfatal("failed to compile dtrace program: %s\n", script);
	}
	fprintf(stdout, "%s: dtrace program compiled\n", g_pname);

	dtrace_proginfo_t info;
	if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
		dfatal("failed to enable dtrace probes\n");
	}
	fprintf(stdout, "%s: dtrace probes enabled\n", g_pname);
*/

	struct sigaction act;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);

	if (dtrace_go(g_dtp) != 0) {
		dfatal("could not start dtrace instrumentation\n");
	}
	fprintf(stdout, "%s: dtrace instrumentation started...\n", g_pname);

	int done = 0;
	do {
		if (!g_intr && !done) {
			dtrace_sleep(g_dtp);
		}

		if (done || g_intr) {
			done = 1;
			if (dtrace_stop(g_dtp) == -1) {
				dfatal("could not stop tracing\n");
			}
		}
		
		switch (dtrace_work(g_dtp, stdout, &con, NULL)) {
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_OKAY:
			break;
		case DTRACE_WORKSTATUS_ERROR:
		default:
			if (dtrace_errno(g_dtp) != EINTR) 
				fprintf(stderr, "%s",
				    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
				dfatal("processing aborted\n");
			break;
		}
	} while (!done);

destroy_nvlist:
	nvlist_destroy(props);

close_dlog:
	close(dlog);

destroy_dtrace:
	/* Destroy dtrace the handle. */
	fprintf(stdout, "%s: closing dtrace\n", g_pname);
	dtrace_close(g_dtp);

	return (0);
}

