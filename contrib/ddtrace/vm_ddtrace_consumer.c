/*-
 * Copyright (c) 2019 (Mara Mihali)
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/vtdtr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/nv.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <syslog.h>
#include <dtrace.h>
#include <vtdtr.h>
#include <dl_config.h>
#include <dlog.h>
#include <signal.h>
#include <time.h>

static int daemon_debug;
#define DAEMON_LOG(params) if (daemon_debug) log params

static char *directory_path = "/var/dtrace_log";
static char *script_path = "/var/dtrace_log/script.d";
static char *logging_file_path = "/var/dtrace_log/log_file.txt";
static char *script;
FILE *log_fp;


static dtrace_hdl_t *g_dtp;
static int g_intr, g_status = 0;

static void
log(FILE *fp, char *fmt,...)
{
    va_list args;
    va_start(args,fmt);
    vfprintf(fp, fmt, args);
    fflush(fp);
    va_end(args);
}

/*ARGSUSED*/
static void
intr(int signo)
{
    g_intr = 1;
}

static int
get_script_events()
{
    FILE *script_fp;
    struct vtdtr_conf *vtdtr_conf;
    struct vtdtr_event *ev;
    size_t script_len;
    int fd, last = 0;

    if ((fd = open("/dev/vtdtr", O_RDWR)) == -1)
    {
        DAEMON_LOG((log_fp, "Error opening device driver %s\n", strerror(errno)));
        return -1;
    }

    DAEMON_LOG((log_fp, "Subscribing to events.. \n"));

    vtdtr_conf = malloc(sizeof(struct vtdtr_conf));
    vtdtr_conf->event_flags |= (1 << VTDTR_EV_SCRIPT) | (1 << VTDTR_EV_RECONF);
    vtdtr_conf->timeout = 0;

    if ((ioctl(fd, VTDTRIOC_CONF, vtdtr_conf)) != 0)
    {
        DAEMON_LOG((log_fp, "Failed to subscribe to script event in device driver: %s.\n", strerror(errno)));
        return -1;
    }

    DAEMON_LOG((log_fp, "Successfully subscribed to events. \n"));

    DAEMON_LOG((log_fp, "Waiting for script.. \n"));

    if ((script_fp = fopen(script_path, "w+")) == NULL)
    {
        DAEMON_LOG((log_fp, "Error opening script file %s: %s \n.", script_path, strerror(errno)));
        return -1;
    }

    do
    {
        ev = malloc(sizeof(struct vtdtr_event));
        memset(ev, 0, sizeof(struct vtdtr_event));

        if (read(fd, ev, sizeof(struct vtdtr_event)) < 0)
        {
            DAEMON_LOG((log_fp, "Error while reading %s", strerror(errno)));
            return -1;
        }

        DAEMON_LOG((log_fp, "Got %s \n", ev->args.d_script.script));
        int len = strlen(ev->args.d_script.script) + 1;
        DAEMON_LOG((log_fp, "Length of the script is %d. \n", len - 1));
        script = malloc(sizeof(char) * len);

        strlcpy(script, ev->args.d_script.script, len);
        script[len] = '\0';
        DAEMON_LOG((log_fp, "Copied script %s \n.", script));

        if (fwrite(script, 1, len - 1, script_fp) != len - 1)
        {
            DAEMON_LOG((log_fp, "Haven't written the entire script to file - stop. \n"));
            return -1;
        }

        if (ferror(script_fp))
        {
            DAEMON_LOG((log_fp, "Error occured while writing in the script file. \n"));
            return -1;
        }

        last = ev->args.d_script.last;

        free(script);
        free(ev);

    } while (!last);

    close(fd);
    fflush(script_fp);
    fclose(script_fp);

    return 0;
}

static int
vm_dtrace_consumer()
{

    FILE *fp;
    struct dl_client_config_desc *client_conf;
    dtrace_prog_t *prog;
    dtrace_proginfo_t info;
    nvlist_t *props;
    size_t packed_len;
    char **script_argv;
    char *topic_name;
    char ddtracearg[13];
    int dlog, done = 0, err, ret = 0, rc, script_argc;

    topic_name = "cadets-trace";

    if ((fp = fopen(script_path, "r+")) == NULL)
    {
        DAEMON_LOG((log_fp, "Failed to open script file: %s", strerror(errno)));
        ret = -1;
        return ret;
    }

    dlog = open("/dev/dlog", O_RDWR);
    if (dlog == -1)
    {
        DAEMON_LOG((log_fp, "Failed to open dlog: %s", strerror(errno)));
        ret = -1;
        return ret;
    }

    props = nvlist_create(0);
    nvlist_add_string(props, DL_CONF_TOPIC, topic_name);

    client_conf = (struct dl_client_config_desc *)malloc(
        sizeof(struct dl_client_config_desc));
    if (client_conf == NULL)
    {

        DAEMON_LOG((log_fp, "Failed to allocate client config: %s\n",
                strerror(errno)));
        ret = -1;
        return ret;
    }

    client_conf->dlcc_packed_nvlist = nvlist_pack(props, &packed_len);
    client_conf->dlcc_packed_nvlist_len = packed_len;

    rc = ioctl(dlog, DLOGIOC_PRODUCER, &client_conf);
    if (rc != 0)
    {

        DAEMON_LOG((log_fp, "failed to create DLog producer: %s\n",
                strerror(errno)));
        ret = -1;
        return ret;
    }

    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL)
    {
        DAEMON_LOG((log_fp, "Cannot open dtrace library: %s\n", dtrace_errmsg(g_dtp, err)));
        ret = -1;
        goto destroy_dtrace;
    }

    sprintf(ddtracearg, "%d", dlog);
    (void)dtrace_setopt(g_dtp, "ddtracearg", ddtracearg);

    if (dtrace_setopt(g_dtp, "aggsize", "4m") != 0)
    {
        DAEMON_LOG((log_fp, "Failed to set aggregations size: %s. \n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        goto destroy_dtrace;
    }

    if (dtrace_setopt(g_dtp, "bufsize", "4m") != 0)
    {
        DAEMON_LOG((log_fp, "Failed to set buffers size %s. \n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        goto destroy_dtrace;
    }

    if (dtrace_setopt(g_dtp, "bufpolicy", "switch") != 0)
    {
        DAEMON_LOG((log_fp, "Failed to set bufpolicy to switch %s. \n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        goto destroy_dtrace;
    }

    if (dtrace_setopt(g_dtp, "ddtracearg", ddtracearg) != 0)
    {
        DAEMON_LOG((log_fp, "Failed to set ddtracearg: %s. \n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        goto destroy_dtrace;
    }

    DAEMON_LOG((log_fp, "Successfully opened DTrace\n"));
    DAEMON_LOG((log_fp, "About to compile, script is: %s. \n", script));

    if ((prog = dtrace_program_fcompile(g_dtp, fp, 0, 0, NULL)) == NULL)
    {
        DAEMON_LOG((log_fp, "Failed to compile the DTrace program: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        ret = -1;
        goto destroy_dtrace;
    }
    DAEMON_LOG((log_fp, "Dtrace program successfully compiled.\n"));

    if (dtrace_program_exec(g_dtp, prog, &info) == -1)
    {
        DAEMON_LOG((log_fp, "Failed to enable probes: %s \n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        ret = -1;
        goto destroy_dtrace;
    }

    DAEMON_LOG((log_fp, "Dtrace program successfully executed.\n"));

    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = intr;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    if (dtrace_go(g_dtp) != 0)
    {
        DAEMON_LOG((log_fp, "Failed to start instrumentation: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))));
        ret = -1;
        goto destroy_dtrace;
    }

    DAEMON_LOG((log_fp, "DTrace instrumentation started.\n"));

    do
    {
        if (!g_intr && !done)
        {
            dtrace_sleep(g_dtp);
        }

        if (g_intr)
        {
            done = 1;
        }
    } while (!done);

destroy_dtrace:
    DAEMON_LOG((log_fp, "Closing DTrace...\n"));
    dtrace_close(g_dtp);
    return ret;
}

int main(int argc, char **argv)
{

    mkdir(directory_path, 0777);
    if ((log_fp = fopen(logging_file_path, "a+")) == NULL)
    {
            DAEMON_LOG(("Error opening file: %s \n", strerror(errno)));
            exit(1);
    }

    DAEMON_LOG((log_fp, "In vm_ddtrace_consumer.. \n"));

    /* Daemonise first*/
    if (daemon(0, 0) == -1)
    {
        DAEMON_LOG((log_fp, "Failed registering  vm_ddtrace_consumer as a daemon. \n"));
        DAEMON_LOG((log_fp, "Daemon error is %s\n", strerror(errno)));
        exit(1);
    }

    DAEMON_LOG((log_fp, "Successfully daemonised.\n"));
    DAEMON_LOG((log_fp, "Waiting for scripts..\n"));

    // for (;;)
    // {
        if (get_script_events() != 0)
        {
            DAEMON_LOG((log_fp, "Error occured while retrieving and assembling the script"));
            exit(1);
            // break;
        }

        DAEMON_LOG((log_fp, "Start DTrace consumer.. \n"));

        if ((vm_dtrace_consumer()) != 0)
        {
            DAEMON_LOG((log_fp, "Error occured while trying to execute the script. \n"));
            exit(1);
            // break;
        }
        DAEMON_LOG((log_fp, "DTrace consumer finished.. \n"));
   // }

    DAEMON_LOG((log_fp, "Closing log file. \n"));
    fclose(log_fp);

    return 0;
}
