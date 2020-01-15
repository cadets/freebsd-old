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

// TODO(MARA): cleanup include files

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/vtdtr.h>
#include <sys/types.h>
#include <sys/stat.h>

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

// TODO(MARA): turn options into pragma, ignore for now, assume we have
// script in file
int execute_script(char *file_path, FILE *log_fp)
{

    FILE *fp;
    int done = 0, err, ret = 0, script_argc = 1;
    static dtrace_hdl_t *dtp;
    char **script_argv;

    // We are just dealing with a file (for now)
    script_argv = malloc(sizeof(char *) * script_argc);
    script_argv[0] = "-s";

    if ((fp = fopen(file_path, "w+")) == NULL)
    {
        fprintf(log_fp, "Failed to open script file: %s", strerror(errno));
        fflush(log_fp);
        ret = -1;
        return ret;
    }

    if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL)
    {
        fprintf(log_fp, "Failed to initialize dtrace : %s\n", dtrace_errmsg(dtp, err));
        fflush(log_fp);
        ret = -1;
        goto destroy_dtrace;
    }

    fprintf(log_fp, "Successfully opened DTrace\n");
    fflush(log_fp);

    dtrace_prog_t *prog;
    dtrace_proginfo_t info;

    /*if((prog = dtrace_program_fcompile(dtp, fp, DTRACE_C_PSPEC | DTRACE_C_CPP, 0, NULL )) == NULL) {
        fprintf(log_fp, "Failed to compile the DTrace program: %s\n", dtrace_errmsg(dtp,dtrace_errno(dtp)));
        fflush(log_fp);
        ret = -1;
        goto destroy_dtrace;
    }*/

    if ((prog = dtrace_program_fcompile(dtp, fp, DTRACE_C_PSPEC | DTRACE_C_EMPTY, script_argc, script_argv)) == NULL)
    {
        fprintf(log_fp, "Failed to compile the DTrace program: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
        fflush(log_fp);
        ret = -1;
        goto destroy_dtrace;
    }

    fprintf(log_fp, "Dtrace program successfully compiled \n");
    fflush(fp);

    if (dtrace_program_exec(dtp, prog, &info) == -1)
    {
        fprintf(log_fp, "Failed to enable DTrace probes: %s \n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
        fflush(fp);
        ret = -1;
        goto destroy_dtrace;
    }

    if (dtrace_go(dtp) != 0)
    {
        fprintf(log_fp, "Failed to start instrumentation: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
        ret = -1;
        goto destroy_dtrace;
    }

    fprintf(log_fp, "All good. :)\n");
    fflush(fp);

    // print??

destroy_dtrace:
    fprintf(log_fp, "Closing DTrace\n");
    fflush(log_fp);
    dtrace_close(dtp);
    fclose(fp);

    return ret;
}

// TODO(MARA): Cleanup after this works
// TODO(MARA): Figure out why syslogd doesn't work in the virtual machine. Is
// syslogd the best option? Alternative is implementing better custom logging.
int main(int argc, char **argv)
{
    int fd;
    int script_len;
    char *script;

    FILE *log_fp;
    FILE *script_fp;

    // TODO(MARA): syslog in the VM is not working so have a custom one for now
    if ((log_fp = fopen("/tmp/log.txt", "w+")) == NULL)
    {
        printf("Error opening file: %s \n", strerror(errno));
    }

    fprintf(log_fp, "In vm_ddtrace_reader.. \n");
    fflush(log_fp);

    /* Daemonise first*/
    if (daemon(0, 0) == -1)
    {
        fprintf(log_fp, "Failed registering vm_ddtrace_reader as a daemon. \n");
        fprintf(log_fp, "Daemon error is %s\n", strerror(errno));
        fflush(log_fp);
        exit(1);
    }

    fprintf(log_fp, "Successfully daemonised.\n");

    if ((fd = open("/dev/vtdtr", O_RDWR)) == -1)
    {
        fprintf("Error opening device driver %s\n", strerror(errno));
        fflush(log_fp);
        exit(1);
    }

    fprintf(log_fp, "Subscribing to events.. \n");

    struct vtdtr_conf *vtdtr_conf = malloc(sizeof(struct vtdtr_conf));
    vtdtr_conf->event_flags |= (1 << VTDTR_EV_SCRIPT) | (1 << VTDTR_EV_RECONF);
    vtdtr_conf->timeout = 0;

    fprintf(log_fp, "Configurarion has %zd \n", vtdtr_conf->event_flags);
    fflush(log_fp);

    if ((ioctl(fd, VTDTRIOC_CONF, vtdtr_conf)) != 0)
    {
        fprintf(log_fp, "Fail to subscribe to script event in /dev/vtdtr. Error is %s \n", strerror(errno));
        fflush(log_fp);
        exit(1);
    }

    fprintf(log_fp, "Successfully subscribed to events. \n");

    fprintf(log_fp, "Reading.. \n");
    fflush(log_fp);

    struct vtdtr_event *ev;
    ev = (struct vtdtr_event *)malloc(sizeof(struct vtdtr_event));

    if (read(fd, ev, sizeof(struct vtdtr_event)) == -1)
    {
        fprintf(log_fp, "Error while reading %s", strerror(errno));
        fflush(log_fp);
        exit(1);
    }

    fprintf(log_fp, "Got %s \n", ev->args.d_script.script);
    fflush(log_fp);

    close(fd);

    int len = strlen(ev->args.d_script.script) + 1;
    fprintf(log_fp, "Length of the script is %d. \n", len - 1);
    fflush(log_fp);
    script = (char *)malloc(sizeof(char) * len);

    strlcpy(script, ev->args.d_script.script, len);
    script[len] = '\0';
    fprintf(log_fp, "Copied script %s \n.", script);
    fflush(log_fp);

    char *script_file_path = "/tmp/script.d";

    if ((script_fp = fopen(script_file_path, "w+")) == NULL)
    {
        fprintf(log_fp, "Error opening script file %s: %s \n.", script_file_path, strerror(errno));
        fflush(script_fp);
        exit(1);
    }

    if (fwrite(script, sizeof(char), len - 1, script_fp) != len - 1)
    {
        fprintf(log_fp, "Haven't written the entire script to file - stop. \n");
        fflush(log_fp);
        exit(1);
    }

    if (ferror(script_fp))
    {
        fprintf(log_fp, "Error occured while writing in the script file. \n");
        fflush(log_fp);
        exit(1);
    }

    free(script);
    free(ev);

    fprintf(log_fp, "Execute script.. \n");
    fflush(log_fp);

    if ((execute_script(script_file_path, log_fp)) != 0)
    {
        fprintf(log_fp, "Error occured while trying to execute the script. \n");
    }

    fprintf(log_fp, "Closing log file. \n");
    fflush(log_fp);
    fclose(log_fp);
    return 0;
}
