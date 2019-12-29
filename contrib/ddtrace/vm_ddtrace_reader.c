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
// #include "dtrace.h"
#include "vtdtr.h"

/*
int execute_script(char *file_path, FILE *log_fp) {

    FILE *fp;
    int done = 0, err, ret = 0, script_argc = 1;
    static dtrace_hdl_t *g_dtp;
    char **script_argv;

    script_argv = malloc(sizeof(char *) * script_argc);
    if (script_argv == NULL) {
        fprintf(log_fp, "Failed to allocate script a")
    }

    if((fp = fopen(file_path,"w+")) == NULL) {
        fprintf(log_fp, "Failed to open script file: %s", strerror(errno));
    }

    if((g_dtp = dtrace_open(3, 0, &err)) == NULL) {
        fprintf(log_fp, "Failed to initialize dtrace : %s\n", dtrace_errmsg(g_dtp,err));
        ret = -1;
        goto destroy_dtrace;
    }

    dtrace_prog_t * prog;
    if((prog = dtrace_program_fcompile(g_dtp, fp, )))
    

    // TODO(MARA): turn options into pragma, ignore for now, assume we have
    // script in file

    dtrace_program_fcompile();
    dtrace_program_exec();
    dtrace_go();
    dtrace_close();

    destroy_dtrace:
        dtrace_close(g_dtp);
    
    close_file:
        fclose(fp);

    return ret;
}*/

// TODO(MARA): Cleanup after this works
// TODO(MARA): Figure out why syslogd doesn't work in the virtual machine. Is
// syslogd the best option?

int main(int argc, char **argv)
{
    int fd;
    int script_len;
    char *script;

    FILE *log_fp;
    FILE *script_fp;

    // TODO(MARA): syslog in the VM is not working so have a custom one for now
    if((log_fp = fopen("/tmp/log.txt", "w+")) == NULL) {
        printf("Error opening file: %s \n", strerror(errno));
    }


    

    fprintf(log_fp,"In vm_ddtrace_reader.. \n");
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

    fprintf( log_fp, "Successfully subscribed to events. \n");

    fprintf(log_fp, "Reading.. \n");
    fflush(log_fp);

    struct vtdtr_event *ev;
    ev = (struct vtdtr_event *) malloc(sizeof(struct vtdtr_event));

    if (read(fd, ev, sizeof(struct vtdtr_event)) == -1)
    {
        fprintf(log_fp, "Error while reading %s", strerror(errno));
        exit(1);
        fflush(log_fp);
    }
    
    fprintf(log_fp, "Got %s \n", ev->args.d_script.script);
    fflush(log_fp);
    
    close(fd);

    int len = strlen(ev->args.d_script.script);
    script = (char *)malloc(sizeof(char) * 80);

    strncpy(script, ev->args.d_script.script, len);
    fprintf(log_fp, "Copied script %s \n.", script);
    fflush(log_fp);

    char *script_file_path = "/tmp/script.d";

    if((script_fp = fopen(script_file_path, "w+")) == NULL) {
        fprintf(log_fp, "Error opening script file %s: %s \n.", script_file_path,strerror(errno));
    }
    
    fwrite(script, sizeof(char), sizeof(script), script_fp);

    if(ferror(script_fp)) {
        fprintf(log_fp, "Error occured while writing in the script file. \n");
        fflush(log_fp);
        exit(1);
    }

    free(script);
    free(ev);

    fprintf(log_fp, "Execute script.. \n");
    fflush(log_fp);
    
    /*if((execute_script(script_file_path, log_fp)) != 0){
        fprintf(log_fp, "Error occured while trying to execute the script: %s \n",
        strerror(errno));
    }*/

    fprintf(log_fp, "Successfully wrote. Closing log file. \n");
    fflush(log_fp);
    fclose(log_fp);



    return 0;
}
