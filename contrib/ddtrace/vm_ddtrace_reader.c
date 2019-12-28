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

#include "vtdtr.h"

// TODO(MARA): Cleanup after this works
// TODO(MARA): Figure out why syslogd doesn't work in the virtual machine. Is
// syslogd the best option?

int main(int argc, char **argv)
{
    int fd;
    int script_len;
    char *script;

    const char *file_path = "/tmp/vtdtr_log";
    FILE *fp;


    if((fp = fopen(file_path, "rw+")) == NULL) {
        printf("Error opening file: %s \n", strerror(errno));
    }

    

    fprintf(fp,"In vm_ddtrace_reader.. \n");
    fflush(fp);

    /* Daemonise first*/
    if (daemon(0, 1) == -1)
    {
        fprintf(fp, "Failed registering vm_ddtrace_reader as a daemon. \n");
        fprintf(fp, "Daemon error is %s\n", strerror(errno));
        fflush(fp);
        exit(1);
    }

    fprintf(fp, "Successfully daemonised.\n");

    if ((fd = open("/dev/vtdtr", O_RDWR)) == -1)
    {
        fprintf("Error opening device driver %s\n", strerror(errno));
        fflush(fp);
        exit(1);
    }

    script = (char *)malloc(sizeof(char) * 80);

    fprintf(fp, "Subscribing to events.. \n");

    struct vtdtr_conf *vtdtr_conf = malloc(sizeof(struct vtdtr_conf));
    vtdtr_conf->event_flags |= (1 << VTDTR_EV_SCRIPT) | (1 << VTDTR_EV_RECONF);
    vtdtr_conf->timeout = 0;

    fprintf(fp, "Configurarion has %zd \n", vtdtr_conf->event_flags);
    fflush(fp);

    if ((ioctl(fd, VTDTRIOC_CONF, vtdtr_conf)) != 0)
    {
        fprintf(fp, "Fail to subscribe to script event in /dev/vtdtr. Error is %s \n", strerror(errno));
        fflush(fp);
        exit(1);
    }

    fprintf( fp, "Successfully subscribed to events. \n");

    fprintf( fp, "Reading.. \n");

    struct vtdtr_event *ev;
    ev = (struct vtdtr_event *) malloc(sizeof(struct vtdtr_event));

    if (read(fd, ev, sizeof(struct vtdtr_event)) == -1)
    {
        fprintf(fp, "Error while reading %s", strerror(errno));
        exit(1);
        fflush(fp);
    }
    
    fprintf(fp, "%s \n", ev->args.d_script);
    
    close(fd);
    
    fwrite(script, sizeof(char), sizeof(script), fp);

    if(ferror(fp)) {
        fprintf(fp, "Error occured while writing in the file");
        fflush(fp);
        exit(1);
    }

    fclose(fp);

    return 0;
}
