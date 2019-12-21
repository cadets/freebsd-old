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

int main(int argc, char **argv)
{
    int fd;
    int script_len;
    char *script;

    syslog(LOG_ERR, "In vm_ddtrace_reader.. \n");

    /* Daemonise first*/
    if (daemon(0, 0) == -1)
    {
        syslog(LOG_ERR, "Failed registering vm_ddtrace_reader as a daemon. \n");
        syslog(LOG_ERR, "Daemon error %s\n", strerror(errno));
        exit(1);
    }

    syslog(LOG_ERR, "Successfully daemonised.\n");

    if ((fd = open("/dev/vtdtr", O_RDWR)) == -1)
    {
        syslog(LOG_ERR, "Error opening device driver %s\n", strerror(errno));
        exit(1);
    }

    script = (char *)malloc(sizeof(char) * 80);

    syslog(LOG_ERR, "Subscribing to events.. \n");

    static struct vtdtr_conf vtdtr_conf;
    vtdtr_conf.event_flags = 1 << VTDTR_EV_RECONF;
    vtdtr_conf.timeout = 0;

    // this is configuring the device driver, do we need to do this?
    
    if ((ioctl(fd, VTDTRIOC_CONF, &vtdtr_conf)) != 0)
    {
        syslog(LOG_ERR, "Fail to subscribe to script event in /dev/vtdtr. Error is %s", strerror(errno));
        exit(1);
    }

    syslog(LOG_ERR, "Successfully subscribed to events. \n");

    syslog(LOG_ERR, "Reading..");

    struct vtdtr_event ev;

    if (read(fd, &ev, sizeof(struct vtdtr_event)) == -1)
    {
        syslog(LOG_ERR, "Error %s when attempting to read from device driver \n", strerror(errno));
        exit(1);
    }

    syslog(LOG_ERR, "I've read %s. Script is in userspace.\n", ev.args.d_script);
    
    

    close(fd);
    const char *file_path = "/tmp/vtdtr_log";
    FILE *fp;

    syslog(LOG_ERR, "Writing script to file %s", file_path); 

    fwrite(script, sizeof(char), sizeof(script), fp);

    if(ferror(fp)) {
        syslog(LOG_ERR, "Error occured while writing in the file");
        exit(1);
    }

    fclose(fp);

    return 0;
}
