/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
 * All rights reserved.
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
 * $FreeBSD$
 */

#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "dthyve.h"

static int vtdtr_fd = -1;
static struct vtdtr_conf vtdtr_conf;

/*
 * Open the vtdtr device in order to set up the state.
 */
void
dthyve_init(const char *vm __unused)
{
	int error;

	error = 0;

	vtdtr_fd = open("/dev/vtdtr", O_RDWR);
	if (vtdtr_fd == -1) {
		fprintf(stderr, "Error: '%s' opening /dev/vtdtr\n",
		    strerror(errno));
		exit(1);
	}

	error = dthyve_conf(1 << VTDTR_EV_RECONF, 0);
	if (error) {
		fprintf(stderr, "Error: %s attempting to reconfigure /dev/vtdtr\n",
		    strerror(errno));
		exit(1);
	}
}

/*
 * Issues an ioctl to vtdtr to configure itself.
 */
int
dthyve_conf(size_t flags, sbintime_t timeout)
{

	vtdtr_conf.timeout = timeout;
	vtdtr_conf.event_flags = flags;
	return (ioctl(vtdtr_fd, VTDTRIOC_CONF, &vtdtr_conf));
}

/*
 * If we have the file-descriptor, we also have at least the
 * default configuration of the device. Thus, it is sufficient
 * to simply check if the fd is not -1.
 */
int
dthyve_configured(void)
{

	return (vtdtr_fd != -1);
}

/*
 * Read events from the device. This may or may not be a blocking
 * read, depending on the configuration of vtdtr.
 */
int
dthyve_read(struct vtdtr_event *es, size_t n_events)
{
	ssize_t res;

	if (es == NULL || n_events == 0 || vtdtr_fd == -1) {
		return (EINVAL);
	}

	res = read(vtdtr_fd, es, n_events * sizeof(struct vtdtr_event));
	if (res != n_events * sizeof(struct vtdtr_event))
		return (errno);

	return (0);
}

void
dthyve_destroy()
{
	close(vtdtr_fd);
}
