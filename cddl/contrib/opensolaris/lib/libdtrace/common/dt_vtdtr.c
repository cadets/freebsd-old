/*-
 * Copyright (c) 2020 Domagoj Stolfa
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


#include <sys/dtrace.h>

#include <dt_impl.h>
#include <dt_program.h>
#include <dtrace.h>
#include <dt_vtdtr.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>

#include <sys/vtdtr.h>

typedef struct dt_vtdtrhdl {
	int			dtvt_fd;
	int			dtvt_err;
	struct vtdtr_conf	dtvt_conf;
} dt_vtdtrhdl_t;

static int
dt_vtdtr_notify(dt_vtdtrhdl_t *hdl, size_t event, void *arg)
{
	struct vtdtr_event ev;
	ssize_t res;
	size_t l;

	memset(&ev, 0, sizeof(ev));
	res = 0;
	l = 0;

	if (hdl == NULL)
		return (-1);

	switch (event) {
	case VTDTR_EV_ELF:
		l = strlcpy(ev.args.elf_file.path, arg, MAXPATHLEN);
		if (l >= MAXPATHLEN)
			return (-1);
	default:
		return (-1);
	}

	ev.type = event;

	res = write(hdl->dtvt_fd, &ev, sizeof(ev));
	if (res == -1)
		hdl->dtvt_err = errno;
	
	return (res);
}

static int
dt_vtdtr_conf(dt_vtdtrhdl_t *hdl, size_t flags, sbintime_t timeout)
{

	hdl->dtvt_conf.timeout = timeout;
	hdl->dtvt_conf.event_flags = flags;
	return (ioctl(hdl->dtvt_fd, VTDTRIOC_CONF, &hdl->dtvt_conf));
}

const char *
dt_vtdtr_errno(dt_vtdtrhdl_t *hdl)
{
	if (hdl == NULL)
		return (NULL);

	if (hdl->dtvt_err == 0)
		return (NULL);

	return (strerror(hdl->dtvt_err));
}

dt_vtdtrhdl_t *
dt_vtdtr_open(void)
{
	dt_vtdtrhdl_t *hdl;
	int err;

	hdl = NULL;
	err = 0;

	hdl = malloc(sizeof(dt_vtdtrhdl_t));
	if (hdl == NULL)
		return (NULL);

	memset(hdl, 0, sizeof(dt_vtdtrhdl_t));

	err = dt_vtdtr_conf(hdl, 1 << VTDTR_EV_RECONF, 0);
	if (err) {
		free(hdl);
		hdl = NULL;
	}

	return (hdl);
}

void
dt_vtdtr_close(dt_vtdtrhdl_t *hdl)
{
	if (hdl == NULL)
		return;

	if (hdl->dtvt_fd != -1)
		close(hdl->dtvt_fd);

	free(hdl);
}

int
dt_vtdtr_elfnotify(dt_vtdtrhdl_t *hdl, const char *path)
{

	return (dt_vtdtr_notify(hdl, VTDTR_EV_ELF, (void *)path));
}
