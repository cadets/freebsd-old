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

//#include <sys/dtrace.h>
//#include <sys/uuid.h>
//#include <sys/capsicum.h>
//#include <sys/tree.h>
#include <sys/types.h>
#include <sys/vtdtr.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

//#include <dt_impl.h>
//#include <dt_printf.h>
//#include <dtrace.h>

#include "dthyve.h"

#ifndef VTDTR

static int vtdtr_fd = -1;
static struct vtdtr_conf vtdtr_conf;

void
dthyve_init(const char *vm __unused)
{
	int error;

	error = 0;

	vtdtr_fd = open("/dev/vtdtr", O_RDWR);
	if (vtdtr_fd == -1) {
		fprintf(stderr, "Error: '%s' opening /dev/vtdtr",
		    strerror(errno));
		exit(1);
	}
	
	/*
	 * Default configuration.
	 */
	vtdtr_conf.timeout = 0;
	vtdtr_conf.event_flags = VTDTR_EV_INSTALL | VTDTR_EV_UNINSTALL;

	error = ioctl(vtdtr_fd, VTDTRIOC_CONF, &vtdtr_conf);
	if (error) {
		fprintf(stderr, "Error: '%s' configuring vtdtr",
		    strerror(errno));
		exit(1);
	}
}

int
dthyve_read(struct vtdtr_event *es, size_t n_events)
{
	ssize_t res;

	if (es == NULL || n_events == 0) {
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

#endif

#ifdef VTDTR
static dtrace_hdl_t *g_dtp;
static const char *g_prog = "dthyve";

struct dthyve_prov {
	RB_ENTRY(dthyve_prov) node;
	char                  vm[DTRACE_INSTANCENAMELEN];
	char                  name[DTRACE_PROVNAMELEN];
	struct uuid          *uuid;
	struct uuid          *host_uuid;
};

static int	dthyve_priv_unregister(struct dthyve_prov *);
static int	uuidcmp(const struct uuid *, const struct uuid *);
static int	dthyve_prov_cmp(struct dthyve_prov *, struct dthyve_prov *);

RB_HEAD(dthyve_provtree, dthyve_prov) dthyve_provider_tree =
    RB_INITIALIZER(_dthyve_prov);

RB_GENERATE_STATIC(dthyve_provtree, dthyve_prov, node,
    dthyve_prov_cmp);

int
dthyve_open(void)
{
	int error;

	g_dtp = dtrace_open(DTRACE_VERSION, 0, &error);
	return (error);
}

int
dthyve_register_provider(struct uuid *uuid, const char *vm, const char *name)
{
	dtrace_virt_providerdesc_t virt_pv;
	struct dthyve_prov *pv;
	int error;

	strlcpy(virt_pv.vpvd_instance, vm, DTRACE_INSTANCENAMELEN);
	strlcpy(virt_pv.vpvd_name, name, DTRACE_PROVNAMELEN);
	virt_pv.vpvd_uuid = malloc(sizeof(struct uuid));

	if (virt_pv.vpvd_uuid == NULL)
		return (ENOMEM);

	pv = malloc(sizeof(struct dthyve_prov));

	if (pv == NULL)
		return (ENOMEM);

	pv->uuid = malloc(sizeof(struct uuid));

	if (pv->uuid == NULL)
		return (ENOMEM);

	memcpy(virt_pv.vpvd_uuid, uuid, sizeof(struct uuid));
	memcpy(pv->uuid, uuid, sizeof(struct uuid));

	if ((error = dt_ioctl(g_dtp, DTRACEIOC_PROVCREATE, &virt_pv)) != 0)
		return (error);

	strlcpy(pv->vm, vm, DTRACE_INSTANCENAMELEN);
	strlcpy(pv->name, name, DTRACE_PROVNAMELEN);
	pv->host_uuid = virt_pv.vpvd_uuid;

	RB_INSERT(dthyve_provtree, &dthyve_provider_tree, pv);

	return (0);
}

static int
dthyve_priv_unregister(struct dthyve_prov *pv)
{
	int error;

	error = dt_ioctl(g_dtp, DTRACEIOC_PROVDESTROY, pv->host_uuid);
	RB_REMOVE(dthyve_provtree, &dthyve_provider_tree, pv);
	free(pv->host_uuid);
	free(pv->uuid);
	free(pv);

	return (error);
}

int
dthyve_unregister_provider(struct uuid *uuid)
{
	struct dthyve_prov *pv, tmp;
	tmp.uuid = uuid;

	if (uuid == NULL)
		return (EINVAL);

	pv = RB_FIND(dthyve_provtree, &dthyve_provider_tree, &tmp);
	if (pv == NULL)
		return (ESRCH);

	return (dthyve_priv_unregister(pv));
}

/*
 * FIXME: Types is of fixed size. Should be DTrace-defined.
 */
int
dthyve_probe_create(struct uuid *uuid, const char *mod,
    const char *func, const char *name, char types[10][128])
{
	struct dthyve_prov *pv, tmp;
	dtrace_virt_probedesc_t vpdesc;
	int error;

	tmp.uuid = uuid;

	pv = RB_FIND(dthyve_provtree, &dthyve_provider_tree, &tmp);

	if (pv == NULL)
		return (ESRCH);

	strlcpy(vpdesc.vpbd_mod, mod, DTRACE_MODNAMELEN);
	strlcpy(vpdesc.vpbd_func, func, DTRACE_FUNCNAMELEN);
	strlcpy(vpdesc.vpbd_name, name, DTRACE_NAMELEN);

	vpdesc.vpbd_uuid = malloc(sizeof(struct uuid));
	memcpy(vpdesc.vpbd_uuid, pv->host_uuid, sizeof(struct uuid));

	error = dt_ioctl(g_dtp, DTRACEIOC_PROBECREATE, &vpdesc);

	free(vpdesc.vpbd_uuid);

	return (error);
}

void
dthyve_cleanup(void)
{
	struct dthyve_prov *pv, *tmp;
	int error;

	RB_FOREACH_SAFE(pv, dthyve_provtree, &dthyve_provider_tree, tmp) {
		error = dthyve_priv_unregister(pv);
		assert(error == 0);
	}
}

static int
uuidcmp(const struct uuid *uuid1, const struct uuid *uuid2)
{

	return (memcmp(uuid1, uuid2, sizeof(struct uuid)));
}

static int
dthyve_prov_cmp(struct dthyve_prov *p1, struct dthyve_prov *p2)
{
	struct uuid *p1_uuid, *p2_uuid;

	p1_uuid = p1->uuid;
	p2_uuid = p2->uuid;

	return (uuidcmp(p1_uuid, p2_uuid));
}
#endif
