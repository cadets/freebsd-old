/*-
 * Copyright (c) 2017 Domagoj Stolfa
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/event.h>
#include <sys/uio.h>
#include <sys/uuid.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/dtrace_bsd.h>
#include <sys/vtdtr.h>

#include <machine/vmm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

#include <vmmapi.h>

#include "dthyve.h"
#include "bhyverun.h"
#include "pci_emul.h"
#include "virtio.h"

#define	VTDTR_RINGSZ 512
#define	VTDTR_MAXQ     2

/*
 * As already documented in virtio_dtrace.h, probe installation/uninstallation
 * events are only meant to be sent to the guest presently. They have no effect
 * on the host.
 *
 * Provider registration and de-registration, as well as probe
 * creation/destruction is presently on meant to be executed on the host in
 * order to advertise DTrace probes from the guest.
 *
 * READY and EOF are used for synchronization purposes, while CLEANUP is meant
 * to be sent to the guest in order to clean up the TX virtqueue.
 */
#define	VTDTR_DEVICE_READY           0x00
#define	VTDTR_DEVICE_REGISTER        0x01
#define	VTDTR_DEVICE_UNREGISTER      0x02
#define	VTDTR_DEVICE_DESTROY         0x03
#define	VTDTR_DEVICE_PROBE_CREATE    0x04
#define	VTDTR_DEVICE_PROBE_INSTALL   0x05
#define	VTDTR_DEVICE_PROBE_UNINSTALL 0x06
#define	VTDTR_DEVICE_EOF             0x07

static int pci_vtdtr_debug;
#define	DPRINTF(params) if (pci_vtdtr_debug) printf params
#define	WPRINTF(params) printf params

struct pci_vtdtr_probe_create_event {
	char        mod[DTRACE_MODNAMELEN];
	char        func[DTRACE_FUNCNAMELEN];
	char        name[DTRACE_NAMELEN];
	struct uuid uuid;
}__attribute__((packed));

struct pci_vtdtr_probe_toggle_event {
	char *dif; /* TODO */
}__attribute__((packed));

struct pci_vtdtr_ctrl_pbevent {
	uint32_t probe;

	union {
		struct pci_vtdtr_probe_create_event probe_evcreate;
		struct pci_vtdtr_probe_toggle_event probe_evtoggle;
	} upbev;
}__attribute__((packed));

struct pci_vtdtr_ctrl_provevent {
	char        name[DTRACE_PROVNAMELEN];
	struct uuid uuid;
}__attribute__((packed));

struct pci_vtdtr_control {
	uint32_t event;

	union {
		struct pci_vtdtr_ctrl_pbevent   probe_ev;
		struct pci_vtdtr_ctrl_provevent prov_ev;
	} uctrl;
}__attribute__((packed));

struct pci_vtdtr_ctrl_entry {
	struct pci_vtdtr_control           ctrl;
	STAILQ_ENTRY(pci_vtdtr_ctrl_entry) entries;
};

struct pci_vtdtr_ctrlq {
	STAILQ_HEAD(, pci_vtdtr_ctrl_entry) head;
	pthread_mutex_t                          mtx;
};

struct pci_vtdtr_softc {
	struct virtio_softc     vsd_vs;
	struct vqueue_info      vsd_queues[VTDTR_MAXQ];
	struct vmctx           *vsd_vmctx;
	struct pci_vtdtr_ctrlq *vsd_ctrlq;
	pthread_mutex_t         vsd_condmtx;
	pthread_cond_t          vsd_cond;
	pthread_mutex_t         vsd_mtx;
	uint64_t                vsd_cfg;
	int                     vsd_guest_ready;
	int                     vsd_ready;
};

static void pci_vtdtr_reset(void *);
static void pci_vtdtr_control_tx(struct pci_vtdtr_softc *,
    struct iovec *, int);
static int pci_vtdtr_control_rx(struct pci_vtdtr_softc *,
    struct iovec *, int);
static void pci_vtdtr_process_prov_evt(struct pci_vtdtr_softc *,
    struct pci_vtdtr_control *);
static void pci_vtdtr_process_probe_evt(struct pci_vtdtr_softc *,
    struct pci_vtdtr_control *);
static void pci_vtdtr_notify_tx(void *, struct vqueue_info *);
static void pci_vtdtr_notify_rx(void *, struct vqueue_info *);
static void pci_vtdtr_cq_enqueue(struct pci_vtdtr_ctrlq *,
    struct pci_vtdtr_ctrl_entry *);
static void pci_vtdtr_cq_enqueue_front(struct pci_vtdtr_ctrlq *,
    struct pci_vtdtr_ctrl_entry *);
static int pci_vtdtr_cq_empty(struct pci_vtdtr_ctrlq *);
static struct pci_vtdtr_ctrl_entry *pci_vtdtr_cq_dequeue(
    struct pci_vtdtr_ctrlq *);
static void pci_vtdtr_fill_desc(struct vqueue_info *,
    struct pci_vtdtr_control *);
static void pci_vtdtr_poll(struct vqueue_info *, int);
static void pci_vtdtr_notify_ready(struct pci_vtdtr_softc *);
static void pci_vtdtr_fill_eof_desc(struct vqueue_info *);
static void * pci_vtdtr_run(void *);
#if 0
static void pci_vtdtr_handle_mev(int, enum ev_type, int, void *);
#endif
static void pci_vtdtr_reset_queue(struct pci_vtdtr_softc *);
static int pci_vtdtr_init(struct vmctx *, struct pci_devinst *, char *);

static struct virtio_consts vtdtr_vi_consts = {
	"vtdtr",			/* name */
	VTDTR_MAXQ,			/* maximum virtqueues */
	0,				/* config reg size */
	pci_vtdtr_reset,		/* reset */
	NULL,				/* device-wide qnotify */
	NULL,				/* read virtio config */
	NULL,				/* write virtio config */
	NULL,				/* apply negotiated features */
	0,				/* capabilities */
};

static void
pci_vtdtr_reset(void *xsc)
{
	struct pci_vtdtr_softc *sc;

	sc = xsc;

	pthread_mutex_lock(&sc->vsd_mtx);
	DPRINTF(("vtdtr: device reset requested!\n"));
	pci_vtdtr_reset_queue(sc);
	vi_reset_dev(&sc->vsd_vs);
	pthread_mutex_unlock(&sc->vsd_mtx);
}

static void
pci_vtdtr_control_tx(struct pci_vtdtr_softc *sc, struct iovec *iov, int niov)
{
	/*
	 * TODO
	 */
}

/*
 * In this function we process each of the events, for probe and provider
 * related events, we delegate the processing to a function specialized for that
 * type of event.
 */
static int
pci_vtdtr_control_rx(struct pci_vtdtr_softc *sc, struct iovec *iov, int niov)
{
	struct pci_vtdtr_control *ctrl;
	//struct pci_vtdtr_ctrl_provevent *pv_ev;
	//struct pci_vtdtr_ctrl_pbevent *pb_ev;
	int retval;// error;

	assert(niov == 1);
	retval = 0;

	ctrl = (struct pci_vtdtr_control *)iov->iov_base;
	switch (ctrl->event) {
	case VTDTR_DEVICE_READY:
		pthread_mutex_lock(&sc->vsd_mtx);
		sc->vsd_guest_ready = 1;
		pthread_mutex_unlock(&sc->vsd_mtx);
		break;
#if 0
	case VTDTR_DEVICE_REGISTER:
		sc->vsd_ready = 0;
		pv_ev = &ctrl->uctrl.prov_ev;
		error = dthyve_register_provider(&pv_ev->uuid,
		    vm_get_name(sc->vsd_vmctx), pv_ev->name);
		if (error)
			WPRINTF(("%s: error %d during registration",
			    __func__, errno));
		break;
	case VTDTR_DEVICE_UNREGISTER:
		sc->vsd_ready = 0;
		pv_ev = &ctrl->uctrl.prov_ev;
		error = dthyve_unregister_provider(&pv_ev->uuid);
		if (error)
			WPRINTF(("%s: error %d during unregistration",
			    __func__, error));
		break;
	case VTDTR_DEVICE_DESTROY:
		break;
	case VTDTR_DEVICE_PROBE_CREATE: {
		char *mod;
		char *func;
		char *name;
		struct uuid *uuid;
		/*
		 * FIXME: All of this is fixed. Should be DTrace-defined.
		 */
		sc->vsd_ready = 0;
		pb_ev = &ctrl->uctrl.probe_ev;

		mod = pb_ev->upbev.probe_evcreate.mod;
		func = pb_ev->upbev.probe_evcreate.func;
		name = pb_ev->upbev.probe_evcreate.name;
		uuid = &pb_ev->upbev.probe_evcreate.uuid;

		error = dthyve_probe_create(uuid, mod, func, name,
		    pb_ev->upbev.probe_evcreate.types);
		if (error)
			WPRINTF(("%s: error %d during probe creation",
			    __func__, errno));
		break;
	}
	case VTDTR_DEVICE_PROBE_INSTALL:
	case VTDTR_DEVICE_PROBE_UNINSTALL:
		break;
#endif
	case VTDTR_DEVICE_EOF:
		retval = 1;
		break;
	default:
		WPRINTF(("Warning: Unknown event: %u\n", ctrl->event));
		break;
	}

	return (retval);
}

static void
pci_vtdtr_process_prov_evt(struct pci_vtdtr_softc *sc,
    struct pci_vtdtr_control *ctrl)
{
	/*
	 * XXX: The processing functions... are the actually
	 * necessary, or do we want a layer that DTrace talks
	 * to and simply delegates it towards the virtio driver?
	 */
}

static void
pci_vtdtr_process_probe_evt(struct pci_vtdtr_softc *sc,
    struct pci_vtdtr_control *ctrl)
{

}

static void
pci_vtdtr_notify_tx(void *xsc, struct vqueue_info *vq)
{
}

/*
 * The RX queue interrupt. This function gets all the descriptors until we hit
 * EOF or run out of descriptors and processes each event in a lockless manner.
 */
static void
pci_vtdtr_notify_rx(void *xsc, struct vqueue_info *vq)
{
	struct pci_vtdtr_softc *sc;
	struct iovec iov[1];
	uint16_t idx;
	uint16_t flags[8];
	int n;
	int retval;

	sc = xsc;

	while (vq_has_descs(vq)) {
		n = vq_getchain(vq, &idx, iov, 1, flags);
		retval = pci_vtdtr_control_rx(sc, iov, 1);
		vq_relchain(vq, idx, sizeof(struct pci_vtdtr_control));
		if (retval == 1)
			break;
	}

	pthread_mutex_lock(&sc->vsd_mtx);
	if (sc->vsd_ready == 0)
		pci_vtdtr_notify_ready(sc);
	pthread_mutex_unlock(&sc->vsd_mtx);

	pci_vtdtr_poll(vq, 1);

	pthread_mutex_lock(&sc->vsd_condmtx);
	pthread_cond_signal(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_condmtx);

}

#if 0
/*
 * Here we handle the kernel event that we get from kqueue and identify various
 * control messages that we need to send
 */
static void
pci_vtdtr_handle_mev(int fd __unused, enum ev_type et __unused, int ne,
    void *xsc)
{
	struct pci_vtdtr_softc *sc;
	struct pci_vtdtr_control *ctrl;
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	char *name;

	sc = xsc;
	name = vm_get_name(sc->vsd_vmctx);

	/*
	 * FIXME: The DTrace error probe for each VM instance gets enabled
	 * regardless of what we're tracing. This maybe shouldn't happen?
	 */
	if (strcmp(name, sc->vsd_pbi.instance) != 0)
		return;

	ctrl_entry = malloc(sizeof(struct pci_vtdtr_ctrl_entry));
	assert(ctrl_entry != NULL);
	ctrl = &ctrl_entry->ctrl;

	assert((ne & (NOTE_PROBE_INSTALL | NOTE_PROBE_UNINSTALL)) != 0);
	if (ne & NOTE_PROBE_INSTALL)
		ctrl->event = VTDTR_DEVICE_PROBE_INSTALL;
	else
		ctrl->event = VTDTR_DEVICE_PROBE_UNINSTALL;

	ctrl->uctrl.probe_ev.probe = sc->vsd_pbi.id;

	pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
	pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
	pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

	pthread_mutex_lock(&sc->vsd_condmtx);
	pthread_cond_signal(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_condmtx);
}
#endif

static __inline void
pci_vtdtr_cq_enqueue(struct pci_vtdtr_ctrlq *cq,
    struct pci_vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_TAIL(&cq->head, ctrl_entry, entries);
}

static __inline void
pci_vtdtr_cq_enqueue_front(struct pci_vtdtr_ctrlq *cq,
    struct pci_vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_HEAD(&cq->head, ctrl_entry, entries);
}

static __inline int
pci_vtdtr_cq_empty(struct pci_vtdtr_ctrlq *cq)
{

	return (STAILQ_EMPTY(&cq->head));
}

static struct pci_vtdtr_ctrl_entry *
pci_vtdtr_cq_dequeue(struct pci_vtdtr_ctrlq *cq)
{
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	ctrl_entry = STAILQ_FIRST(&cq->head);
	if (ctrl_entry != NULL) {
		STAILQ_REMOVE_HEAD(&cq->head, entries);
	}

	return (ctrl_entry);
}

/*
 * In this function we fill the descriptor that was provided to us by the guest.
 * No allocation is needed, since we memcpy everything.
 */
static void
pci_vtdtr_fill_desc(struct vqueue_info *vq, struct pci_vtdtr_control *ctrl)
{
	struct iovec iov;
	size_t len;
	int n;
	uint16_t idx;

	n = vq_getchain(vq, &idx, &iov, 1, NULL);
	assert(n == 1);

	len = sizeof(struct pci_vtdtr_control);
	memcpy(iov.iov_base, ctrl, len);

	vq_relchain(vq, idx, len);
}

static void
pci_vtdtr_poll(struct vqueue_info *vq, int all_used)
{

	vq_endchains(vq, all_used);
}

/*
 * In this function we enqueue the READY control message in front of the queue,
 * so that when the guest receives the messages, READY is the first one in the
 * queue. If we already are ready, we simply signal the communicator thread that
 * it is safe to run.
 */
static void
pci_vtdtr_notify_ready(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	struct pci_vtdtr_control *ctrl;

	sc->vsd_ready = 1;

	ctrl_entry = malloc(sizeof(struct pci_vtdtr_ctrl_entry));
	assert(ctrl_entry != NULL);

	ctrl = &ctrl_entry->ctrl;

	ctrl->event = VTDTR_DEVICE_READY;


	pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
	pci_vtdtr_cq_enqueue_front(sc->vsd_ctrlq, ctrl_entry);
	pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);
}

static void
pci_vtdtr_fill_eof_desc(struct vqueue_info *vq)
{
	struct pci_vtdtr_control ctrl;
	ctrl.event = VTDTR_DEVICE_EOF;
	pci_vtdtr_fill_desc(vq, &ctrl);
}

/*
 * The communicator thread that is created when we attach the PCI device. It
 * serves the purpose of draining the control queue of messages and filling the
 * guest memory with the descriptors.
 */
static void *
pci_vtdtr_run(void *xsc)
{
	struct pci_vtdtr_softc *sc;
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	struct vqueue_info *vq;
	uint32_t nent;
	int error;
	int ready_flag;

	sc = xsc;
	vq = &sc->vsd_queues[0];

	for (;;) {
		nent = 0;
		error = 0;
		ready_flag = 1;

		error = pthread_mutex_lock(&sc->vsd_condmtx);
		assert(error == 0);
		/*
		 * We are safe to proceed if the following conditions are
		 * satisfied:
		 * (1) We have messages in the control queue
		 * (2) The guest is ready
		 */
		while (!sc->vsd_guest_ready ||
		    pci_vtdtr_cq_empty(sc->vsd_ctrlq)) {
			error = pthread_cond_wait(&sc->vsd_cond, &sc->vsd_condmtx);
			assert(error == 0);
		}
		error = pthread_mutex_unlock(&sc->vsd_condmtx);
		assert(error == 0);

		assert(vq_has_descs(vq) != 0);
		error = pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
		assert(error == 0);
		assert(!pci_vtdtr_cq_empty(sc->vsd_ctrlq));

		/*
		 * While dealing with the entires, we will fill every single
		 * entry as long as we have space or entries in the queue.
		 */
		while (vq_has_descs(vq) && !pci_vtdtr_cq_empty(sc->vsd_ctrlq)) {
			ctrl_entry = pci_vtdtr_cq_dequeue(sc->vsd_ctrlq);
			error = pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);
			assert(error == 0);

			if (ready_flag &&
			    ctrl_entry->ctrl.event != VTDTR_DEVICE_READY)
				ready_flag = 0;

			pci_vtdtr_fill_desc(vq, &ctrl_entry->ctrl);
			free(ctrl_entry);
			nent++;
			error = pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
			assert(error == 0);
		}

		/*
		 * If we've filled >= 1 entry in the descriptor queue, we first
		 * check if the queue is empty, and if so, we append a special
		 * EOF descriptor to send to the guest. Following that, we end
		 * the chains and force an interrupt in the guest
		 */
		if (nent) {
			if (pci_vtdtr_cq_empty(sc->vsd_ctrlq) &&
			    vq_has_descs(vq)) {
				pci_vtdtr_fill_eof_desc(vq);
			}
			pthread_mutex_lock(&sc->vsd_mtx);
			sc->vsd_guest_ready = ready_flag;
			pthread_mutex_unlock(&sc->vsd_mtx);
			pci_vtdtr_poll(vq, 1);
		}

		error = pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

	}

	pthread_exit(NULL);
}

/*
 * A simple wrapper function used to reset the control queue
 */
static void
pci_vtdtr_reset_queue(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *n1, *n2;
	struct pci_vtdtr_ctrlq *q;

	q = sc->vsd_ctrlq;

	pthread_mutex_lock(&q->mtx);
	n1 = STAILQ_FIRST(&q->head);
	while (n1 != NULL) {
		n2 = STAILQ_NEXT(n1, entries);
		free(n1);
		n1 = n2;
	}

	STAILQ_INIT(&q->head);
	pthread_mutex_unlock(&q->mtx);
}

static void *
pci_vtdtr_events(void *xsc)
{
	struct pci_vtdtr_softc *sc;
	int error;

	sc = xsc;

	/*
	 * We listen for events indefinitely.
	 */
	for (;;) {
		struct vtdtr_event ev;
		struct pci_vtdtr_ctrl_entry *ctrl_entry;
		struct pci_vtdtr_control *ctrl;

		error = dthyve_read(&ev, 1);
		if (error) {
			fprintf(stderr, "Error: '%s' reading.\n",
			    strerror(error));
			continue;
		}

		ctrl_entry = malloc(sizeof(struct pci_vtdtr_ctrl_entry));
		assert(ctrl_entry != NULL);
		ctrl = &ctrl_entry->ctrl;

		assert((ev.type & (VTDTR_EV_INSTALL | VTDTR_EV_UNINSTALL)) != 0);
		if (ev.type == VTDTR_EV_INSTALL)
			ctrl->event = VTDTR_DEVICE_PROBE_INSTALL;
		else
			ctrl->event = VTDTR_DEVICE_PROBE_UNINSTALL;

		ctrl->uctrl.probe_ev.probe = ev.args.p_toggle.probeid;

		pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
		pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
		pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

		pthread_mutex_lock(&sc->vsd_condmtx);
		pthread_cond_signal(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_condmtx);
	}
}

/*
 * Mostly boilerplate, we initialize everything required for the correct
 * operation of the emulated PCI device, do error checking and finally dispatch
 * the communicator thread and add an event handler for kqueue.
 */
static int
pci_vtdtr_init(struct vmctx *ctx, struct pci_devinst *pci_inst, char *opts)
{
	struct pci_vtdtr_softc *sc;
	pthread_t communicator, reader;
	int error;

	error = 0;
	sc = calloc(1, sizeof(struct pci_vtdtr_softc));
	assert(sc != NULL);
	sc->vsd_ctrlq = calloc(1, sizeof(struct pci_vtdtr_ctrlq));
	assert(sc->vsd_ctrlq != NULL);
	STAILQ_INIT(&sc->vsd_ctrlq->head);

	vi_softc_linkup(&sc->vsd_vs, &vtdtr_vi_consts,
	    sc, pci_inst, sc->vsd_queues);
	sc->vsd_vs.vs_mtx = &sc->vsd_mtx;
	sc->vsd_vmctx = ctx;
	sc->vsd_ready = 0;

	sc->vsd_queues[0].vq_qsize = VTDTR_RINGSZ;
	sc->vsd_queues[0].vq_notify = pci_vtdtr_notify_tx;
	sc->vsd_queues[1].vq_qsize = VTDTR_RINGSZ;
	sc->vsd_queues[1].vq_notify = pci_vtdtr_notify_rx;

	pci_set_cfgdata16(pci_inst, PCIR_DEVICE, VIRTIO_DEV_DTRACE);
	pci_set_cfgdata16(pci_inst, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pci_inst, PCIR_CLASS, PCIC_OTHER);
	pci_set_cfgdata16(pci_inst, PCIR_SUBDEV_0, VIRTIO_TYPE_DTRACE);
	pci_set_cfgdata16(pci_inst, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	error = pthread_mutex_init(&sc->vsd_ctrlq->mtx, NULL);
	assert(error == 0);
	error = pthread_cond_init(&sc->vsd_cond, NULL);
	assert(error == 0);
	error = pthread_create(&communicator, NULL, pci_vtdtr_run, sc);
	assert(error == 0);
	if (dthyve_configured()) {
		error = pthread_create(&reader, NULL, pci_vtdtr_events, sc);
		assert(error == 0);
	}

	if (vi_intr_init(&sc->vsd_vs, 1, fbsdrun_virtio_msix()))
		return (1);

	vi_set_io_bar(&sc->vsd_vs, 0);
	return (0);
}

struct pci_devemu pci_de_vdtr = {
	.pe_emu      = "virtio-dtrace",
	.pe_init     = pci_vtdtr_init,
	.pe_barwrite = vi_pci_write,
	.pe_barread  = vi_pci_read
};
PCI_EMUL_SET(pci_de_vdtr);
