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
#include <sys/stat.h>

#include <machine/vmm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <dtdaemon.h>

#include <syslog.h>
#include <stdarg.h>

#include <vmmapi.h>

#include "dthyve.h"
#include "bhyverun.h"
#include "pci_emul.h"
#include "virtio.h"

#define	VTDTR_RINGSZ	4096
#define	VTDTR_MAXQ	2

#define	VTDTR_DEVICE_READY		0x00 /* Device is ready */
#define	VTDTR_DEVICE_REGISTER		0x01 /* UNUSED */
#define	VTDTR_DEVICE_UNREGISTER		0x02 /* UNUSED */
#define	VTDTR_DEVICE_DESTROY		0x03 /* UNUSED */
#define	VTDTR_DEVICE_PROBE_CREATE	0x04 /* UNUSED */
#define	VTDTR_DEVICE_PROBE_INSTALL	0x05 /* Install a given probe */
#define	VTDTR_DEVICE_PROBE_UNINSTALL	0x06 /* Uninstall a given probe */
#define	VTDTR_DEVICE_EOF		0x07 /* End of file */
#define	VTDTR_DEVICE_GO			0x08 /* Start the tracing */
#define	VTDTR_DEVICE_ELF		0x09 /* Send an ELF file */
#define	VTDTR_DEVICE_STOP		0x0A /* Stop tracing */
#define	VTDTR_DEVICE_KILL		0x0B /* Kill a DTrace process */

#define PCI_VTDTR_MAXELFLEN		2048ul

#define PCI_VTDTR_EVENTSLEEPTIME	5

static int pci_vtdtr_debug;
#define	DPRINTF(params) if (pci_vtdtr_debug) printf params
#define	WPRINTF(params) printf params

struct pci_vtdtr_control {
	uint32_t 		pvc_event;
	union {
		uint32_t	pvc_probeid;	/* install/uninstall event */

		struct {	/*  elf event */
			size_t		pvc_elflen;
			size_t		pvc_totalelflen;
			uint32_t	pvc_identifier;
			int		pvc_elfhasmore;
			char		pvc_elf[PCI_VTDTR_MAXELFLEN];
		} elf;

		struct {
			pid_t pvc_pid; /* kill a dtrace process */
		} kill;

		/*
		 * Defines for easy access into the union and underlying structs
		 */
#define	pvc_probeid	uctrl.pvc_probeid

#define	pvc_identifier	uctrl.elf.pvc_identifier
#define	pvc_elflen	uctrl.elf.pvc_elflen
#define	pvc_elfhasmore	uctrl.elf.pvc_elfhasmore
#define	pvc_totalelflen	uctrl.elf.pvc_totalelflen
#define	pvc_elf		uctrl.elf.pvc_elf
#define	pvc_pid		uctrl.kill.pvc_pid
	} uctrl;
};

_Static_assert(sizeof(struct pci_vtdtr_control) <= 4096,
    "pci_vtdtr_control must fit in one page");

struct pci_vtdtr_ctrl_entry {
	STAILQ_ENTRY(pci_vtdtr_ctrl_entry)	entries;
	struct pci_vtdtr_control		*ctrl;
};

struct pci_vtdtr_ctrlq {
	STAILQ_HEAD(, pci_vtdtr_ctrl_entry)	head;
	pthread_mutex_t				mtx;
};

struct pci_vtdtr_softc {
	struct virtio_softc	vsd_vs;
	struct vqueue_info	vsd_queues[VTDTR_MAXQ];
	struct vmctx		*vsd_vmctx;
	struct pci_vtdtr_ctrlq	*vsd_ctrlq;
	pthread_mutex_t		vsd_condmtx;
	pthread_cond_t		vsd_cond;
	pthread_mutex_t		vsd_mtx;
	uint64_t		vsd_cfg;
	int			vsd_guest_ready;
	int			vsd_ready;
};

/*
 * By defn, a flexibly array member is not included in the sizeof(), so we can
 * simply compute the maximum amount of bytes we can fit in each event to not
 * overwrite the ringbuffer using it.
 */

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

static void
get_randname(char *b, size_t len)
{
	size_t i;

	/*
	 * Generate lower-case random characters.
	 */
	for (i = 0; i < len; i++)
		b[i] = arc4random_uniform(25) + 97;
}

static char *
gen_filename(void)
{
	char *filename;
	size_t len;

	len = MAXPATHLEN / 64;
	assert(len > 10);

	filename = malloc(len);
	filename[0] = '.';
	get_randname(filename + 1, len - 2);
	filename[len - 1] = '\0';

	while (dthyve_access(filename) != -1) {
		filename[0] = '.';
		get_randname(filename + 1, len - 2);
		filename[len - 1] = '\0';
	}

	return (filename);
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
	int retval;
	static int inprogress = 0;
	static size_t len = 0;
	static size_t offs = 0;
	static char *elf;
	uint64_t size;
	char *name;
	uint16_t vmid;
	static char padding[6] = {0,0,0,0,0,0};
	static char inbound[DTDAEMON_LOCSIZE] = "inbound";
	size_t buflen;
	unsigned char *buf, *_buf;
	dtdaemon_hdr_t header;

	memset(&header, 0, sizeof(header));
	assert(niov == 1);
	retval = 0;
	vmid = 0;
	buflen = 0;
	buf = _buf = NULL;

	ctrl = (struct pci_vtdtr_control *)iov->iov_base;
	switch (ctrl->pvc_event) {
	case VTDTR_DEVICE_READY:
		pthread_mutex_lock(&sc->vsd_mtx);
		sc->vsd_guest_ready = 1;
		pthread_mutex_unlock(&sc->vsd_mtx);
		break;
		
	case VTDTR_DEVICE_ELF:
		sc->vsd_ready = 0;
		if (inprogress == 0) {
			len = ctrl->pvc_totalelflen;
			elf = malloc(ctrl->pvc_totalelflen);
			memset(elf, 0, ctrl->pvc_totalelflen);
			inprogress = 1;
		}

		assert(offs < len);
		assert(ctrl->pvc_elflen <= len);

		if (elf == NULL)
			return (retval);

		assert((elf + offs) <= (elf + len));
		memcpy((void *)(elf + offs), ctrl->pvc_elf, ctrl->pvc_elflen);
		offs += ctrl->pvc_elflen;

		if (ctrl->pvc_elfhasmore == 0) {
			assert(elf + offs == elf + len);
			vmid = vm_get_vmid(sc->vsd_vmctx);
			name = vm_get_name(sc->vsd_vmctx);
			size = strlen(name);

			DTDAEMON_MSG_TYPE(header) = DTDAEMON_MSG_ELF;
			memcpy(DTDAEMON_MSG_LOC(header), inbound,
			    DTDAEMON_LOCSIZE);

			buflen = DTDAEMON_MSGHDRSIZE + sizeof(vmid) +
			    sizeof(padding) + sizeof(size) + size + len;

			assert(buflen > len);

			buf = malloc(buflen);
			if (buf == NULL) {
				fprintf(stderr, "malloc() failed with: %s\n",
				    strerror(errno));
				return (retval);
			}

			_buf = buf;

			assert((_buf + DTDAEMON_MSGHDRSIZE) < (buf + buflen));

			memcpy(_buf, &header, DTDAEMON_MSGHDRSIZE);
			_buf += DTDAEMON_MSGHDRSIZE;

			assert(_buf > buf);
			assert((_buf + sizeof(vmid)) < (buf + buflen));

			memcpy(_buf, &vmid, sizeof(vmid));
			_buf += sizeof(vmid);

			assert(_buf > buf);
			assert((_buf + sizeof(padding)) < (buf + buflen));

			memcpy(_buf, padding, sizeof(padding));
			_buf += sizeof(padding);

			assert(_buf > buf);
			assert((_buf + sizeof(size)) < (buf + buflen));

			memcpy(_buf, &size, sizeof(size));
			_buf += sizeof(size);

			assert(_buf > buf);
			assert((_buf + size) < (buf + buflen));

			memcpy(_buf, name, size);
			_buf += size;

			assert(_buf > buf);
			assert((_buf + len) == (buf + buflen));

			memcpy(_buf, elf, len);

			if (dthyve_write(buf, buflen) == -1) {
				fprintf(stderr, "dthyve_write() failed\n");
				return (retval);
			}

			free(buf);
			free(elf);
			len = 0;
			inprogress = 0;
			offs = 0;
		}
		break;

	case VTDTR_DEVICE_EOF:
		retval = 1;
		break;

	case VTDTR_DEVICE_KILL:
		WPRINTF(("Warning: VTDTR_DEVICE_KILL received on the host "
			 "for pid %d\n",
		    ctrl->pvc_pid));
		break;

	default:
		WPRINTF(("Warning: Unknown event: %u\n", ctrl->pvc_event));
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
	memset(ctrl_entry, 0, sizeof(struct pci_vtdtr_ctrl_entry));

	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	assert(ctrl != NULL);
	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));

	ctrl->pvc_event = VTDTR_DEVICE_READY;
	ctrl_entry->ctrl = ctrl;

	pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
	pci_vtdtr_cq_enqueue_front(sc->vsd_ctrlq, ctrl_entry);
	pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);
}

static void
pci_vtdtr_fill_eof_desc(struct vqueue_info *vq)
{
	/*
	 * Do a malloc to ensure that we don't break the stack
	 */
	struct pci_vtdtr_control *ctrl;
	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	ctrl->pvc_event = VTDTR_DEVICE_EOF;
	pci_vtdtr_fill_desc(vq, ctrl);
	free(ctrl);
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
			error =
			    pthread_cond_wait(&sc->vsd_cond, &sc->vsd_condmtx);
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
			    ctrl_entry->ctrl->pvc_event != VTDTR_DEVICE_READY)
				ready_flag = 0;

			pci_vtdtr_fill_desc(vq, ctrl_entry->ctrl);
			free(ctrl_entry->ctrl);
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

static struct pci_vtdtr_control *
vtdtr_elf_event(void *buf, size_t size, size_t offs)
{
	struct pci_vtdtr_control *ctrl;
	ssize_t rval;
	size_t maxlen;
	size_t len_to_read;
	int hasmore;

	rval = 0;
	ctrl = NULL;
	maxlen = 0;
	len_to_read = 0;
	hasmore = 0;

	/*
	 * Compute how much we'll actually be reading.
	 */
	maxlen = size - offs;
	len_to_read = maxlen > PCI_VTDTR_MAXELFLEN ?
	    PCI_VTDTR_MAXELFLEN : maxlen;
	hasmore = maxlen > PCI_VTDTR_MAXELFLEN ? 1 : 0;

	/*
	 * Allocate the control message with the appropriate size to fit
	 * all of the data that we'll be reading in.
	 */
	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc a new control event\n");
		return (NULL);
	}

	/*
	 * Zero the control event.
	 */
	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));
	memcpy(ctrl->pvc_elf, buf + offs, len_to_read);

	/*
	 * At this point, we will have returned NULL in any case of failure,
	 * so we don't need to check anything further and can fill in the full
	 * control message and return it.
	 */
	ctrl->pvc_event = VTDTR_DEVICE_ELF;
	ctrl->pvc_elflen = len_to_read;
	ctrl->pvc_totalelflen = size;
	ctrl->pvc_elfhasmore = hasmore;
	return (ctrl);
}

static struct pci_vtdtr_control *
vtdtr_kill_event(pid_t pid)
{
	struct pci_vtdtr_control *ctrl;

	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc new control event\n");
		return (NULL);
	}

	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));

	ctrl->pvc_event = VTDTR_DEVICE_KILL;
	ctrl->pvc_pid = pid;
	printf("constructed VTDTR_DEVICE_KILL with pid = %d\n", pid);

	return (ctrl);
}

static struct stat *
vtdtr_get_filestat(int fd)
{
	struct stat *st;
	int rval;

	st = NULL;
	rval = 0;

	st = malloc(sizeof(struct stat));
	assert(st != NULL);
	memset(st, 0, sizeof(struct stat));

	rval = fstat(fd, st);
	if (rval != 0) {
		fprintf(stderr, "failed to fstat: %s\n", strerror(errno));
		free(st);
		return (NULL);
	}

	return (st);
}

static void *
pci_vtdtr_events(void *xsc)
{
	struct pci_vtdtr_softc *sc;
	int error;
	int fd;
	struct stat *st;
	size_t offs;
	char *buf = NULL, *_buf = NULL;
	struct pci_vtdtr_control *ctrl;
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	size_t len;
	dtdaemon_hdr_t header;

	buf = NULL;
	sc = xsc;
	fd = 0;
	st = NULL;
	offs = 0;
	len = 0;
	memset(&header, 0, sizeof(header));

	for (;;) {
		error = dthyve_read((void **)&buf, &len);
		if (error) {
			fprintf(stderr, "Error in dthyve_read(): %s\n",
			    strerror(errno));
			if (errno == EINTR)
				exit(1);

			if (errno == EAGAIN)
				sleep(PCI_VTDTR_EVENTSLEEPTIME);

			continue;
		}

		memcpy(&header, buf, DTDAEMON_MSGHDRSIZE);
		/*
		 * We don't need the header anymore...
		 */
		_buf = buf + DTDAEMON_MSGHDRSIZE;
		len -= DTDAEMON_MSGHDRSIZE;

		ctrl_entry = malloc(sizeof(struct pci_vtdtr_ctrl_entry));
		assert(ctrl_entry != NULL);
		memset(ctrl_entry, 0, sizeof(struct pci_vtdtr_ctrl_entry));

		switch (DTDAEMON_MSG_TYPE(header)) {
		case DTDAEMON_MSG_KILL:
			ctrl = vtdtr_kill_event(DTDAEMON_MSG_KILLPID(header));
			ctrl_entry->ctrl = ctrl;

			pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
			pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

			pthread_mutex_lock(&sc->vsd_condmtx);
			pthread_cond_signal(&sc->vsd_cond);
			pthread_mutex_unlock(&sc->vsd_condmtx);

			break;

		case DTDAEMON_MSG_ELF:
			/*
			 * We can't do anything meaningful if this malloc fails,
			 * so we simply assume it will succeed every time and
			 * assert it.
			 */

			ctrl = vtdtr_elf_event(_buf, len, offs);
			assert(ctrl != NULL);
			offs += ctrl->pvc_elflen;

			while (ctrl->pvc_elfhasmore == 1) {
				ctrl_entry->ctrl = ctrl;

				pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
				pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
				pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

				/*
				 * Get the new control element
				 */
				ctrl = vtdtr_elf_event(_buf, len, offs);
				assert(ctrl != NULL);
				offs += ctrl->pvc_elflen;

				ctrl_entry =
				    malloc(sizeof(struct pci_vtdtr_ctrl_entry));
				assert(ctrl_entry != NULL);
				memset(ctrl_entry, 0,
				    sizeof(struct pci_vtdtr_ctrl_entry));
			}

			ctrl_entry->ctrl = ctrl;

			pthread_mutex_lock(&sc->vsd_ctrlq->mtx);
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
			pthread_mutex_unlock(&sc->vsd_ctrlq->mtx);

			pthread_mutex_lock(&sc->vsd_condmtx);
			pthread_cond_signal(&sc->vsd_cond);
			pthread_mutex_unlock(&sc->vsd_condmtx);

			offs = 0;
			len = 0;
			break;
		}

		free(buf);
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
	.pe_emu		= "virtio-dtrace",
	.pe_init	= pci_vtdtr_init,
	.pe_barwrite	= vi_pci_write,
	.pe_barread	= vi_pci_read
};
PCI_EMUL_SET(pci_de_vdtr);
