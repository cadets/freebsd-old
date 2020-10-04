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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/condvar.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/taskqueue.h>
#include <sys/queue.h>
#include <sys/uuid.h>
#include <sys/vtdtr.h>
#include <sys/dtrace.h>
#include <sys/sema.h>
#include <sys/conf.h>
#include <sys/time.h>

#include <cddl/dev/vtdtr/vtdtr.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

#include "virtio_dtrace.h"
#include "virtio_if.h"

struct vtdtr_probe
{
	uint32_t vtdprobe_id;
	LIST_ENTRY(vtdtr_probe)
	vtdprobe_next;
};

struct vtdtr_probelist
{
	LIST_HEAD(, vtdtr_probe)
	head;
	struct mtx mtx;
};

struct vtdtr_softc
{
	device_t vtdtr_dev;
	struct mtx vtdtr_mtx;
	uint64_t vtdtr_features;

	struct virtio_dtrace_queue vtdtr_txq;
	struct virtio_dtrace_queue vtdtr_rxq;
	int vtdtr_tx_nseg;
	int vtdtr_rx_nseg;

	struct cv vtdtr_condvar;
	struct mtx vtdtr_condmtx;

	struct vtdtr_ctrlq *vtdtr_ctrlq;

	struct thread *vtdtr_commtd;
	struct thread *vtdtr_listd;

	struct sema vtdtr_exit;

	/*
	 * We need to keep track of all the enabsled probes in the
	 * driver in order to act as a bridge between the guest DTrace
	 * and host DTrace. The driver is the one asking to install
	 * or uninstall the probes on the guest, as instructed by host.
	 */
	struct vtdtr_probelist *vtdtr_probelist;

	int vtdtr_shutdown;
	int vtdtr_ready;
	int vtdtr_host_ready;
};

static MALLOC_DEFINE(M_VTDTR, "vtdtr", "VirtIO DTrace memory");

SYSCTL_NODE(_dev, OID_AUTO, vtdtr, CTLFLAG_RD, NULL, NULL);

/*
 * This is protected by the vtdtr_probelist mutex.
 */
static uint32_t num_dtprobes;
SYSCTL_U32(_dev_vtdtr, OID_AUTO, nprobes, CTLFLAG_RD, &num_dtprobes, 0,
		   "Number of installed probes through virtio-dtrace");

static uint32_t debug = 1;
SYSCTL_U32(_dev_vtdtr, OID_AUTO, debug, CTLFLAG_RWTUN, &debug, 0,
		   "Enable debugging of virtio-dtrace");

static int vstate = 0;

static struct vtdtr_traceq *tq;
struct timespec tv1;

static int vtdtr_modevent(module_t, int, void *);
static void vtdtr_cleanup(void);

static int vtdtr_probe(device_t);
static int vtdtr_attach(device_t);
static int vtdtr_detach(device_t);
static int vtdtr_config_change(device_t);
static void vtdtr_negotiate_features(struct vtdtr_softc *);
static void vtdtr_setup_features(struct vtdtr_softc *);
static void vtdtr_alloc_probelist(struct vtdtr_softc *);
static int vtdtr_alloc_virtqueues(struct vtdtr_softc *);
static void vtdtr_stop(struct vtdtr_softc *);
static void vtdtr_drain_virtqueues(struct vtdtr_softc *);
static int vtdtr_queue_populate(struct virtio_dtrace_queue *);
static void vtdtr_queue_requeue_ctrl(struct virtio_dtrace_queue *,
									 struct virtio_dtrace_control *, int, int);
static int vtdtr_queue_new_ctrl(struct virtio_dtrace_queue *);
static int vtdtr_queue_enqueue_ctrl(struct virtio_dtrace_queue *,
									struct virtio_dtrace_control *, int, int);
static int vtdtr_enable_interrupts(struct vtdtr_softc *);
static void vtdtr_disable_interrupts(struct vtdtr_softc *);
static int vtdtr_ctrl_process_event(struct vtdtr_softc *,
									struct virtio_dtrace_control *);
static void vtdtr_destroy_probelist(struct vtdtr_softc *);
static void vtdtr_start_taskqueues(struct vtdtr_softc *);
static void vtdtr_drain_taskqueues(struct vtdtr_softc *);
static int vtdtr_vq_enable_intr(struct virtio_dtrace_queue *);
static void vtdtr_vq_disable_intr(struct virtio_dtrace_queue *);
static void vtdtr_rxq_tq_intr(void *, int);
static void vtdtr_notify_ready(struct vtdtr_softc *);
static void vtdtr_rxq_vq_intr(void *);
static void vtdtr_txq_vq_intr(void *);
static int vtdtr_init_txq(struct vtdtr_softc *, int);
static int vtdtr_init_rxq(struct vtdtr_softc *, int);
static void vtdtr_queue_destroy(struct virtio_dtrace_queue *);
static void vtdtr_fill_desc(struct virtio_dtrace_queue *,
							struct virtio_dtrace_control *);
static void vtdtr_cq_init(struct vtdtr_ctrlq *);
static void vtdtr_cq_enqueue(struct vtdtr_ctrlq *,
							 struct vtdtr_ctrl_entry *);
static void vtdtr_cq_enqueue_front(struct vtdtr_ctrlq *,
								   struct vtdtr_ctrl_entry *);
static int vtdtr_cq_empty(struct vtdtr_ctrlq *);
static size_t vtdtr_cq_count(struct vtdtr_ctrlq *);
static struct vtdtr_ctrl_entry *vtdtr_cq_dequeue(struct vtdtr_ctrlq *);
static void vtdtr_notify(struct virtio_dtrace_queue *);
static void vtdtr_poll(struct virtio_dtrace_queue *);
static void vtdtr_consume_trace(void *);
static void vtdtr_run(void *);
static void vtdtr_advertise_prov_priv(void *, const char *, struct uuid *);
static void vtdtr_destroy_prov_priv(void *, struct uuid *);
static void vtdtr_advertise_probe_priv(void *, const char *, const char *,
									   const char *, struct uuid *);

static device_method_t vtdtr_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe, vtdtr_probe),
	DEVMETHOD(device_attach, vtdtr_attach),
	DEVMETHOD(device_detach, vtdtr_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_config_change, vtdtr_config_change),

	DEVMETHOD_END};

static driver_t vtdtr_driver = {
	"vtdtr",
	vtdtr_methods,
	sizeof(struct vtdtr_softc)};
static devclass_t vtdtr_devclass;

DRIVER_MODULE(virtio_dtrace, virtio_pci, vtdtr_driver, vtdtr_devclass,
			  vtdtr_modevent, 0);
MODULE_VERSION(virtio_dtrace, 1);
MODULE_DEPEND(virtio_dtrace, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_dtrace, dtrace, 1, 1, 1);

// TODO(Mara): check whether we need this
MODULE_DEPEND(virtio_dtrace, vtdtr, 1, 1, 1);

static struct virtio_feature_desc vtdtr_feature_desc[] = {
	{0, NULL}};

void (*dtrace_provide_all_probes)(void) = NULL;
int (*dtrace_probeid_enable)(dtrace_id_t) = NULL;
int (*dtrace_virtstate_create)(void) = NULL;
void (*dtrace_virtstate_destroy)(void) = NULL;
int (*dtrace_virtstate_go)(void) = NULL;
int (*dtrace_virtstate_stop)(void) = NULL;

static int
vtdtr_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type)
	{
	case MOD_LOAD:
		error = 0;
		break;
	case MOD_QUIESCE:
		error = 0;
		break;
	case MOD_UNLOAD:
		vtdtr_cleanup();
		error = 0;
		break;
	case MOD_SHUTDOWN:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static void
vtdtr_cleanup(void)
{
	/*
	 * Perhaps to be used for cleaning up the module unloading later on. For
	 * now, the VMM handles that.
	 */
}

static int
vtdtr_probe(device_t dev)
{
	if (virtio_get_device_type(dev) != VIRTIO_ID_DTRACE)
		return (ENXIO);

	device_set_desc(dev, "VirtIO DTrace driver");

	return (BUS_PROBE_DEFAULT);
}

struct vtdtr_traceq *
virtio_dtrace_device_register()
{
	KASSERT(tq != NULL, "trace queue not initialised");
	return tq;
}

int vtdtr_tq_empty(struct vtdtr_traceq *tq)
{
	return STAILQ_EMPTY(&tq->head);
}

void vtdtr_tq_enqueue(struct vtdtr_traceq *tq, struct vtdtr_trace_entry *trc_entry)
{
	STAILQ_INSERT_TAIL(&tq->head, trc_entry, entries);
	tq->n_entries++;
}

void vtdtr_tq_init(struct vtdtr_traceq *tq)
{
	STAILQ_INIT(&tq->head);
	tq->n_entries = 0;
}

struct vtdtr_trace_entry *vtdtr_tq_dequeue(struct vtdtr_traceq *tq)
{
	struct vtdtr_trace_entry *trc_entry;
	trc_entry = STAILQ_FIRST(&tq->head);
	if (trc_entry != NULL)
	{
		STAILQ_REMOVE_HEAD(&tq->head, entries);
		tq->n_entries--;
	}

	return trc_entry;
}

void vtdtr_tq_print(struct vtdtr_traceq *tq, char *from)
{
	printf("%s", from);

	struct vtdtr_trace_entry *trc_entry, *trc_entry_temp;

	if (!STAILQ_EMPTY(&tq->head))
		STAILQ_FOREACH_SAFE(trc_entry, &tq->head, entries, trc_entry_temp)
		{
			printf(" %d \n", trc_entry->uentry.trace.dtbd_size);
		}
	else
		printf("Trace queue is empty. \n");
}

void vtdtr_cq_print(struct vtdtr_ctrlq *cq, char *from)
{
	printf("%s", from);

	struct vtdtr_ctrl_entry *ctrl_entry, *ctrl_entry_temp;

	if (!STAILQ_EMPTY(&cq->head))
		STAILQ_FOREACH_SAFE(ctrl_entry, &cq->head, entries, ctrl_entry_temp)
		{
			printf("%d \n", ctrl_entry->ctrl.uctrl.trace_ev.dtbd_size);
		}
	else
		printf("Control queue is empty. \n");
}

/*
 * Here we initialize the device. This is largely boilerplate. Here we
 * initialize all of the necessary mutexes, condition variables, threads, the
 * control queue, virtqueues and taskqueues and perform the necessary error
 * checking. Finally, we spawn the vtdtr_run() communicator thread and return
 * the error code.
 *
 * If the error code is non-zero, we will detach the device immediately.
 */
static int
vtdtr_attach(device_t dev)
{
	struct vtdtr_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtdtr_dev = dev;
	mtx_init(&sc->vtdtr_mtx, "vtdtrmtx", NULL, MTX_DEF);
	sc->vtdtr_rx_nseg = 1;
	sc->vtdtr_tx_nseg = 1;
	sc->vtdtr_shutdown = 0;
	sc->vtdtr_host_ready = 1;

	/*
	vtdtr_advertise_prov = vtdtr_advertise_prov_priv;
	vtdtr_destroy_prov = vtdtr_destroy_prov_priv;
	vtdtr_advertise_probe = vtdtr_advertise_probe_priv;
	*/
	tq = malloc(sizeof(struct vtdtr_traceq), M_DEVBUF, M_NOWAIT | M_ZERO);

	if (tq == NULL)
	{
		error = ENOMEM;
		device_printf(dev, "cannot allocate memory for the trace queue");
		goto fail;
	}
	mtx_init(&tq->mtx, "vtdtrtqmtx", NULL, MTX_DEF);

	vtdtr_tq_init(tq);

	sc->vtdtr_ctrlq = malloc(sizeof(struct vtdtr_ctrlq),
							 M_DEVBUF, M_NOWAIT | M_ZERO);

	if (sc->vtdtr_ctrlq == NULL)
	{
		error = ENOMEM;
		device_printf(dev, "cannot allocate memory"
						   " for the control queue");
		goto fail;
	}
	mtx_init(&sc->vtdtr_ctrlq->mtx, "vtdtrctrlqmtx", NULL, MTX_DEF);

	vtdtr_cq_init(sc->vtdtr_ctrlq);

	sc->vtdtr_probelist = malloc(sizeof(struct vtdtr_probelist),
								 M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->vtdtr_probelist == NULL)
	{
		error = ENOMEM;
		device_printf(dev, "cannot allocate memory"
						   " for the probe list");
		goto fail;
	}
	LIST_INIT(&sc->vtdtr_probelist->head);
	mtx_init(&sc->vtdtr_probelist->mtx, "pblistmtx", NULL, MTX_DEF);

	virtio_set_feature_desc(dev, vtdtr_feature_desc);
	vtdtr_setup_features(sc);

	error = vtdtr_init_rxq(sc, 0);
	if (error)
	{
		device_printf(dev, "cannot initialize RX queue\n");
		goto fail;
	}

	error = vtdtr_init_txq(sc, 0);
	if (error)
	{
		device_printf(dev, "cannot initialize TX queue\n");
		goto fail;
	}

	error = vtdtr_alloc_virtqueues(sc);
	if (error)
	{
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	device_printf(dev, "txq = %s, rxq = %s\n",
				  sc->vtdtr_txq.vtdq_name, sc->vtdtr_rxq.vtdq_name);

	error = vtdtr_queue_populate(&sc->vtdtr_rxq);
	if (error)
	{
		device_printf(dev, "cannot populate %s\n",
					  sc->vtdtr_rxq.vtdq_name);
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error)
	{
		device_printf(dev, "cannot set up virtio interrupts\n");
		goto fail;
	}

	sc->vtdtr_commtd = malloc(sizeof(struct thread), M_DEVBUF,
							  M_NOWAIT | M_ZERO);
	sc->vtdtr_listd = malloc(sizeof(struct thread), M_DEVBUF,
							 M_NOWAIT | M_ZERO);

	if (sc->vtdtr_commtd == NULL)
	{
		error = ENOMEM;
		device_printf(dev, "cannot allocate memory"
						   " for the communicator thread");
		goto fail;
	}

	if (sc->vtdtr_listd == NULL)
	{
		error = ENOMEM;
		device_printf(dev, "cannot allocate memory"
						   " for the trace listener thread");
	}

	cv_init(&sc->vtdtr_condvar, "Virtio DTrace CV");
	mtx_init(&sc->vtdtr_condmtx, "vtdtrcondmtx", NULL, MTX_DEF);
	sema_init(&sc->vtdtr_exit, 0, "vtdtrexitsema");

	vtdtr_enable_interrupts(sc);

	vtdtr_start_taskqueues(sc);
	sc->vtdtr_ready = 0;
	vtdtr_notify_ready(sc);
	kthread_add(vtdtr_run, sc, NULL, &sc->vtdtr_commtd,
				0, 0, NULL, "vtdtr_communicator");
	kthread_add(vtdtr_consume_trace, sc, NULL, &sc->vtdtr_listd, 0, 0, NULL, "vtdtr_trace_data_consumer");

	/*dtrace_vtdtr_enable((void *)sc);*/
fail:
	if (error)
		vtdtr_detach(dev);

	return (error);
}

static void
vtdtr_cq_destroy(struct vtdtr_ctrlq *cq)
{
	struct vtdtr_ctrl_entry *n1, *n2;
	mtx_lock(&cq->mtx);
	n1 = STAILQ_FIRST(&cq->head);
	while (n1 != NULL)
	{
		n2 = STAILQ_NEXT(n1, entries);
		free(n1, M_DEVBUF);
		n1 = n2;
	}

	STAILQ_INIT(&cq->head);
	cq->n_entries = 0;
	mtx_unlock(&cq->mtx);
}

static void
vtdtr_condvar_destroy(struct vtdtr_softc *sc)
{
	mtx_lock(&sc->vtdtr_condmtx);
	cv_destroy(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
	mtx_destroy(&sc->vtdtr_condmtx);
}

/*
 * Here used memory in the
 * driver, drain all the taskqeueues and
 * destroy all the mutexes.
 */
static int
vtdtr_detach(device_t dev)
{
	struct vtdtr_softc *sc;
	;

	sc = device_get_softc(dev);

	mtx_lock(&sc->vtdtr_mtx);
	if (device_is_attached(dev))
		vtdtr_stop(sc);
	mtx_unlock(&sc->vtdtr_mtx);

	vtdtr_drain_taskqueues(sc);
	vtdtr_drain_virtqueues(sc);

	vtdtr_destroy_probelist(sc);
	vtdtr_queue_destroy(&sc->vtdtr_rxq);
	vtdtr_queue_destroy(&sc->vtdtr_txq);
	vtdtr_cq_destroy(sc->vtdtr_ctrlq);
	mtx_destroy(&sc->vtdtr_ctrlq->mtx);
	free(sc->vtdtr_ctrlq, M_DEVBUF);
	vtdtr_condvar_destroy(sc);
	mtx_destroy(&sc->vtdtr_mtx);

	return (0);
}

static int
vtdtr_config_change(device_t dev)
{
	/*
	 * There is no reason to change the configuration yet.
	 */
	return (0);
}

/*
 * Wrapper function for virtio_negotiate_features()
 */
static void
vtdtr_negotiate_features(struct vtdtr_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtdtr_dev;
	features = 0;

	sc->vtdtr_features = virtio_negotiate_features(dev, features);
}

/*
 * Set up the features that this driver can handle
 */
static void
vtdtr_setup_features(struct vtdtr_softc *sc)
{
	device_t dev;

	dev = sc->vtdtr_dev;

	vtdtr_negotiate_features(sc);
}

/*
 * Allocate all the virtqueues.
 */
static int
vtdtr_alloc_virtqueues(struct vtdtr_softc *sc)
{
	device_t dev;
	struct vq_alloc_info *info;
	struct virtio_dtrace_queue *rxq, *txq;
	int error;

	dev = sc->vtdtr_dev;
	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;
	rxq->vtdq_vqintr = vtdtr_rxq_vq_intr;
	txq->vtdq_vqintr = vtdtr_txq_vq_intr;

	info = malloc(2 * sizeof(struct vq_alloc_info), M_TEMP, M_NOWAIT);
	if (info == NULL)
		return (ENOMEM);

	VQ_ALLOC_INFO_INIT(&info[0], sc->vtdtr_rx_nseg, rxq->vtdq_vqintr, sc,
					   &rxq->vtdq_vq, "%s-control RX", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&info[1], sc->vtdtr_tx_nseg, txq->vtdq_vqintr, sc,
					   &txq->vtdq_vq, "%s-control TX", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, 0, 2, info);
	free(info, M_TEMP);

	return (error);
}

static void
vtdtr_stop(struct vtdtr_softc *sc)
{
	vtdtr_disable_interrupts(sc);
	virtio_stop(sc->vtdtr_dev);

	sc->vtdtr_shutdown = 1;
	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}

/*
 * A wrapper function around vtdtr_queue_enqueue_ctrl() used to requeue a
 * descriptor we have just processed in the RX taskqueue.
 */
static void
vtdtr_queue_requeue_ctrl(struct virtio_dtrace_queue *q,
						 struct virtio_dtrace_control *ctrl, int readable, int writable)
{
	struct vtdtr_softc *sc;
	device_t dev;
	int error;

	sc = q->vtdq_sc;
	dev = sc->vtdtr_dev;

	bzero(ctrl, sizeof(struct virtio_dtrace_control));
	error = vtdtr_queue_enqueue_ctrl(q, ctrl, readable, writable);
	KASSERT(error == 0, ("%s: cannot requeue control buffer %d",
						 __func__, error));
}

/*
 * A simple function used to populate the RX queue in the initialization
 */
static int
vtdtr_queue_populate(struct virtio_dtrace_queue *q)
{
	struct virtqueue *vq;
	int nbufs;
	int error;

	vq = q->vtdq_vq;
	error = ENOSPC;

	for (nbufs = 0; !virtqueue_full(vq); nbufs++)
	{
		error = vtdtr_queue_new_ctrl(q);
		if (error)
			break;
	}

	if (nbufs > 0)
	{
		virtqueue_notify(vq);
		error = 0;
	}

	return (error);
}

/*
 * Wrapper around the vtdtr_queue_enqueue_ctrl() function in order to create a
 * new descriptor in the RX queue.
 */
static int
vtdtr_queue_new_ctrl(struct virtio_dtrace_queue *q)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_control *ctrl;
	int error;

	sc = q->vtdq_sc;
	ctrl = malloc(sizeof(struct virtio_dtrace_control),
				  M_DEVBUF, M_NOWAIT | M_ZERO);
	if (ctrl == NULL)
		return (ENOMEM);

	error = vtdtr_queue_enqueue_ctrl(q, ctrl, 0, 1);
	if (error)
		free(ctrl, M_DEVBUF);

	return (error);
}

/*
 * A more hands-on function used to enqueue a control message in the virtqueue.
 * We use this in order to enqueue empty descriptors in the RX queue with the
 * writable >= 1 and readable == 0, and to enqueue control messages in the TX
 * queue with readable >= 1 and writable == 0.
 */
static int
vtdtr_queue_enqueue_ctrl(struct virtio_dtrace_queue *q,
						 struct virtio_dtrace_control *ctrl, int readable, int writable)
{
	struct sglist_seg seg;
	struct sglist sg;
	struct virtqueue *vq;
	int error;

	vq = q->vtdq_vq;

	sglist_init(&sg, 1, &seg);
	error = sglist_append(&sg, ctrl, sizeof(struct virtio_dtrace_control));
	KASSERT(error == 0, ("%s: error %d adding control to sglist",
						 __func__, error));

	error = virtqueue_enqueue(vq, ctrl, &sg, readable, writable);

	return (error);
}

/*
 * Used for identification of the event type we need to process and delegating
 * it to the according functions.
 */
static int
vtdtr_ctrl_process_event(struct vtdtr_softc *sc,
						 struct virtio_dtrace_control *ctrl)
{
	struct vtdtr_ctrl_pbevent *pb;
	struct vtdtr_ctrl_provevent *pv;
	struct timeval tv;

	device_t dev;
	size_t d_script_length;
	int retval;
	int error;

	dev = sc->vtdtr_dev;
	retval = 0;
	error = 0;

	// #ifdef VTDTR
	struct vtdtr_event *ev;
	// #endif

	int len;

	/*
	 * XXX: Double switch statement... meh.
	 */
	switch (ctrl->event)
	{
	case VIRTIO_DTRACE_DEVICE_READY:
		// if (debug)
		// device_printf(dev, "VIRTIO_DTRACE_DEVICE_READY\n");
		sc->vtdtr_host_ready = 1;
		break;
	case VIRTIO_DTRACE_REGISTER:
		// if (debug)
		// device_printf(dev, "VIRTIO_DTRACE_REGISTER\n");
		sc->vtdtr_ready = 0;
		pv = &ctrl->uctrl.prov_ev;
		break;
	case VIRTIO_DTRACE_UNREGISTER:
		// if (debug)
		//	device_printf(dev, "VIRTIO_DTRACE_UNREGISTER\n");
		sc->vtdtr_ready = 0;
		pv = &ctrl->uctrl.prov_ev;
		break;
	case VIRTIO_DTRACE_DESTROY:
		// if (debug)
		// 	device_printf(dev, "VIRTIO_DTRACE_DESTROY\n");
		sc->vtdtr_ready = 0;
		break;
	case VIRTIO_DTRACE_PROBE_CREATE:
		pb = &ctrl->uctrl.probe_ev;
		// if (debug)
		// 	device_printf(dev, "VIRTIO_DTRACE_PROBE_CREATE: %d\n", pb->probe);
		sc->vtdtr_ready = 0;
		break;
	case VIRTIO_DTRACE_PROBE_INSTALL:
	{
		sc->vtdtr_ready = 0;
		pb = &ctrl->uctrl.probe_ev;

		// if (debug)
		//	device_printf(dev, "VIRTIO_DTRACE_PROBE_INSTALL: %d\n", pb->probe);
		if (vstate == 0)
		{
			error = dtrace_virtstate_create();
			if (error)
			{
				device_printf(dev, "%s: error %d creating "
								   "virtstate",
							  __func__, error);
				break;
			}

			device_printf(dev, "Virtual state created\n");
			vstate = 1;
		}

		KASSERT(vstate == 1, ("vstate must be 1\n"));
		dtrace_provide_all_probes();
		error = dtrace_probeid_enable(pb->probe);
		if (error)
		{
			device_printf(dev, "%s: error %d enabling"
							   " probe %d\n",
						  __func__, error, pb->probe);
		}
		break;
	}
	case VIRTIO_DTRACE_SCRIPT:
		sc->vtdtr_ready = 0;
		ev = malloc(sizeof(struct vtdtr_event), M_TEMP, M_ZERO);
		KASSERT(ev != NULL, ("Malloc event failed.\n"));
		d_script_length = strlen(ctrl->uctrl.script_ev.d_script);

		// if (debug)
		//	device_printf(dev, "Length of the script is %d. \n", d_script_length);

		ev->type = VTDTR_EV_SCRIPT;
		ev->args.d_script.last = ctrl->uctrl.script_ev.last;
		if ((strlcpy(ev->args.d_script.script, ctrl->uctrl.script_ev.d_script, d_script_length + 1)) != d_script_length)
			device_printf(dev, "Error occured when copying script from control event. \n");
		vtdtr_enqueue(ev);

		// if (debug)
		// device_printf(dev, "I've enqueued %s.\n",
		//				  ev->args.d_script.script);
		break;
	case VIRTIO_DTRACE_GO:
		sc->vtdtr_ready = 0;

		// if (debug)
		// 	device_printf(dev, "VIRTIO_DTRACE_GO\n");

		error = dtrace_virtstate_go();
		if (error)
			device_printf(dev, "Error in dtrace_virtstate_go(): %d\n", error);
		else
			device_printf(dev, "Starting the trace...\n");
		break;
	case VIRTIO_DTRACE_STOP:
		sc->vtdtr_ready = 0;
		KASSERT(vstate == 1, ("vstate must exist\n"));

		// if (debug)
		// 	device_printf(dev, "VIRTIO_DTRACE_STOP\n");

		error = dtrace_virtstate_stop();
		if (error)
			device_printf(dev, "Error in dtrace_virtstate_stop(): %d\n", error);
		else
			device_printf(dev, "Stopping the trace...\n");

		dtrace_virtstate_destroy();
		vstate = 0;
		break;
	case VIRTIO_DTRACE_EOF:
		// if (debug)
		// 	device_printf(dev, "VIRTIO_DTRACE_EOF\n");
		retval = 1;
		break;
	default:
		device_printf(dev, "WARNING: Wrong control event: %x\n", ctrl->event);
		break;
	}

	return (retval);
}

/*
 * A wrapper function used to free the list of enabled probes
 */
static void
vtdtr_destroy_probelist(struct vtdtr_softc *sc)
{
	struct vtdtr_probelist *list;
	struct vtdtr_probe *tmp;

	list = sc->vtdtr_probelist;
	tmp = NULL;

	mtx_lock(&list->mtx);
	while (!LIST_EMPTY(&list->head))
	{
		tmp = LIST_FIRST(&list->head);
		LIST_REMOVE(tmp, vtdprobe_next);
		free(tmp, M_DEVBUF);
	}
	mtx_unlock(&list->mtx);
}

/*
 * Start all the taskqueues on the cpu_id = 1. This ensures that each of the
 * taskqueues have a thread assigned to them that will then process all the
 * events that take place.
 */
static void
vtdtr_start_taskqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq, *txq;
	device_t dev;
	int error;

	dev = sc->vtdtr_dev;
	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;

	error = taskqueue_start_threads(&rxq->vtdq_tq, 1, PI_SOFT,
									"%s rxq %d", device_get_nameunit(dev), rxq->vtdq_id);
	if (error)
		device_printf(dev, "failed to start rx taskq %d\n",
					  txq->vtdq_id);
}

/*
 * Drain all the taskqueues in the driver
 */
static void
vtdtr_drain_taskqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq, *txq;

	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;

	if (rxq->vtdq_tq != NULL)
		taskqueue_drain(rxq->vtdq_tq, &rxq->vtdq_intrtask);

	if (txq->vtdq_tq != NULL)
		taskqueue_drain(txq->vtdq_tq, &txq->vtdq_intrtask);
}

static void
vtdtr_drain_virtqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq, *txq;
	struct virtio_dtrace_control *ctrl;
	struct virtqueue *vq;
	uint32_t last;

	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;
	last = 0;

	// confusion

	vq = rxq->vtdq_vq;

	while ((ctrl = virtqueue_drain(vq, &last)) != NULL)
		free(ctrl, M_DEVBUF);

	vq = txq->vtdq_vq;

	while ((ctrl = virtqueue_drain(vq, &last)) != NULL)
		free(ctrl, M_DEVBUF);
}

/*
 * Disable interrupts on all of the virtqueues in the virtio driver
 */
static void
vtdtr_disable_interrupts(struct vtdtr_softc *sc)
{
	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	vtdtr_vq_disable_intr(&sc->vtdtr_rxq);
	vtdtr_vq_disable_intr(&sc->vtdtr_txq);
}

/*
 * Enable interrupts on all of the virtqueues in the virtio driver.
 */
static int
vtdtr_enable_interrupts(struct vtdtr_softc *sc)
{
	int retval;
	mtx_lock(&sc->vtdtr_mtx);
	retval = vtdtr_vq_enable_intr(&sc->vtdtr_rxq);
	retval = vtdtr_vq_enable_intr(&sc->vtdtr_txq);
	mtx_unlock(&sc->vtdtr_mtx);
}

/*
 * A wrapper function to enable interrupts in a virtqueue
 */
static int
vtdtr_vq_enable_intr(struct virtio_dtrace_queue *q)
{
	struct vtdtr_softc *sc;
	sc = q->vtdq_sc;
	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	return (virtqueue_enable_intr(q->vtdq_vq));
}

/*
 * A wrapper function to disable interrupts in a virtqueue
 */
static void
vtdtr_vq_disable_intr(struct virtio_dtrace_queue *q)
{
	struct vtdtr_softc *sc;
	sc = q->vtdq_sc;
	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	virtqueue_disable_intr(q->vtdq_vq);
}

static void
vtdtr_send_eof(struct virtio_dtrace_queue *q)
{
	struct virtio_dtrace_control *ctrl;
	ctrl = malloc(sizeof(struct virtio_dtrace_control),
				  M_DEVBUF, M_NOWAIT | M_ZERO);
	KASSERT(ctrl != NULL,
			("%s: no memory to allocate a control message", __func__));
	ctrl->event = VIRTIO_DTRACE_EOF;
	vtdtr_fill_desc(q, ctrl);
}

/*
 * This function is used to enqueue the READY descriptor in the TX virtqueue. If
 * we already are ready, we simply notify the communicator thread that it is
 * safe to proceed execution. If not, we enqueue the said descriptor and
 * following that notify the communicator.
 */
static void
vtdtr_notify_ready(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *q;
	struct vtdtr_ctrl_entry *ctrl_entry;
	device_t dev;

	dev = sc->vtdtr_dev;
	q = &sc->vtdtr_txq;

	sc->vtdtr_ready = 1;

	ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry),
						M_DEVBUF, M_NOWAIT | M_ZERO);

	if (ctrl_entry == NULL)
	{
		device_printf(dev, "no memory to allocate a control entry");
		return;
	}

	ctrl_entry->ctrl.event = VIRTIO_DTRACE_DEVICE_READY;

	mtx_lock(&sc->vtdtr_ctrlq->mtx);
	vtdtr_cq_enqueue_front(sc->vtdtr_ctrlq, ctrl_entry);
	mtx_unlock(&sc->vtdtr_ctrlq->mtx);

	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}

/*
 * The separate thread (created by the taskqueue) that acts as an interrupt
 * handler that blocks, allowing us to process more interrupts. In here we
 * dequeue every control message until we have either dequeued the maximum
 * allowed size of the virtqueue or until we hit an EOF descriptor. We process
 * each of the events lockless and finally notify that we are ready after
 * processing every event. Additionally, this function is responsible for
 * requeuing the memory in the virtqueue.
 */
static void
vtdtr_rxq_tq_intr(void *xrxq, int pending)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *rxq;
	struct virtio_dtrace_control *ctrl;
	uint32_t len;
	int retval;
	device_t dev;

	rxq = xrxq;
	sc = rxq->vtdq_sc;
	dev = sc->vtdtr_dev;
	retval = 0;

	VTDTR_QUEUE_LOCK(rxq);
	while ((ctrl = virtqueue_dequeue(rxq->vtdq_vq, &len)) != NULL)
	{
		KASSERT(len == sizeof(struct virtio_dtrace_control),
				("%s: wrong control message length: %u, expected %zu",
				 __func__, len, sizeof(struct virtio_dtrace_control)));

		VTDTR_QUEUE_UNLOCK(rxq);
		retval = vtdtr_ctrl_process_event(sc, ctrl);
		VTDTR_QUEUE_LOCK(rxq);

		vtdtr_queue_requeue_ctrl(rxq, ctrl, 0, 1);
		if (retval == 1)
			break;
	}
	VTDTR_QUEUE_UNLOCK(rxq);

	mtx_lock(&sc->vtdtr_mtx);
	vtdtr_notify(rxq);
	if (vtdtr_vq_enable_intr(rxq) != 0)
		taskqueue_enqueue(rxq->vtdq_tq, &rxq->vtdq_intrtask);

	if (sc->vtdtr_ready == 0)
		vtdtr_notify_ready(sc);
	mtx_unlock(&sc->vtdtr_mtx);

	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}

/*
 * Interrupt handler for the RX virtqueue. We enqueue the operation in the
 * taskqueue specific to the RX queue and enable interrupts.
 */
static void
vtdtr_rxq_vq_intr(void *xsc)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *rxq;
	device_t dev;

	sc = xsc;
	rxq = &sc->vtdtr_rxq;
	dev = sc->vtdtr_dev;

	taskqueue_enqueue(rxq->vtdq_tq, &rxq->vtdq_intrtask);
}

/*
 * Interrupt handler for the TX virtqueue. The only thing we do here is enable
 * interrupts again so that we can send control messages.
 */
static void
vtdtr_txq_vq_intr(void *xsc)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *txq;

	sc = xsc;
	txq = &sc->vtdtr_txq;

	mtx_lock(&sc->vtdtr_mtx);
	vtdtr_vq_enable_intr(txq);
	mtx_unlock(&sc->vtdtr_mtx);
}

/*
 * This functions sets up all the necessary data for the correct
 * operation of a RX queue of the VirtIO driver:
 *     rxq->vtdq_sc       <- sc
 *     rxq->vtdq_id       <- id
 *     rxq->vtdq_name     <- devname-rx(1|2|3...)
 *     rxq->vtdq_sg       <- allocate or ENOMEM
 *     rxq->vtdq_intrtask <- vtdtr_rxq_tq_intr
 *     rxq->vtdq_tq       <- create taskqueue
 */
static int
vtdtr_init_rxq(struct vtdtr_softc *sc, int id)
{
	struct virtio_dtrace_queue *rxq;

	rxq = &sc->vtdtr_rxq;

	snprintf(rxq->vtdq_name, sizeof(rxq->vtdq_name), "%s-rx%d",
			 device_get_nameunit(sc->vtdtr_dev), id);
	mtx_init(&rxq->vtdq_mtx, rxq->vtdq_name, NULL, MTX_DEF);

	rxq->vtdq_sc = sc;
	rxq->vtdq_id = id;

	TASK_INIT(&rxq->vtdq_intrtask, 0, vtdtr_rxq_tq_intr, rxq);
	rxq->vtdq_tq = taskqueue_create(rxq->vtdq_name, M_NOWAIT,
									taskqueue_thread_enqueue, &rxq->vtdq_tq);

	return (rxq->vtdq_tq == NULL ? ENOMEM : 0);
}

/*
* This functions sets up all the necessary data for the correct
* operation of a TX queue of the VirtIO driver:
*     txq->vtdq_sc       <- sc
*     txq->vtdq_id       <- id
*     txq->vtdq_name     <- devname-tx(1|2|3...)
*
* In the TX queue, we do not need a taskqueue as we are not required to handle
* complex events upon being interrupted by it.
*/
static int
vtdtr_init_txq(struct vtdtr_softc *sc, int id)
{
	struct virtio_dtrace_queue *txq;

	txq = &sc->vtdtr_txq;

	snprintf(txq->vtdq_name, sizeof(txq->vtdq_name), "%s-tx%d",
			 device_get_nameunit(sc->vtdtr_dev), id);
	mtx_init(&txq->vtdq_mtx, txq->vtdq_name, NULL, MTX_DEF);

	txq->vtdq_sc = sc;
	txq->vtdq_id = id;

	return (0);
}

/*
 * Destroy a given queue.
 */
static void
vtdtr_queue_destroy(struct virtio_dtrace_queue *q)
{
	mtx_destroy(&q->vtdq_mtx);
	q->vtdq_sc = NULL;
	if (q->vtdq_tq != NULL)
		taskqueue_free(q->vtdq_tq);
}

/*
 * Fill the virtqueue descriptor with a given control message. This is a wrapper
 * around vtdtr_queue_enqueue_ctrl() with read-only data
 */
static void
vtdtr_fill_desc(struct virtio_dtrace_queue *q,
				struct virtio_dtrace_control *ctrl)
{
	VTDTR_QUEUE_LOCK(q);
	vtdtr_queue_enqueue_ctrl(q, ctrl, 1, 0);
	VTDTR_QUEUE_UNLOCK(q);
}

static void
vtdtr_cq_init(struct vtdtr_ctrlq *cq)
{

	STAILQ_INIT(&cq->head);
	cq->n_entries = 0;
}

static __inline void
vtdtr_cq_enqueue(struct vtdtr_ctrlq *cq,
				 struct vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_TAIL(&cq->head, ctrl_entry, entries);
	cq->n_entries++;
}

static __inline void
vtdtr_cq_enqueue_front(struct vtdtr_ctrlq *cq,
					   struct vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_HEAD(&cq->head, ctrl_entry, entries);
	cq->n_entries++;
}

static __inline int
vtdtr_cq_empty(struct vtdtr_ctrlq *cq)
{

	return (STAILQ_EMPTY(&cq->head));
}

static __inline __unused size_t
vtdtr_cq_count(struct vtdtr_ctrlq *cq)
{

	return (cq->n_entries);
}

static struct vtdtr_ctrl_entry *
vtdtr_cq_dequeue(struct vtdtr_ctrlq *cq)
{
	struct vtdtr_ctrl_entry *ctrl_entry;
	ctrl_entry = STAILQ_FIRST(&cq->head);
	if (ctrl_entry != NULL)
	{
		STAILQ_REMOVE_HEAD(&cq->head, entries);
		cq->n_entries--;
	}

	return (ctrl_entry);
}

static void
vtdtr_notify(struct virtio_dtrace_queue *q)
{
	struct virtqueue *vq;

	vq = q->vtdq_vq;

	VTDTR_QUEUE_LOCK(q);
	virtqueue_notify(vq);
	VTDTR_QUEUE_UNLOCK(q);
}

static void
vtdtr_poll(struct virtio_dtrace_queue *q)
{
	struct virtqueue *vq;

	vq = q->vtdq_vq;

	VTDTR_QUEUE_LOCK(q);
	virtqueue_notify(vq);
	virtqueue_poll(vq, NULL);
	VTDTR_QUEUE_UNLOCK(q);
}

static void
vtdtr_consume_trace(void *xsc)
{
	struct vtdtr_ctrlq *cq;
	struct vtdtr_softc *sc;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct vtdtr_trace_entry *trc_entry;
	struct virtio_dtrace_control *ctrl;
	struct virtio_dtrace_trace *trc;
	struct virtio_dtrace_metadata *mtd;
	struct vtdtr_ctrl_trcevent *ctrl_trc_ev;
	struct vtdtr_ctrl_metaevent *ctrl_mtd_ev;
	struct timeval tv;

	device_t dev;
	size_t trc_buf_len, epdesc_len, pbdesc_len, fmt_len;
	size_t cp;
	int error;

	char *data;
	uint64_t data_sz, to_send;

	sc = xsc;
	cq = sc->vtdtr_ctrlq;
	dev = sc->vtdtr_dev;
	for (;;)
	{
		mtx_lock(&tq->mtx);
		while (!vtdtr_tq_empty(tq))
		{
			trc_entry = vtdtr_tq_dequeue(tq);

			ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry), M_DEVBUF, M_NOWAIT | M_ZERO);
			KASSERT(ctrl_entry != NULL, "Failed allocating memory for control entry.");
			memset(ctrl_entry, 0, sizeof(struct vtdtr_ctrl_entry));

			switch (trc_entry->type)
			{
			case DDTRACE_TRACE:
				trc = &trc_entry->uentry.trace;
				KASSERT(trc->dtbd_data != NULL, "Trace data buffer cannot be NULL.");

				ctrl = &ctrl_entry->ctrl;
				ctrl->event = VIRTIO_DTRACE_TRACE;
				ctrl_trc_ev = &ctrl->uctrl.trace_ev;

				ctrl_trc_ev->dtbd_size = trc->dtbd_size;
				ctrl_trc_ev->dtbd_cpu = trc->dtbd_cpu;
				ctrl_trc_ev->dtbd_errors = trc->dtbd_errors;
				ctrl_trc_ev->dtbd_drops = trc->dtbd_drops;
				ctrl_trc_ev->dtbd_oldest = trc->dtbd_oldest;
				ctrl_trc_ev->dtbd_timestamp = trc->dtbd_timestamp;
				KASSERT(ctrl_trc_ev->dtbd_size == trc->dtbd_size, "Failed copying into fields");

				data = trc->dtbd_data;
				data_sz = trc->dtbd_size;
				KASSERT(data_sz == ctrl_trc_ev->dtbd_size, "Invalid trace buffer size");
				to_send = (data_sz > FRAGMENTSZ) ? FRAGMENTSZ : data_sz;
				ctrl_trc_ev->first_chunk = 1;
				ctrl_trc_ev->last_chunk = (data_sz > FRAGMENTSZ) ? 0 : 1;
				data_sz -= to_send;

				ctrl_trc_ev->chunk_sz = to_send;
				memcpy(ctrl_trc_ev->dtbd_chunk, data, to_send);

				mtx_lock(&sc->vtdtr_ctrlq->mtx);
				vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
				mtx_unlock(&sc->vtdtr_ctrlq->mtx);

				mtx_lock(&sc->vtdtr_condmtx);
				cv_signal(&sc->vtdtr_condvar);
				mtx_unlock(&sc->vtdtr_condmtx);

				while (data_sz > 0)
				{
					data += to_send;
					ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry), M_DEVBUF, M_NOWAIT | M_ZERO);
					KASSERT(ctrl_entry != NULL, "Failed allocating memory for control entry.");
					memset(ctrl_entry, 0, sizeof(struct vtdtr_ctrl_entry));

					ctrl = &ctrl_entry->ctrl;
					ctrl->event = VIRTIO_DTRACE_TRACE;
					ctrl_trc_ev = &ctrl->uctrl.trace_ev;
					ctrl_trc_ev->first_chunk = 0;
					ctrl_trc_ev->last_chunk = (data_sz > FRAGMENTSZ) ? 0 : 1;
					to_send = (data_sz > FRAGMENTSZ) ? FRAGMENTSZ : data_sz;
					data_sz -= to_send;

					ctrl_trc_ev->chunk_sz = to_send;
					memcpy(ctrl_trc_ev->dtbd_chunk, data, to_send);

					mtx_lock(&sc->vtdtr_ctrlq->mtx);
					vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
					mtx_unlock(&sc->vtdtr_ctrlq->mtx);

					mtx_lock(&sc->vtdtr_condmtx);
					cv_signal(&sc->vtdtr_condvar);
					mtx_unlock(&sc->vtdtr_condmtx);
				}

				break;
			case DDTRACE_METADATA:
				mtd = &trc_entry->uentry.metadata;
				ctrl = &ctrl_entry->ctrl;
				ctrl->event = VIRTIO_DTRACE_METADATA;
				ctrl_mtd_ev = &ctrl->uctrl.meta_ev;
				ctrl_mtd_ev->type = mtd->type;
				switch (mtd->type)
				{
				case NFORMAT:
					ctrl_mtd_ev->umtd.dts_nformats = mtd->umtd.dts_nformats;
					break;
				case FORMAT_STRING:
					fmt_len = strlen(mtd->umtd.dts_fmtstr);
					if (fmt_len < FRAGMENTSZ)
					{
						cp = strlcpy(ctrl_mtd_ev->umtd.dts_fmtstr, mtd->umtd.dts_fmtstr, fmt_len + 1);
						KASSERT(cp == fmt_len, "Error occurred while copying format string");
					}
					else
					{
						device_printf(dev, "Format string doesn't fit in control element");
					}
					break;
				case NPROBES:
					ctrl_mtd_ev->umtd.dtrace_nprobes = mtd->umtd.dtrace_nprobes;
					break;
				case NPDESC:
					ctrl_mtd_ev->umtd.dt_npdescs = mtd->umtd.dt_npdescs;
					break;
				case PROBE_DESCRIPTION:
					ctrl_mtd_ev->umtd.dt_pdesc.buf_size = mtd->umtd.dt_pdesc.buf_size;
					KASSERT(ctrl_mtd_ev->umtd.dt_pdesc.buf_size == sizeof(dtrace_probedesc_t), "Probe description size is invalid");
					memcpy(ctrl_mtd_ev->umtd.dt_pdesc.buf, mtd->umtd.dt_pdesc.buf, sizeof(dtrace_probedesc_t));
					break;
				case EPROBE_DESCRIPTION:
					ctrl_mtd_ev->umtd.dt_epdesc.buf_size = mtd->umtd.dt_epdesc.buf_size;
					memcpy(ctrl_mtd_ev->umtd.dt_epdesc.buf,
						   mtd->umtd.dt_epdesc.buf,
						   mtd->umtd.dt_epdesc.buf_size);
					break;
				default:
					device_printf(dev, "WARNING: Wrong metadata event.");
					break;
				}
				mtx_lock(&sc->vtdtr_ctrlq->mtx);
				vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
				mtx_unlock(&sc->vtdtr_ctrlq->mtx);

				mtx_lock(&sc->vtdtr_condmtx);
				cv_signal(&sc->vtdtr_condvar);
				mtx_unlock(&sc->vtdtr_condmtx);
				break;
			default:
				device_printf(dev, "WARNING: Wrong trace queue event.");
				break;
			}

			vtdtr_notify_ready(sc);
			free(trc_entry, M_DEVBUF);
		}
		mtx_unlock(&tq->mtx);
	}
}

/*
 * This is the communicator thread. It is responsible for spinning until we shut
 * down and sending messages to the emulated PCI device on the host.
 */
static void
vtdtr_run(void *xsc)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *txq;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct virtio_dtrace_control *ctrls;
	struct virtqueue *vq;
	device_t dev;
	size_t vq_size;
	int nent;
	int ready_flag;

	sc = xsc;
	dev = sc->vtdtr_dev;

	txq = &sc->vtdtr_txq;
	vq = txq->vtdq_vq;
	vq_size = virtqueue_size(vq);

	ctrls = malloc(sizeof(struct virtio_dtrace_control) *
					   vq_size,
				   M_DEVBUF, M_NOWAIT | M_ZERO);
	if (ctrls == NULL)
	{
		panic("No memory for vtdtr_run()");
	}

	for (;;)
	{
		nent = 0;
		ready_flag = 1;
		memset(ctrls, 0,
			   vq_size * sizeof(struct virtio_dtrace_control));

		mtx_lock(&sc->vtdtr_condmtx);
		/*
		 * We are safe to proceed sending messages if the following
		 * conditions are satisfied:
		 * (1) We have messages in the control queue
		 * (2) The host is ready to receive messages
		 * or if we are
		 * (3) Shutting down
		 */

		while ((vtdtr_cq_empty(sc->vtdtr_ctrlq) ||
				!sc->vtdtr_host_ready) &&
			   (!sc->vtdtr_shutdown))
		{
			cv_wait(&sc->vtdtr_condvar, &sc->vtdtr_condmtx);
		}
		mtx_unlock(&sc->vtdtr_condmtx);

		kthread_suspend_check();

		if (sc->vtdtr_shutdown == 1)
		{
			free(ctrls, M_DEVBUF);
			sema_post(&sc->vtdtr_exit);
			kthread_exit();
		}

		KASSERT(!virtqueue_full(vq),
				("%s: virtqueue is full", __func__));
		KASSERT(!vtdtr_cq_empty(sc->vtdtr_ctrlq),
				("%s: control queue is empty", __func__));

		/*
		 * Here we drain the control queue until it's either:
		 * (1) Empty
		 * (2) We have no room in the virtqueue
		 *
		 * Following every dequeue, we free the control entry in the
		 * control queue and send the control messages through the
		 * virtqueue. Additionally, we keep a count of entries
		 * processed.
		 */
		mtx_lock(&sc->vtdtr_ctrlq->mtx);
		while (!virtqueue_full(vq) &&
			   !vtdtr_cq_empty(sc->vtdtr_ctrlq))
		{
			ctrl_entry = vtdtr_cq_dequeue(sc->vtdtr_ctrlq);
			mtx_unlock(&sc->vtdtr_ctrlq->mtx);
			memcpy(&ctrls[nent], &ctrl_entry->ctrl,
				   sizeof(struct virtio_dtrace_control));
			if (ready_flag &&
				ctrls[nent].event != VIRTIO_DTRACE_DEVICE_READY)
				ready_flag = 0;

			// if(ctrl_entry->ctrl.event == VIRTIO_DTRACE_TRACE)
			// {
			// 	nanouptime(&tv1);
			// 	device_printf(dev, "Time of send %ld s %ld ns\n", tv1.tv_sec, tv1.tv_nsec);
			// }
			vtdtr_fill_desc(txq, &ctrls[nent]);
			free(ctrl_entry, M_DEVBUF);
			nent++;
			// check size of control element
			//
			mtx_lock(&sc->vtdtr_ctrlq->mtx);
		}

		/*
		 * If we have processed any entries, we ought to send an EOF
		 * unless we have filled up the virtqueue. Otherwise, the EOF is
		 * implicit.
		 */
		if (nent)
		{
			if (vtdtr_cq_empty(sc->vtdtr_ctrlq) &&
				!virtqueue_full(vq))
			{
				vtdtr_send_eof(txq);
			}

			sc->vtdtr_host_ready = ready_flag;
			vtdtr_poll(txq);
		}

		mtx_unlock(&sc->vtdtr_ctrlq->mtx);
	}
}

static void
vtdtr_advertise_prov_priv(void *xsc, const char *name, struct uuid *uuid)
{
	struct vtdtr_softc *sc;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct virtio_dtrace_control *ctrl;
	device_t dev;

	sc = xsc;
	dev = sc->vtdtr_dev;

	ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry),
						M_DEVBUF, M_NOWAIT | M_ZERO);

	if (ctrl_entry == NULL)
	{
		device_printf(dev, "no memory to allocate a control entry");
		return;
	}

	ctrl = &ctrl_entry->ctrl;
	ctrl->event = VIRTIO_DTRACE_REGISTER;
	memcpy(&ctrl->uctrl.prov_ev.uuid, uuid, sizeof(struct uuid));
	strlcpy(ctrl->uctrl.prov_ev.name, name, DTRACE_PROVNAMELEN);

	mtx_lock(&sc->vtdtr_ctrlq->mtx);
	vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
	mtx_unlock(&sc->vtdtr_ctrlq->mtx);

	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}

static void
vtdtr_destroy_prov_priv(void *xsc, struct uuid *uuid)
{
	struct vtdtr_softc *sc;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct virtio_dtrace_control *ctrl;
	device_t dev;

	sc = xsc;
	dev = sc->vtdtr_dev;

	ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry),
						M_DEVBUF, M_NOWAIT | M_ZERO);

	if (ctrl_entry == NULL)
	{
		device_printf(dev, "no memory to allocate a control entry");
		return;
	}

	ctrl = &ctrl_entry->ctrl;
	ctrl->event = VIRTIO_DTRACE_UNREGISTER;
	memcpy(&ctrl->uctrl.prov_ev.uuid, uuid, sizeof(struct uuid));

	mtx_lock(&sc->vtdtr_ctrlq->mtx);
	vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
	mtx_unlock(&sc->vtdtr_ctrlq->mtx);

	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}

static void
vtdtr_advertise_probe_priv(void *xsc, const char *mod, const char *func,
						   const char *name, struct uuid *uuid)
{
	struct vtdtr_softc *sc;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct virtio_dtrace_control *ctrl;
	struct vtdtr_pbev_create_event *cevent;
	device_t dev;

	sc = xsc;
	dev = sc->vtdtr_dev;

	ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry),
						M_DEVBUF, M_NOWAIT | M_ZERO);

	if (ctrl_entry == NULL)
	{
		device_printf(dev, "no memory to allocate a control entry");
		return;
	}

	ctrl = &ctrl_entry->ctrl;
	ctrl->event = VIRTIO_DTRACE_PROBE_CREATE;
	cevent = &ctrl->uctrl.probe_ev.upbev.create;
	strlcpy(cevent->mod, mod, DTRACE_MODNAMELEN);
	strlcpy(cevent->func, func, DTRACE_FUNCNAMELEN);
	strlcpy(cevent->name, name, DTRACE_NAMELEN);
	memcpy(&cevent->uuid, uuid, sizeof(struct uuid));

	mtx_lock(&sc->vtdtr_ctrlq->mtx);
	vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
	mtx_unlock(&sc->vtdtr_ctrlq->mtx);

	mtx_lock(&sc->vtdtr_condmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_condmtx);
}
