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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <dev/virtio/dtrace/virtio_dtrace.h>

#include "dttransport.h"

static MALLOC_DEFINE(M_DTTRANSPORT, "dttransport", "");

typedef struct dtt_qentry {
	TAILQ_ENTRY(dtt_qentry)	next;
	struct dtt_entry	*ent;
} dtt_qentry_t;

struct dtt_softc {
	struct cdev			*cdev;
	struct mtx			mtx;
	
	struct cv			cv;
	struct mtx			cvmtx;

	TAILQ_HEAD(, dtt_qentry)	dataq;
	struct mtx			qmtx;

	struct proc			*proc;
};

static struct dtt_softc *gsc = NULL;

/*
 * device methods
 */
static int	dtt_attach(device_t);
static int	dtt_detach(device_t);

/*
 * cdevsw
 */
static d_read_t		dtt_read;
static d_write_t	dtt_write;
static d_open_t		dtt_open;
static d_close_t	dtt_close;

static struct cdevsw dtt_cdevsw = {
	.d_version	= D_VERSION,
	.d_open		= dtt_open,
	.d_close	= dtt_close,
	.d_read		= dtt_read,
	.d_write	= dtt_write,
	.d_name		= "dttransport"
};

static dtt_qentry_t *
dtt_queue_fst(struct dtt_softc *sc)
{

	return (TAILQ_FIRST(&sc->dataq));
}

static int
dtt_queue_empty(struct dtt_softc *sc)
{

	return (dtt_queue_fst(sc) == NULL);
}

static void
dtt_queue_remove(struct dtt_softc *sc, dtt_qentry_t *qe)
{

	TAILQ_REMOVE(&sc->dataq, qe, next);
}

static int
dtt_handler(module_t mod, int what, void *arg)
{
	struct dtt_softc *sc = NULL;

	switch (what) {
	case MOD_LOAD:
		sc = malloc(sizeof(struct dtt_softc),
		    M_DTTRANSPORT, M_WAITOK | M_ZERO);
		gsc = sc;

		mtx_init(&sc->mtx, "dttscmtx", NULL, MTX_DEF);
		mtx_init(&sc->qmtx, "dttqmtx", NULL, MTX_DEF);
		mtx_init(&sc->cvmtx, "dttcvmtx", NULL, MTX_DEF);

		cv_init(&sc->cv, "dttransport CV");

		sc->cdev = make_dev(&dtt_cdevsw, 0, UID_ROOT, GID_OPERATOR,
		    S_IRUSR | S_IWUSR, "dttransport");
		sc->cdev->si_drv1 = sc;
		TAILQ_INIT(&sc->dataq);

		break;

	case MOD_UNLOAD:
		sc = gsc;

		KASSERT(sc != NULL, ("sc must not be NULL on module unload"));

		mtx_destroy(&sc->mtx);
		mtx_destroy(&sc->qmtx);

		mtx_lock(&sc->cvmtx);
		cv_destroy(&sc->cv);
		mtx_unlock(&sc->cvmtx);
		
		mtx_destroy(&sc->cvmtx);

		free(sc, M_DTTRANSPORT);
		gsc = NULL;
		break;

	default:
		break;
	}

	return (0);
}


static int
dtt_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct dtt_softc *sc;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	if (sc->proc != NULL) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	
	sc->proc = td->td_proc;
	mtx_unlock(&sc->mtx);
	
	return (0);
}

static int
dtt_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct dtt_softc *sc;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	sc->proc = NULL;
	mtx_unlock(&sc->mtx);
	
	return (0);
}

static int
dtt_read(struct cdev *dev, struct uio *uio, int flags)
{
	struct dtt_softc *sc;
	int err;
	dtt_qentry_t *entry;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	KASSERT(sc->proc != NULL,
	    ("%s(%d): proc must not be NULL", __func__, __LINE__));

	KASSERT(uio->uio_rw == UIO_READ, ("%s: bogus write", __func__));
	KASSERT(uio->uio_resid >= 0, ("%s: bogus negative resid", __func__));

	err = 0;
	
	if (uio->uio_resid != DTT_ENTRYLEN) {
		mtx_unlock(&sc->mtx);
		return (EINVAL);
	}

	if (uio->uio_td->td_proc != sc->proc) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}

	mtx_unlock(&sc->mtx);

	mtx_lock(&sc->cvmtx);
	while (err == 0 && dtt_queue_empty(sc))
		err = cv_wait_sig(&sc->cv, &sc->cvmtx);
	mtx_unlock(&sc->cvmtx);

	if (err)
		return (err);

	mtx_lock(&sc->qmtx);
	entry = dtt_queue_fst(sc);
	mtx_unlock(&sc->qmtx);

	err = uiomove(entry->ent, DTT_ENTRYLEN, uio);

	mtx_lock(&sc->qmtx);
	dtt_queue_remove(sc, entry);
	mtx_unlock(&sc->qmtx);

	free(entry->ent, M_DEVBUF);
	free(entry, M_DEVBUF);
	return (err);
}

static int
dtt_write(struct cdev *dev, struct uio *uio, int flags)
{
	struct dtt_softc *sc;
	int err;
	dtt_entry_t entry;

	sc = dev->si_drv1;

	err = 0;

	mtx_lock(&sc->mtx);
	KASSERT(sc->proc != NULL,
	    ("%s(%d): proc must not be NULL", __func__, __LINE__));

	KASSERT(uio->uio_rw == UIO_WRITE, ("%s: bogus write", __func__));
	KASSERT(uio->uio_resid >= 0, ("%s: bogus negative resid", __func__));

	if (uio->uio_resid != DTT_ENTRYLEN) {
		mtx_unlock(&sc->mtx);
		return (EINVAL);
	}

	if (uio->uio_td->td_proc != sc->proc) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	
	mtx_unlock(&sc->mtx);

	err = uiomove(&entry, DTT_ENTRYLEN, uio);
	if (err)
		return (err);

	err = virtio_dtrace_enqueue(&entry);
	if (err)
		return (err);

	return (0);
}

int
dtt_queue_enqueue(dtt_entry_t *e)
{
	struct dtt_softc *sc;
	dtt_qentry_t *qe;
	dtt_entry_t *ent;

	qe = NULL;
	ent = NULL;
	
	sc = gsc;

	qe = malloc(sizeof(dtt_qentry_t), M_DTTRANSPORT, M_NOWAIT | M_ZERO);
	if (qe == NULL)
		return (-1);

	ent = malloc(sizeof(dtt_entry_t), M_DTTRANSPORT, M_NOWAIT | M_ZERO);
	if (ent == NULL) {
		free(qe, M_DTTRANSPORT);
		return (-1);
	}

	memcpy(ent, e, sizeof(dtt_entry_t));
	qe->ent = ent;

	mtx_lock(&sc->qmtx);
	TAILQ_INSERT_TAIL(&sc->dataq, qe, next);
	mtx_unlock(&sc->qmtx);

	mtx_lock(&sc->cvmtx);
	cv_signal(&sc->cv);
	mtx_unlock(&sc->cvmtx);

	return (0);
}

static moduledata_t dtt_kmod = {
	"dttransport",
	dtt_handler,
	NULL
};

DECLARE_MODULE(dttransport, dtt_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(dttransport, 1);
MODULE_DEPEND(dttransport, virtio_dtrace, 1, 1, 1);
