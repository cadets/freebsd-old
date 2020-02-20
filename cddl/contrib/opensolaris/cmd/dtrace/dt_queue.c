#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "dt_queue.h"

void pci_vtdtr_tq_enqueue(struct pci_vtdtr_traceq *tq, struct pci_vtdtr_trc_entry *trc_entry)
{
	STAILQ_INSERT_HEAD(&tq->head, trc_entry, entries);
}

struct pci_vtdtr_trc_entry* pci_vtdtr_tq_dequeue(struct pci_vtdtr_traceq *tq)
{
	struct pci_vtdtr_trc_entry *trc_entry;
	trc_entry = STAILQ_FIRST(&tq->head);
	if (trc_entry != NULL)
	{
		STAILQ_REMOVE_HEAD(&tq->head, entries);
	}
	return (trc_entry);

}

int
pci_vtdtr_tq_empty(struct pci_vtdtr_traceq *tq)
{
	return (STAILQ_EMPTY(&tq->head));
}

void 
pci_vtdtr_tq_init(struct pci_vtdtr_traceq *tq)
{
    tq = calloc(1,sizeof(struct pci_vtdtr_traceq));
	assert(tq != NULL);
	STAILQ_INIT(&tq->head);
}
