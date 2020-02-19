
#ifndef _PCI_VIRTIO_DTRACE_H
#define _PCI_VIRTIO_DTRACE_H
#include <sys/queue.h>
#include <stdint.h>
#include <pthread.h>
#include <dtrace.h>

struct dtrace_trc_entry {
	dtrace_bufdesc_t desc;
	STAILQ_ENTRY(dtrace_trc_entry) 
	entries;
};

struct dtrace_traceq {
	STAILQ_HEAD(, dtrace_trc_entry) 
	head;
	pthread_mutex_t mtx;
};

void pci_vtdtr_tq_enqueue(struct dtrace_traceq *, struct dtrace_trc_entry *);
int pci_vtdtr_tq_empty(struct dtrace_traceq *);
struct dtrace_trc_entry pci_vtdtr_tq_dequeue(struct dtrace_traceq);
void pci_vtdtr_tq_init(struct dtrace_traceq *tq);

#endif