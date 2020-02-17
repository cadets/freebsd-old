
#ifndef _PCI_VIRTIO_DTRACE_H
#define _PCI_VIRTIO_DTRACE_H
#include <sys/queue.h>
#include <stdint.h>
#include <pthread.h>

struct dtrace_trc_data {
	uint64_t dtbd_size;
	uint32_t dtbd_cpu;
	uint32_t dtbd_errors;
	uint32_t dtbd_drops;
	char dtbd_data[512];
	uint64_t dtbd_oldest;
};

struct dtrace_trc_entry {
	struct dtrace_trc_data data;
	STAILQ_ENTRY(dtrace_trc_entry) 
	entries;
};

struct dtrace_traceq {
	STAILQ_HEAD(, dtrace_trc_entry) 
	head;
	pthread_mutex_t mtx;
};

extern void pci_vtdtr_tq_enqueue(struct dtrace_traceq *, struct dtrace_traceq *);
extern int pci_vtdtr_tq_empty(struct dtrace_traceq *);
extern struct dtrace_trc_entry pci_vtdtr_tq_dequeue(struct dtrace_traceq);
extern void pci_vtdtr_tq_init(struct dtrace_traceq *tq);

#endif