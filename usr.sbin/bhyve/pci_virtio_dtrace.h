
#ifndef _PCI_VIRTIO_DTRACE_H
#define _PCI_VIRTIO_DTRACE_H
#include <sys/queue.h>
#include <stdint.h>
#include <pthread.h>

struct pci_vtdtr_trc_data {
	uint64_t dtbd_size;
	uint32_t dtbd_cpu;
	uint32_t dtbd_errors;
	uint32_t dtbd_drops;
	char dtbd_data[512];
	uint64_t dtbd_oldest;
};

struct pci_vtdtr_trc_entry {
	struct pci_vtdtr_trc_data data;
	STAILQ_ENTRY(pci_vtdtr_trc_entry) 
	entries;
};

struct pci_vtdtr_traceq {
	STAILQ_HEAD(, pci_vtdtr_trc_entry) 
	head;
	pthread_mutex_t mtx;
};

void pci_vtdtr_tq_enqueue(struct pci_vtdtr_traceq *, struct pci_vtdtr_traceq *);
int pci_vtdtr_tq_empty(struct pci_vtdtr_traceq *);
struct pci_vtdtr_trc_entry pci_vtdtr_tq_dequeue(struct pci_vtdtr_traceq);
void pci_vtdtr_tq_init(struct pci_vtdtr_traceq *tq);

#endif