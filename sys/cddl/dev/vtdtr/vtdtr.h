#ifndef _DEV_VTDTR_H_
#define _DEV_VTDTR_H_

#include <sys/vtdtr.h>

extern void vtdtr_enqueue(struct vtdtr_event *);

#endif

// this has to be surfaced to virtio
