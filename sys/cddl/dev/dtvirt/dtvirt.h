#ifndef _DTVIRT_H_
#define _DTVIRT_H_

#include <sys/proc.h>

extern void dtvirt_probe(void *, int, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern void * (*dtvirt_ptr)(void *, uintptr_t, size_t);
extern void (*dtvirt_bcopy)(void *, void *, void *, size_t);
extern void (*dtvirt_free)(void *, size_t);
extern lwpid_t (*dtvirt_gettid)(void *);
extern uint16_t (*dtvirt_getns)(void *);

#endif
