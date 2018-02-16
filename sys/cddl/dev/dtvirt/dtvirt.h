#ifndef _DTVIRT_H_
#define _DTVIRT_H_

extern void dtvirt_probe(void *, int, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern void * (*dtvirt_ptr)(void *, uintptr_t, size_t);
extern void (*dtvirt_free)(void *, size_t);

#endif
