#ifndef _SHIMVTDTR_H
#define _SHIMVTDTR_H

#include <sys/vtdtr.h>


/*
    Shim layer ...
*/

extern void shim_vtdtr_enqueue(struct vtdtr_event);

#endif