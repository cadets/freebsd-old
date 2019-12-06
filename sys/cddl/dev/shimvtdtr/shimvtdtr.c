
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/module.h>
#include <sys/vtdtr.h>

#include <vtdtr/vtdtr.h>


#include "shimvtdtr.h"

void shim_vtdtr_enqueue(struct vtdtr_event e) {
    vtdtr_enqueue(&e);
}