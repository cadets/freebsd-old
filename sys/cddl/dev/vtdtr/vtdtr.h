#ifndef _DEV_VTDTR_H_
#define _DEV_VTDTR_H_

#include <sys/vtdtr.h>
#include <sys/dtrace.h>

/*
 * We only have one event at the moment -- possibly others in the future.
 */
struct vtdtr_event {
	size_t type;

	union {
		struct {
			dtrace_id_t probeid;
		} p_toggle;
	} args;
};


void vtdtr_enqueue(struct vtdtr_event *);

#endif
