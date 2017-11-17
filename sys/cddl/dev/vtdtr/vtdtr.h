#ifndef _VTDTR_H_
#define _VTDTR_H_

/*
 * We only have one event at the moment -- possibly others in the future.
 */
struct vtdtr_event {
	int type;
	union {
		struct {
			dtrace_id_t probeid;
		} p_toggle;
	} args;
};


int vtdtr_enqueue(struct vtdtr_event *);

#endif
