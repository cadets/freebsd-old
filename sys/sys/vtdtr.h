#ifndef _SYS_VTDTR_H_
#define _SYS_VTDTR_H_

//#include <sys/dtrace.h>

#define VTDTR_EV_INSTALL   0x01
#define VTDTR_EV_UNINSTALL 0x02

/*
 * We only have one event at the moment -- possibly others in the future.
 */
struct vtdtr_event {
	size_t type;

	union {
		struct {
			int probeid;
		} p_toggle;
	} args;
};



struct vtdtr_conf {
	sbintime_t timeout;
	size_t max_size;
	size_t event_flags;
};

#define VTDTRIOC_CONF _IOR('v',1,struct vtdtr_conf)

#endif
