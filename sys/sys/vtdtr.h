#ifndef _SYS_VTDTR_H_
#define _SYS_VTDTR_H_

//#include <sys/dtrace.h>

#define VTDTR_MAXVMS       16
#define VTDTR_VMNAMEMAX    256

#define VTDTR_EV_INSTALL   0x01
#define VTDTR_EV_UNINSTALL 0x02
#define VTDTR_EV_GO        0x03
#define VTDTR_EV_STOP      0x04
#define VTDTR_EV_RECONF    0x05

/*
 * We only have one event at the moment -- possibly others in the future.
 */
struct vtdtr_event {
	size_t type;

	union {
		struct {
			int probeid;
		} p_toggle;

		struct {
			char vms[VTDTR_MAXVMS][VTDTR_VMNAMEMAX];
			size_t count;
		} d_config;
	} args;
};



struct vtdtr_conf {
	sbintime_t timeout;
	size_t max_size;
	size_t event_flags;
};

#define VTDTRIOC_CONF _IOW('v',1,struct vtdtr_conf)

#endif
