#ifndef _SYS_VTDTR_H_
#define _SYS_VTDTR_H_

#define VTDTR_EV_INSTALL   0x00
#define VTDTR_EV_UNINSTALL 0x01

struct vtdtr_conf {
	size_t max_size;
	size_t event_flags;
};

#define VTDTRIOC_CONF 0x00


#endif
