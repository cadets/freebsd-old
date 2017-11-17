#ifndef _VTDTR_H_
#define _VTDTR_H_

struct uuid;

extern void (*vtdtr_notify_load)(void);
extern void (*vtdtr_advertise_prov)(void *, const char *, struct uuid *);
extern void (*vtdtr_destroy_prov)(void *, struct uuid *);
extern void (*vtdtr_advertise_probe)(void *, const char *,
    const char *, const char *, struct uuid *);

#endif
