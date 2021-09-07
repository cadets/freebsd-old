#ifndef __HYPERTRACE_H_
#define __HYPERTRACE_H_

/*
 * HyperTrace defines
 */
#define	HYPERTRACE_MAX_VMS	1024
#define	HYPERTRACE_HOSTID	0

/*
 * Public interfaces to HyperTrace
 */ 
int hypertrace_create_probes(void *, size_t);
int hypertrace_rmprobe(uint16_t, int);


#endif // __HYPERTRACE_H_
