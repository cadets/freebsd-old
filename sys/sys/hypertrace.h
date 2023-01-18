#ifndef __HYPERTRACE_H_
#define __HYPERTRACE_H_

#include <sys/types.h>
#include <sys/proc.h>

/*
 * HyperTrace defines
 */
#define	HYPERTRACE_MAX_VMS      1024
#define	HYPERTRACE_HOSTID       0
#define	HYPERTRACE_ARGS_MAX     10

/*
 * XXX: This should be defined to dtrace_id_t, but because of annoying linking
 * issues, we have to do it this way. It should be fixed, but for now we just
 * have to manually keep dtrace_id_t and hypertrace_id_t in sync.
 */
typedef int hypertrace_id_t;

/*
 * The arguments that we pass in from the guest to host to implement builtin
 * variables. (v) denotes that we have to validate the argument before we send
 * it off to DTrace. (h) denotes variables that can be set by the hypervisor
 * rather than the guest. However, for simplicity's sake they are all set in the
 * guest currently.
 */
typedef struct hypertrace_args {
	uintptr_t htr_args[HYPERTRACE_ARGS_MAX]; /* guest probe args */
	void *htr_curthread;                     /* guest thread */
	char *htr_execname;                      /* (v) guest execname */
	char *htr_execargs;                      /* (v) guest execargs */
	lwpid_t htr_tid;                         /* guest tid */
	pid_t htr_pid;                           /* guest pid */
	pid_t htr_ppid;                          /* guest ppid */
	uid_t htr_uid;                           /* guest uid */
	gid_t htr_gid;                           /* guest gid */
	int htr_errno;                           /* guest errno */
	u_int htr_curcpu;                        /* (h) guest curcpu */
	u_int htr_execargs_len;                  /* (v) guest execargs */
	char *htr_jailname;                      /* (v) guest jailname */
	int htr_jid;                             /* guest jid */
	char *htr_immstack;                      /* guest immstack */
	int htr_immstacksize;                    /* guest immstack size */
} hypertrace_args_t;

/*
 * Handles that depend on hypertrace.ko being loaded. This would normally not be
 * needed, but the weird interfaces between CDDL and BSD code in the kernel make
 * it necessary for anything to work. Maybe there is a better way, but this will
 * do for now. This acts as a public interface to HyperTrace for both FreeBSD
 * and DTrace.
 */
extern void       hypertrace_probe(const void *, hypertrace_id_t, hypertrace_args_t *);
extern lwpid_t    (*hypertrace_gettid)(const void *);
extern uint16_t   (*hypertrace_getns)(const void *);
extern const char *(*hypertrace_getname)(const void *);
extern int        (*hypertrace_create_probes)(uint16_t, void *, size_t);
extern int        (*hypertrace_rmprobe)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_is_enabled)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_enable)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_disable)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_suspend)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_resume)(uint16_t, hypertrace_id_t);


#endif // __HYPERTRACE_H_
