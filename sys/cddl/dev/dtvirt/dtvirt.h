#ifndef _HYPERTRACE_IMPL_H_
#define _HYPERTRACE_IMPL_H_

#include <sys/types.h>
#include <sys/proc.h>

#define	HYPERTRACE_ARGS_MAX	10

/*
 * The arguments that we pass in from the guest to host to implement builtin
 * variables. (v) denotes that we have to validate the argument before we send
 * it off to DTrace. (h) denotes variables that can be set by the hypervisor
 * rather than the guest. However, for simplicity's sake they are all set in the
 * guest currently.
 */
struct hypertrace_args {
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
};

extern void hypertrace_probe(void *, int, struct hypertrace_args *);
extern lwpid_t (*hypertrace_gettid)(void *);
extern uint16_t (*hypertrace_getns)(void *);
extern const char *(*hypertrace_getname)(void *);

#endif /* _HYPERTRACE_IMPL_H_ */
