#ifndef _DTVIRT_H_
#define _DTVIRT_H_

#include <sys/types.h>
#include <sys/proc.h>

#define	DTVIRT_ARGS_MAX	10

/*
 * The arguments that we pass in from the guest to host to implement builtin
 * variables. (v) denotes that we have to validate the argument before we send
 * it off to DTrace. (h) denotes variables that can be set by the hypervisor
 * rather than the guest. However, for simplicity's sake they are all set in the
 * guest currently.
 *
 * XXX(dstolfa): EXECNAME and EXECARGS are currently guest-controlled in terms
 * of what the length is. This requires verification code on the interface and
 * is probably not something that we should try exercise. Would it make sense to
 * make this static to avoid any kind of validation necessary and forcefully
 * NULL-terminate a string?
 */
struct dtvirt_args {
	uintptr_t dtv_args[DTVIRT_ARGS_MAX];	/* guest probe args */
	void *dtv_curthread;			/* guest thread */
	char *dtv_execname;			/* (v) guest execname */
	char *dtv_execargs;			/* (v) guest execargs */
	lwpid_t dtv_tid;			/* guest tid */
	pid_t dtv_pid;				/* guest pid */
	pid_t dtv_ppid;				/* guest ppid */
	uid_t dtv_uid;				/* guest uid */
	gid_t dtv_gid;				/* guest gid */
	int dtv_errno;				/* guest errno */
	u_int dtv_curcpu;			/* (h) guest curcpu */
	u_int dtv_execargs_len;			/* (v) guest execargs */
	char *dtv_jailname;			/* (v) guest jailname */
	int dtv_jid;				/* guest jid */
};

extern void dtvirt_probe(void *, int, struct dtvirt_args *);
extern lwpid_t (*dtvirt_gettid)(void *);
extern uint16_t (*dtvirt_getns)(void *);
extern const char *(*dtvirt_getname)(void *);

#endif
