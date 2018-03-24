#ifndef _DTVIRT_H_
#define _DTVIRT_H_

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
	uintptr_t	args[DTVIRT_ARGS_MAX];	/* guest probe args */
	void		*curthread;		/* guest thread */
	char		*execname;		/* (v) guest execname */
	char		*execargs;		/* (v) guest execargs */
	lwpid_t		tid;			/* guest tid */
	pid_t		pid;			/* guest pid */
	pid_t		ppid;			/* guest ppid */
	uid_t		uid;			/* guest uid */
	gid_t		gid;			/* guest gid */
	errno_t		errno;			/* guest errno */
	u_int		execname_len;		/* (v) length of execname */
	u_int		execargs_len;		/* (v) length of execargs */
	u_int		curcpu;			/* (h) guest curcpu */
};

extern void dtvirt_probe(void *, int, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern void * (*dtvirt_ptr)(void *, uintptr_t, size_t);
extern void (*dtvirt_bcopy)(void *, void *, void *, size_t);
extern void (*dtvirt_free)(void *, size_t);
extern lwpid_t (*dtvirt_gettid)(void *);
extern uint16_t (*dtvirt_getns)(void *);

#endif
