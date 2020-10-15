#include <dt_resolver.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>

#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>

#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#define	DT_RESOLVER_HOSTNAME(f) ((f) & 1)
#define	DT_RESOLVER_VERSION(f)  (((f) >> 1) & 1)

static uint32_t resolve_flags;

/*
 * This subroutine checks whether or not the current target machine matches
 * the "target" description, whatever it may be based on the flags passed in.
 */
int
dt_resolve(const char *target, uint32_t flags)
{
	char curtarget[
	    MAX(MAXHOSTNAMELEN, OSRELEASELEN) + sizeof("FreeBSD-")] = {0};
	size_t len = MAX(MAXHOSTNAMELEN, OSRELEASELEN) + sizeof("FreeBSD-");

	/*
	 * If there is no target, we just assume that it's for all targets.
	 */
	if (strlen(target) == 0)
		return (0);

	/*
	 * If flags are 0, we assume default configuration
	 */
	if (flags == 0)
		flags = resolve_flags;
	
	if (DT_RESOLVER_HOSTNAME(flags) != 0) {
		if (gethostname(curtarget, MAXHOSTNAMELEN) != 0)
			errx(EXIT_FAILURE, "failed to get hostname");

		if (strcmp(target, curtarget) == 0)
			return (0);
	}

	if (DT_RESOLVER_VERSION(flags) != 0) {
		strcpy(curtarget, "FreeBSD-");
		if (sysctlbyname("kern.osrelease",
		    curtarget + strlen("FreeBSD-"), &len, NULL, 0) != 0)
			errx(EXIT_FAILURE, "failed getting the OS release %s",
			    strerror(errno));

		if (strcmp(target, curtarget) == 0)
			return (0);
	}

	return (-1);
}

void
dt_resolver_setflags(uint32_t flags)
{

	resolve_flags = flags;
}
