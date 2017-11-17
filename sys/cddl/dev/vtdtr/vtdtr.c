#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/disk.h>
#include <sys/bus.h>
#include <sys/filio.h>
#include <sys/dtrace.h>

#include <machine/bus.h>
#include <machine/vmparam.h>

#include "vtdtr.h"

/*
 * For now, only an abstraction. However, we could make use of this to have
 * multiple queues per process to only deal with certain types of events (i.e.
 * we are only interested in probe installs/uninstalls, ...). Can easily turn
 * this into statistics.
 */
struct vtdtr_queue {
	struct mtx                 mtx;
	STAILQ_HEAD(, vtdtr_event) head;
	size_t                     max_size;
	size_t                     num_entries;
};

static int vtdtr_read(struct cdev *, struct uio *, int);
static int vtdtr_ioctl(struct cdev *, u_long, caddr_t, int, struct thread *);
static int vtdtr_modevent(module_t, int, void *);

static struct vtdtr_queue *queue;

static struct cdev *vtdtr_dev;
static d_ioctl_t    vtdtr_ioctl;
static d_read_t     vtdtr_read;

static struct cdevsw vtdtr_cdevsw = {
	.d_version = D_VERSION,
	.d_read    = vtdtr_read,
	.d_write   = NULL,
	.d_ioctl  = vtdtr_ioctl,
	.d_name   = "vtdtr"
};

/*
 * TODO: We currently don't support any configuration, but it might be useful at
 * some point?
 */
static int
vtdtr_read(struct cdev *dev __unused, struct uio *uio, int flags __unused)
{
	return (0);
}

static int
vtdtr_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int flags __unused, struct thread *td)
{
	return (0);
}

static int
vtdtr_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch(type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("vtdtr: <vtdtr device>\n");
		vtdtr_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD, &vtdtr_cdevsw, 0,
		    NULL, UID_ROOT, GID_WHEEL, 0440, "vtdtr");
		break;
	case MOD_UNLOAD:
		destroy_dev(vtdtr_dev);
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		return (EOPNOTSUPP);
	};

	return (0);
}

DEV_MODULE(vtdtr, vtdtr_modevent, NULL);
MODULE_VERSION(vtdtr, 1);
