#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/dtrace.h>
#include <machine/vmm.h>

#include "dtvirt.h"

static MALLOC_DEFINE(M_DTVIRT, "dtvirt", "");
static void * dtvirt_priv_ptr(void *, uintptr_t, size_t);
static void dtvirt_priv_bcopy(void *, void *, void *, size_t);
static void dtvirt_priv_free(void *, size_t);

void * (*vmm_copyin)(void *biscuit,
    void *addr, size_t len, struct malloc_type *t);
void (*vmm_bcopy)(void *biscuit,
    void *src, void *dst, size_t len);

void
dtvirt_probe(void *biscuit, int probeid, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{

	dtrace_ns_probe(biscuit, probeid,
	    arg0, arg1, arg2, arg3, arg4);
}

static int
dtvirt_handler(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		dtvirt_ptr = dtvirt_priv_ptr;
		dtvirt_free = dtvirt_priv_free;
		dtvirt_bcopy = dtvirt_priv_bcopy;
		break;
	case MOD_UNLOAD:
		dtvirt_ptr = NULL;
		dtvirt_free = NULL;
		dtvirt_bcopy = NULL;
		break;
	default:
		break;
	}
	return (0);
}

static void *
dtvirt_priv_ptr(void *biscuit, uintptr_t addr, size_t size)
{

	if (vmm_copyin != NULL)
		return (vmm_copyin(biscuit, (void *)addr, size, M_DTVIRT));
	return (NULL);
}

static void
dtvirt_priv_bcopy(void *biscuit, void *src, void *dst, size_t size)
{

	if (vmm_bcopy != NULL)
		vmm_bcopy(biscuit, src, dst, size);
}

static void
dtvirt_priv_free(void *addr, size_t size)
{

	free(addr, M_DTVIRT);
}

static moduledata_t dtvirt_kmod = {
	"dtvirt",
	dtvirt_handler,
	NULL
};

DECLARE_MODULE(dtvirt, dtvirt_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(dtvirt, 1);
MODULE_DEPEND(dtvirt, dtrace, 1, 1, 1);
