#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <machine/vmm.h>

#include "vmm_dtrace.h"

static MALLOC_DEFINE(M_VMMDT, "vmmdt", "vmmdt");

static int
vmmdt_handler(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		break;
	case MOD_UNLOAD:
		break;
	default:
		break;
	}
	return (0);
}

uintptr_t
vmmdt_ptr(void *biscuit, uintptr_t addr, size_t size)
{

	return (vmm_copyin(biscuit, (void *)addr, size, M_VMMDT));
}

void
vmmdt_free(void *addr, size_t size)
{

	free(addr, M_VMMDT);
}

static moduledata_t vmmdt_kmod = {
	"vmm_dtrace",
	vmmdt_handler,
	NULL
};

DECLARE_MODULE(vmm_dtrace, vmmdt_kmod, SI_SUB_SMP + 1, SI_ORDER_ANY);
MODULE_VERSION(vmm_dtrace, 1);
MODULE_DEPEND(vmm_dtrace, vmm, 1, 1, 1);
