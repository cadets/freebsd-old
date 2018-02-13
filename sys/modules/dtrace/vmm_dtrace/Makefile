.include <src.opts.mk>

SYSDIR?= ${SRCTOP}/sys

.PATH: ${SYSDIR}/cddl/dev/vmm_dtrace

KMOD= vmm_dtrace
SRCS= vmm_dtrace.c


CFLAGS+=	-I${SYSDIR}/cddl/dev/vmm_dtrace \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

EXPORT_SYMS=	vmmdt_ptr vmmdt_free 

.include <bsd.kmod.mk>

