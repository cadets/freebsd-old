.include <src.opts.mk>

SYSDIR?= ${SRCTOP}/sys

.PATH: ${SYSDIR}/cddl/contrib/opensolaris/uts/common/dtrace
.PATH: ${SYSDIR}/cddl/compat/opensolaris/kern
.PATH: ${SYSDIR}/cddl/kern
.PATH: ${SYSDIR}/cddl/dev/dtvirt

KMOD= dtvirt
SRCS= dtvirt.c vnode_if.h


CFLAGS+=	-I${SYSDIR}/cddl/dev/dtvirt \
		${OPENZFS_CFLAGS}

EXPORT_SYMS=	dtvirt_probe

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h

.include <bsd.kmod.mk>
