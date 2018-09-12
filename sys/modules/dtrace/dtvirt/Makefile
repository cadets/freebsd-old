.include <src.opts.mk>

SYSDIR?= ${SRCTOP}/sys

.PATH: ${SYSDIR}/cddl/dev/dtvirt

KMOD= dtvirt
SRCS= dtvirt.c vnode_if.h


CFLAGS+=	-I${SYSDIR}/cddl/dev/dtvirt \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

EXPORT_SYMS=	dtvirt_probe

.include <bsd.kmod.mk>
