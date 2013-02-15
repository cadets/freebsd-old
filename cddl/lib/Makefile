# $FreeBSD: head/cddl/lib/Makefile 242723 2012-11-07 23:45:09Z jhibbits $

.include <bsd.own.mk>

SUBDIR=	${_drti} \
	libavl \
	libctf \
	${_libdtrace} \
	libnvpair \
	libumem \
	libuutil \
	${_libzfs} \
	${_libzpool}

.if ${MK_ZFS} != "no"
_libzfs=	libzfs
.if ${MK_LIBTHR} != "no"
_libzpool=	libzpool
.endif
.endif

.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386" || \
	${MACHINE_CPUARCH} == "mips" || ${MACHINE_CPUARCH} == "powerpc"
_drti=		drti
_libdtrace=	libdtrace
.endif

.include <bsd.subdir.mk>
