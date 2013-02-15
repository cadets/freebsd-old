#
# $FreeBSD: head/sys/modules/cxgbe/Makefile 237263 2012-06-19 07:34:13Z np $
#

SUBDIR = if_cxgbe
SUBDIR+= firmware
SUBDIR+= ${_tom}

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
_tom=		tom
.endif

.include <bsd.subdir.mk>
