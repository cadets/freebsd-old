# $Id$
# $FreeBSD: head/sys/modules/dcons_crom/Makefile 136468 2004-10-13 05:41:09Z simokawa $

.PATH:	${.CURDIR}/../../dev/dcons

KMOD	= dcons_crom
SRCS	= dcons_crom.c dcons.h dcons_os.h \
		bus_if.h device_if.h

#KMODDEPS = firewire dcons

CFLAGS+= -I${.CURDIR}/../..

.include <bsd.kmod.mk>
