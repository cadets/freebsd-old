# $Id$
# $FreeBSD: head/sys/modules/netgraph/bluetooth/bt3c/Makefile 155824 2006-02-18 23:49:28Z yar $

.PATH: ${.CURDIR}/../../../../netgraph/bluetooth/drivers/bt3c

CFLAGS+=	-I${.CURDIR}/../../../../netgraph/bluetooth/include \
		-I${.CURDIR}/../../../../netgraph/bluetooth/drivers/bt3c

KMOD=		ng_bt3c
SRCS=		ng_bt3c_pccard.c bus_if.h card_if.h device_if.h pccarddevs.h

.include <bsd.kmod.mk>
