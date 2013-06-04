# $FreeBSD$

LIB=		tesla
#MAN=		tesla.3

SHLIB_MAJOR=	1
CFLAGS+=	-DHAVE_CONFIG_H -I${.CURDIR}

.PATH: ${.CURDIR}/../../sys/contrib/tesla/include
.PATH: ${.CURDIR}/../../sys/contrib/tesla/libtesla

INCS=		tesla.h libtesla.h
SRCS=		tesla_class.c tesla_class_global.c tesla_class_perthread.c \
		tesla_debug.c tesla_dtrace.c tesla_key.c tesla_notification.c \
		tesla_store.c tesla_update.c tesla_util.c

.include <bsd.lib.mk>
