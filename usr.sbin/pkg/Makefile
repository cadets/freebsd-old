# $FreeBSD: head/usr.sbin/pkg/Makefile 243883 2012-12-05 11:35:50Z bapt $

PROG=	pkg
SRCS=	pkg.c dns_utils.c

NO_MAN=	yes
DPADD=	${LIBARCHIVE} ${LIBELF} ${LIBFETCH}
LDADD=	-larchive -lelf -lfetch

.include <bsd.prog.mk>
