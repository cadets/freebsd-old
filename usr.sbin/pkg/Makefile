# $FreeBSD: head/usr.sbin/pkg/Makefile 248133 2013-03-10 17:10:16Z antoine $

PROG=	pkg
SRCS=	pkg.c dns_utils.c config.c

NO_MAN=	yes
DPADD=	${LIBARCHIVE} ${LIBELF} ${LIBFETCH} ${LIBBSDYML} ${LIBSBUF}
LDADD=	-larchive -lelf -lfetch -lbsdyml -lsbuf

.include <bsd.prog.mk>
