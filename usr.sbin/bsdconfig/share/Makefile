# $FreeBSD: head/usr.sbin/bsdconfig/share/Makefile 245052 2013-01-05 02:08:47Z dteske $

NO_OBJ=

FILESDIR=	${SHAREDIR}/bsdconfig
FILES=		common.subr dialog.subr mustberoot.subr script.subr \
		strings.subr sysrc.subr variable.subr

beforeinstall:
	mkdir -p ${DESTDIR}${FILESDIR}

.include <bsd.prog.mk>
