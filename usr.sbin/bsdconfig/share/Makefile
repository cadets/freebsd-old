# $FreeBSD: head/usr.sbin/bsdconfig/share/Makefile 250323 2013-05-07 05:40:20Z dteske $

NO_OBJ=

SUBDIR=	media packages

FILESDIR=	${SHAREDIR}/bsdconfig
FILES=		common.subr device.subr dialog.subr mustberoot.subr \
		script.subr strings.subr struct.subr sysrc.subr variable.subr

beforeinstall:
	mkdir -p ${DESTDIR}${FILESDIR}

.include <bsd.prog.mk>
