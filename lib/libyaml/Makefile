# $FreeBSD: head/lib/libyaml/Makefile 247840 2013-03-05 13:06:40Z bapt $

LIBYAML=	${.CURDIR}/../../contrib/libyaml

LIB=		bsdyml
SHLIB_MAJOR=	0
INCS=		bsdyml.h
SRCS=		api.c dumper.c emitter.c loader.c \
		parser.c reader.c scanner.c writer.c
MAN=		libbsdyml.3

.PATH:		${LIBYAML}/src ${LIBYAML}/include
CLEANFILES=	bsdyml.h

WARNS?=		1
CFLAGS+=	-I${LIBYAML}/include \
		-I${LIBYAML} \
		-I${.CURDIR} \
		-DHAVE_CONFIG_H

bsdyml.h: yaml.h
	cp -f ${.ALLSRC} ${.TARGET}

.include <bsd.lib.mk>
