# The FreeBSD Simplified Chinese Project
#
# Original Revision: 166821
# $FreeBSD: head/release/doc/zh_CN.GB2312/hardware/Makefile 250805 2013-05-19 05:49:21Z hrs $

RELN_ROOT?= ${.CURDIR}/../..

.ifdef NO_LANGCODE_IN_DESTDIR
DESTDIR?=	${DOCDIR}/hardware
.else
DESTDIR?=	${DOCDIR}/zh_CN.GB2312/hardware
.endif

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=	-V %generate-article-toc%

# SGML content
SRCS+=	article.xml
SRCS+=	${DEV-AUTODIR}/catalog-auto
SRCS+=	${DEV-AUTODIR}/dev-auto.ent

CATALOGS+=	-c ${DEV-AUTODIR}/catalog-auto

URL_RELPREFIX?=	../../../..

HWNOTES_MI=	1

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
