# $FreeBSD: head/release/doc/de_DE.ISO8859-1/hardware/ia64/Makefile 241096 2012-10-01 11:26:49Z gabor $
# $FreeBSDde: de-docproj/relnotes/de_DE.ISO8859-1/hardware/ia64/Makefile,v 1.2 2002/03/10 18:41:37 ue Exp $
# $Id$
# basiert auf: 1.2

RELN_ROOT?= ${.CURDIR}/../../..

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=	-V %generate-article-toc%

# SGML content
SRCS+=	article.xml 
# SRCS+=	proc-ia64.xml 
SRCS+=	../common/hw.ent
SRCS+=	../common/artheader.xml
SRCS+=	../common/dev.xml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
