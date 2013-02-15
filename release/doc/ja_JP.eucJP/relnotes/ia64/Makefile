# $FreeBSD: head/release/doc/ja_JP.eucJP/relnotes/ia64/Makefile 241096 2012-10-01 11:26:49Z gabor $
# Original revision: 1.1

RELN_ROOT?= ${.CURDIR}/../../..

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=	-V %generate-article-toc%

# SGML content
SRCS+=	article.xml
SRCS+=	../common/relnotes.ent
SRCS+=	../common/new.xml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
