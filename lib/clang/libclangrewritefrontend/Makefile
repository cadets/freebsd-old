# $FreeBSD: head/lib/clang/libclangrewritefrontend/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	clangrewritefrontend

SRCDIR=	tools/clang/lib/Rewrite/Frontend
SRCS=	FixItRewriter.cpp \
	FrontendActions.cpp \
	HTMLPrint.cpp \
	InclusionRewriter.cpp \
	RewriteMacros.cpp \
	RewriteModernObjC.cpp \
	RewriteObjC.cpp \
	RewriteTest.cpp

TGHDRS=	AttrList \
	AttrParsedAttrList \
	Attrs \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticFrontendKinds \
	StmtNodes

.include "../clang.lib.mk"
