# $FreeBSD: head/lib/clang/libclangstaticanalyzerfrontend/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	clangstaticanalyzerfrontend

SRCDIR=	tools/clang/lib/StaticAnalyzer/Frontend
SRCS=	AnalysisConsumer.cpp \
	CheckerRegistration.cpp \
	FrontendActions.cpp

TGHDRS=	AttrList \
	Attrs \
	Checkers \
	CommentNodes \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticFrontendKinds \
	StmtNodes

.include "../clang.lib.mk"
