# $FreeBSD: head/lib/clang/libclangparse/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	clangparse

SRCDIR=	tools/clang/lib/Parse
SRCS=	ParseAST.cpp \
	ParseCXXInlineMethods.cpp \
	ParseDecl.cpp \
	ParseDeclCXX.cpp \
	ParseExpr.cpp \
	ParseExprCXX.cpp \
	ParseInit.cpp \
	ParseObjc.cpp \
	ParsePragma.cpp \
	ParseStmt.cpp \
	ParseTemplate.cpp \
	ParseTentative.cpp \
	Parser.cpp

TGHDRS=	AttrLateParsed \
	AttrList \
	AttrParsedAttrList \
	Attrs \
	CommentNodes \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticParseKinds \
	DiagnosticSemaKinds \
	StmtNodes

.include "../clang.lib.mk"
