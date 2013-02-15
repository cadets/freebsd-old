# $FreeBSD: head/lib/clang/libclangserialization/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	clangserialization

SRCDIR=	tools/clang/lib/Serialization
SRCS=	ASTCommon.cpp \
	ASTReader.cpp \
	ASTReaderDecl.cpp \
	ASTReaderStmt.cpp \
	ASTWriter.cpp \
	ASTWriterDecl.cpp \
	ASTWriterStmt.cpp \
	GeneratePCH.cpp \
	Module.cpp \
	ModuleManager.cpp

TGHDRS=	AttrList \
	AttrPCHRead \
	AttrPCHWrite \
	AttrParsedAttrList \
	Attrs \
	CommentNodes \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticFrontendKinds \
	DiagnosticSemaKinds \
	DiagnosticSerializationKinds \
	StmtNodes

.include "../clang.lib.mk"
