# $FreeBSD: head/lib/clang/libclangbasic/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	clangbasic

SRCDIR=	tools/clang/lib/Basic
SRCS=	Builtins.cpp \
	ConvertUTF.c \
	ConvertUTFWrapper.cpp \
	Diagnostic.cpp \
	DiagnosticIDs.cpp \
	FileManager.cpp \
	FileSystemStatCache.cpp \
	IdentifierTable.cpp \
	LangOptions.cpp \
	Module.cpp \
	ObjCRuntime.cpp \
	SourceLocation.cpp \
	SourceManager.cpp \
	TargetInfo.cpp \
	Targets.cpp \
	TokenKinds.cpp \
	VersionTuple.cpp \
	Version.cpp

TGHDRS=	DiagnosticAnalysisKinds \
	DiagnosticASTKinds \
	DiagnosticCommentKinds \
	DiagnosticCommonKinds \
	DiagnosticDriverKinds \
	DiagnosticFrontendKinds \
	DiagnosticGroups \
	DiagnosticIndexName \
	DiagnosticLexKinds \
	DiagnosticParseKinds \
	DiagnosticSemaKinds \
	DiagnosticSerializationKinds \
	arm_neon

.include "../clang.lib.mk"
