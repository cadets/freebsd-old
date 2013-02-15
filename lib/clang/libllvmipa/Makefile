# $FreeBSD: head/lib/clang/libllvmipa/Makefile 231057 2012-02-05 23:56:22Z dim $

.include <bsd.own.mk>

LIB=	llvmipa

SRCDIR=	lib/Analysis/IPA
SRCS=	CallGraph.cpp \
	CallGraphSCCPass.cpp \
	FindUsedTypes.cpp \
	GlobalsModRef.cpp

.if ${MK_CLANG_EXTRAS} != "no"
SRCS+=	IPA.cpp
.endif

TGHDRS=	Intrinsics

.include "../clang.lib.mk"
