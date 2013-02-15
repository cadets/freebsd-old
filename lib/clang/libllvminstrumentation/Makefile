# $FreeBSD: head/lib/clang/libllvminstrumentation/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvminstrumentation

SRCDIR=	lib/Transforms/Instrumentation
SRCS=	AddressSanitizer.cpp \
	BlackList.cpp \
	BoundsChecking.cpp \
	EdgeProfiling.cpp \
	GCOVProfiling.cpp \
	Instrumentation.cpp \
	OptimalEdgeProfiling.cpp \
	PathProfiling.cpp \
	ProfilingUtils.cpp \
	ThreadSanitizer.cpp

TGHDRS=	Intrinsics

.include "../clang.lib.mk"
