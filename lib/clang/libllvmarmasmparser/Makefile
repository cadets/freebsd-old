# $FreeBSD: head/lib/clang/libllvmarmasmparser/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvmarmasmparser

SRCDIR=	lib/Target/ARM/AsmParser
INCDIR=	lib/Target/ARM
SRCS=	ARMAsmLexer.cpp \
	ARMAsmParser.cpp

TGHDRS=	ARMGenAsmMatcher \
	ARMGenInstrInfo \
	ARMGenRegisterInfo \
	ARMGenSubtargetInfo

.include "../clang.lib.mk"
