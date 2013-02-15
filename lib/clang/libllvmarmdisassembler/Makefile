# $FreeBSD: head/lib/clang/libllvmarmdisassembler/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvmarmdisassembler

SRCDIR=	lib/Target/ARM/Disassembler
INCDIR=	lib/Target/ARM
SRCS=	ARMDisassembler.cpp

TGHDRS=	ARMGenDisassemblerTables \
	ARMGenEDInfo \
	ARMGenInstrInfo \
	ARMGenRegisterInfo \
	ARMGenSubtargetInfo

.include "../clang.lib.mk"
