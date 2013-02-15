# $FreeBSD: head/lib/clang/libllvmarmdesc/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvmarmdesc

SRCDIR=	lib/Target/ARM/MCTargetDesc
SRCS=	ARMAsmBackend.cpp \
	ARMELFObjectWriter.cpp \
	ARMMachObjectWriter.cpp \
	ARMMCAsmInfo.cpp \
	ARMMCCodeEmitter.cpp \
	ARMMCExpr.cpp \
	ARMMCTargetDesc.cpp
CFLAGS+= -I${LLVM_SRCS}/${SRCDIR}/..

TGHDRS=	ARMGenInstrInfo \
	ARMGenMCCodeEmitter \
	ARMGenRegisterInfo \
	ARMGenSubtargetInfo

.include "../clang.lib.mk"
