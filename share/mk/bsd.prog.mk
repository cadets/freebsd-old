#	from: @(#)bsd.prog.mk	5.26 (Berkeley) 6/25/91
# $FreeBSD$

.include <bsd.init.mk>

.SUFFIXES: .out .o .c .cc .cpp .cxx .C .m .y .l .ln .s .S .asm

# XXX The use of COPTS in modern makefiles is discouraged.
.if defined(COPTS)
CFLAGS+=${COPTS}
.endif

.if ${MK_ASSERT_DEBUG} == "no"
CFLAGS+= -DNDEBUG
NO_WERROR=
.endif

.if defined(DEBUG_FLAGS)
CFLAGS+=${DEBUG_FLAGS}
CXXFLAGS+=${DEBUG_FLAGS}

.if ${MK_CTF} != "no" && ${DEBUG_FLAGS:M-g} != ""
CTFFLAGS+= -g
.endif
.endif

.if defined(CRUNCH_CFLAGS)
CFLAGS+=${CRUNCH_CFLAGS}
.endif

.if !defined(DEBUG_FLAGS)
STRIP?=	-s
.endif

.if defined(NO_SHARED) && (${NO_SHARED} != "no" && ${NO_SHARED} != "NO")
LDFLAGS+= -static
.endif

.if defined(PROG_CXX)
PROG=	${PROG_CXX}
.endif

.if defined(PROG)
PROGNAME?=	${PROG}

.if !defined(SRCS) && !target(${PROG})
.if defined(PROG_CXX)
SRCS=	${PROG}.cc
.else
SRCS=	${PROG}.c
.endif
.endif

.if defined(SRCS) && !empty(SRCS)
OBJS+=  ${SRCS:N*.h:R:S/$/.o/g}

.if target(beforelinking)
beforelinking: ${OBJS}
${PROG}: beforelinking
.endif
${PROG}: ${OBJS}
.if defined(PROG_CXX)
	${CXX} ${CXXFLAGS} ${LDFLAGS} -o ${.TARGET} ${OBJS} ${LDADD}
.else
	${CC} ${CFLAGS} ${LDFLAGS} -o ${.TARGET} ${OBJS} ${LDADD}
.endif
.if ${MK_CTF} != "no"
	${CTFMERGE} ${CTFFLAGS} -o ${.TARGET} ${OBJS}
.endif
.endif

# XXX: forced assignment due to make not figuring out how to make things
# from generated .c files (which are added to SRCS later).
CSRC_OBJS:=	${SRCS:M*.c:R:S/$/.object/:N.object}
CXXSRC_OBJS:=	${SRCS:M*.cc:R:S/$/.object/:N.object} \
		${SRCS:M*.cpp:R:S/$/.object/:N.object} \
		${SRCS:M*.cxx:R:S/$/.object/:N.object} \
		${SRCS:M*.C:R:S/$/.object/:N.object}
SRC_OBJS=	${CSRC_OBJS} ${CXX_OBJS}

TESLA_FILES=	${CSRC_OBJS:.object=.tesla}
OLLS=		${CSRC_OBJS:.object=.oll}
INSTRLLS=	${CSRC_OBJS:.object=.instrll}
INSTROBJS=	${CSRC_OBJS:.object=.instro}
CLEANFILES+=	${TESLA_FILES} tesla.manifest ${OLLS} ${INSTRLLS} ${INSTROBJS} \
		${PROG}.instrumented

tesla.manifest: ${TESLA_FILES}
	cat ${TESLA_FILES} > ${.TARGET}

tesla: ${PROG}.instrumented

${PROG}.instrumented: ${INSTROBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o ${.TARGET} ${INSTROBJS} ${LDADD} -ltesla

.if defined(LLVM_IR) && !defined(NO_LLVM_IR)
LOBJS:=		${SRC_OBJS:.object=.obc}
CLEANFILES+=	${PROG}.bc ${LOBJS}

.if !empty(LOBJS)
all: ${PROG}.bc
${PROG}.bc: ${LOBJS}
	${LLVM_LINK} -o ${.TARGET} ${LOBJS}

all: ${PROG}.bc-opt
${PROG}.bc-opt: ${PROG}.bc
.if empty(OPT_PASSES)
	cp ${PROG}.bc ${.TARGET}
.else
	${OPT} -o ${.TARGET} ${OPT_PASSES} ${PROG}.bc
.endif
.endif
.endif

.if	${MK_MAN} != "no" && !defined(MAN) && \
	!defined(MAN1) && !defined(MAN2) && !defined(MAN3) && \
	!defined(MAN4) && !defined(MAN5) && !defined(MAN6) && \
	!defined(MAN7) && !defined(MAN8) && !defined(MAN9)
MAN=	${PROG}.1
MAN1=	${MAN}
.endif
.endif # defined(PROG)

all: objwarn ${PROG} ${SCRIPTS}
.if ${MK_MAN} != "no"
all: _manpages
.endif

.if defined(PROG)
CLEANFILES+= ${PROG}
.endif

.if defined(OBJS)
CLEANFILES+= ${OBJS}
.endif

.include <bsd.libnames.mk>

.if defined(PROG)
_EXTRADEPEND:
.if defined(LDFLAGS) && !empty(LDFLAGS:M-nostdlib)
.if defined(DPADD) && !empty(DPADD)
	echo ${PROG}: ${DPADD} >> ${DEPENDFILE}
.endif
.else
	echo ${PROG}: ${LIBC} ${DPADD} >> ${DEPENDFILE}
.if defined(PROG_CXX)
.if !empty(CXXFLAGS:M-stdlib=libc++)
	echo ${PROG}: ${LIBCPLUSPLUS} >> ${DEPENDFILE}
.else
	echo ${PROG}: ${LIBSTDCPLUSPLUS} >> ${DEPENDFILE}
.endif
.endif
.endif
.endif

.if !target(install)

.if defined(PRECIOUSPROG)
.if !defined(NO_FSCHG)
INSTALLFLAGS+= -fschg
.endif
INSTALLFLAGS+= -S
.endif

_INSTALLFLAGS:=	${INSTALLFLAGS}
.for ie in ${INSTALLFLAGS_EDIT}
_INSTALLFLAGS:=	${_INSTALLFLAGS${ie}}
.endfor

.if !target(realinstall) && !defined(INTERNALPROG)
realinstall: _proginstall
.ORDER: beforeinstall _proginstall
_proginstall:
.if defined(PROG)
	${INSTALL} ${STRIP} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
	    ${_INSTALLFLAGS} ${PROG} ${DESTDIR}${BINDIR}/${PROGNAME}
.endif
.endif	# !target(realinstall)

.if defined(SCRIPTS) && !empty(SCRIPTS)
realinstall: _scriptsinstall
.ORDER: beforeinstall _scriptsinstall

SCRIPTSDIR?=	${BINDIR}
SCRIPTSOWN?=	${BINOWN}
SCRIPTSGRP?=	${BINGRP}
SCRIPTSMODE?=	${BINMODE}

.for script in ${SCRIPTS}
.if defined(SCRIPTSNAME)
SCRIPTSNAME_${script:T}?=	${SCRIPTSNAME}
.else
SCRIPTSNAME_${script:T}?=	${script:T:R}
.endif
SCRIPTSDIR_${script:T}?=	${SCRIPTSDIR}
SCRIPTSOWN_${script:T}?=	${SCRIPTSOWN}
SCRIPTSGRP_${script:T}?=	${SCRIPTSGRP}
SCRIPTSMODE_${script:T}?=	${SCRIPTSMODE}
_scriptsinstall: _SCRIPTSINS_${script:T}
_SCRIPTSINS_${script:T}: ${script}
	${INSTALL} -o ${SCRIPTSOWN_${.ALLSRC:T}} \
	    -g ${SCRIPTSGRP_${.ALLSRC:T}} -m ${SCRIPTSMODE_${.ALLSRC:T}} \
	    ${.ALLSRC} \
	    ${DESTDIR}${SCRIPTSDIR_${.ALLSRC:T}}/${SCRIPTSNAME_${.ALLSRC:T}}
.endfor
.endif

NLSNAME?=	${PROG}
.include <bsd.nls.mk>

.include <bsd.files.mk>
.include <bsd.incs.mk>
.include <bsd.links.mk>

.if ${MK_MAN} != "no"
realinstall: _maninstall
.ORDER: beforeinstall _maninstall
.endif

.endif

.if !target(lint)
lint: ${SRCS:M*.c}
.if defined(PROG)
	${LINT} ${LINTFLAGS} ${CFLAGS:M-[DIU]*} ${.ALLSRC}
.endif
.endif

.if ${MK_MAN} != "no"
.include <bsd.man.mk>
.endif

.include <bsd.dep.mk>

.if defined(PROG) && !exists(${.OBJDIR}/${DEPENDFILE})
${OBJS}: ${SRCS:M*.h}
.endif

.include <bsd.obj.mk>

.include <bsd.sys.mk>

.if defined(PORTNAME)
.include <bsd.pkg.mk>
.endif
