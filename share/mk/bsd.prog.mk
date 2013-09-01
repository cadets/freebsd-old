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
# XXX: currently tesla can't handle C++ so build C++ code normaly in the
# WITH_TESLA case.
.if defined(EARLY_BUILD) || defined(NO_LLVM_IR) || \
    ${MK_LLVM_INSTRUMENTED} == "no" || \
    (${MK_TESLA} != "no" && defined(PROG_CXX))
OBJS+=  ${SRCS:N*.h:R:S/$/.o/g}
.else
# XXX: should blow up if other SRCS types are found
OBJS+=		${SRCS:M*.bin:R:S/$/.o/g:N.o} ${SRCS:M*.[Ss]:R:S/$/.o/g:N.o}
LLVM_CFILES=	${SRCS:M*.c} \
		${SRCS:M*.cc} ${SRCS:M*.cpp} ${SRCS:M*.cxx} ${SRCS:M*.C} \
		${SRCS:M*.l:R:S/$/.c/:N.c} ${SRCS:M*.y:R:S/$/.c/:N.c}
OIRS=		${LLVM_CFILES:R:S/$/.o${LLVM_IR_TYPE}/}
INSTR_IRS=	${LLVM_CFILES:R:S/$/.instr${LLVM_IR_TYPE}/}
INSTR_OBJS=	${LLVM_CFILES:R:S/$/.instro/}
OBJS+=		${INSTR_OBJS}
CLEANFILES+=	${OIRS} ${INSTR_IRS} ${INSTR_OBJS} ${PROG}.${LLVM_IR_TYPE}-a
.if ${MK_TESLA} != "no"
TESLA_FILES=	${LLVM_CFILES:R:S/$/.tesla/}
CLEANFILES+=	${TESLA_FILES} tesla.manifest
.endif
.endif

.if target(beforelinking)
beforelinking: ${OBJS}
${PROG}: beforelinking
.endif

${PROG}.${LLVM_IR_TYPE}-a: ${OIRS}
	if [ -z "${OIRS}" ]; then \
		touch ${.TARGET} ;\
	else \
		${LLVM_LINK} -o ${.TARGET} ${OIRS} ;\
	fi

${PROG}.soaap: ${PROG}.${LLVM_IR_TYPE}-a
	${OPT} -load $(SOAAP_BUILD_DIR)/libsoaap.so -soaap ${SOAAP_FLAGS} -o /dev/null ${PROG}.${LLVM_IR_TYPE}-a

${PROG}.soaap_cg: ${PROG}.${LLVM_IR_TYPE}-a
	${OPT} -load $(SOAAP_BUILD_DIR)/libcep.so -insert-call-edge-profiling -o ${PROG}.pbc ${PROG}.${LLVM_IR_TYPE}-a
	${LLC} -filetype=obj -o ${PROG}.po ${PROG}.pbc 
	${CC} -L $(SOAAP_BUILD_DIR) -L $(LLVM_BUILD_DIR)/lib -lcep_rt -lprofile_rt $(LDADD) -o ${.TARGET} ${PROG}.po

${PROG}.soaap_perf: ${PROG}.${LLVM_IR_TYPE}-a
	${OPT} -load $(SOAAP_BUILD_DIR)/libsoaap.so -soaap -soaap-emulate-performance ${SOAAP_FLAGS} -o ${PROG}.pbc ${PROG}.${LLVM_IR_TYPE}-a
	${LLC} -filetype=obj -o ${PROG}.po ${PROG}.pbc 
	${CC} $(LDADD) -o ${.TARGET} ${PROG}.po

CLEANFILES+= ${PROG}.po ${PROG}.pbc ${PROG}.soaap_perf ${PROG}.soaap_cg

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

.if ${MK_TESLA} != "no" && !defined(EARLY_BUILD)
tesla.manifest: ${TESLA_FILES}
	cat ${TESLA_FILES} > ${.TARGET}

DPADD+=	${LIBTESLA}
LDADD+= -ltesla
.else
tesla.manifest:
	touch ${.TARGET}
.endif

.if	${MK_MAN} != "no" && !defined(MAN) && \
	!defined(MAN1) && !defined(MAN2) && !defined(MAN3) && \
	!defined(MAN4) && !defined(MAN5) && !defined(MAN6) && \
	!defined(MAN7) && !defined(MAN8) && !defined(MAN9)
MAN=	${PROG}.1
MAN1=	${MAN}
.endif
.endif # defined(PROG)

.if defined(WITH_LLVM_INSTRUMENTED)
all: objwarn ${PROG} ${PROG}.${LLVM_IR_TYPE}-a ${SCRIPTS}
.else
all: objwarn ${PROG} ${SCRIPTS}
.endif
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
