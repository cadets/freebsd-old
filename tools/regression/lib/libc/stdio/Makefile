# $FreeBSD: head/tools/regression/lib/libc/stdio/Makefile 247411 2013-02-27 19:50:46Z jhb $

TESTS=	test-fmemopen test-getdelim test-open_memstream test-open_wmemstream \
	test-perror test-print-positional test-printbasic test-printfloat \
	test-scanfloat 
CFLAGS+= -lm

.PHONY: tests
tests: ${TESTS}
	for p in ${TESTS}; do ${.OBJDIR}/$$p; done

.PHONY: clean
clean:
	-rm -f ${TESTS}
