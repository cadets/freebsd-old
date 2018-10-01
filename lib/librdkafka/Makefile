# $FreeBSD$

LIBRDKAFKA=	${SRCTOP}/contrib/librdkafka

.include <${LIBRDKAFKA}/Makefile.config>

.if !defined(COMPAT_32BIT)
CFLASG+= -DWITH_CRC32C_HW=1
CFLAGS+= -DHAVE_ATOMICS_64=1
.else
CFLASG+= -DHAVE_ATOMICS_32=1
.endif

PACKAGE=lib${LIB}
LIB=		rdkafka	
PRIVATELIB=	true
SHLIB_MAJOR=	1
SHLIB_MINOR=	0

SRCS=		crc32c.c \
		lz4.c \
		lz4frame.c \
		lz4hc.c \
		rdaddr.c \
		rdavl.c \
		rdbuf.c \
		rdcrc32.c \
		rddl.c \
		rdgz.c \
		rdhdrhistogram.c \
		rdkafka.c \
		rdkafka_admin.c \
		rdkafka_assignor.c \
		rdkafka_aux.c \
		rdkafka_background.c \
		rdkafka_broker.c \
		rdkafka_buf.c \
		rdkafka_cgrp.c \
		rdkafka_conf.c \
		rdkafka_event.c \
		rdkafka_feature.c \
		rdkafka_header.c \
		rdkafka_interceptor.c \
		rdkafka_lz4.c \
		rdkafka_metadata.c \
		rdkafka_metadata_cache.c \
		rdkafka_msg.c \
		rdkafka_msgset_reader.c \
		rdkafka_msgset_writer.c \
		rdkafka_offset.c \
		rdkafka_op.c \
		rdkafka_partition.c \
		rdkafka_pattern.c \
		rdkafka_plugin.c \
		rdkafka_queue.c \
		rdkafka_range_assignor.c \
		rdkafka_request.c \
		rdkafka_roundrobin_assignor.c \
		rdkafka_subscription.c \
		rdkafka_timer.c \
		rdkafka_topic.c \
		rdkafka_transport.c \
		rdlist.c \
		rdlog.c \
		rdmurmur2.c \
		rdports.c \
		rdrand.c \
		rdregex.c \
		rdstring.c \
		rdunittest.c \
		rdvarint.c \
		regexp.c \
		snappy.c \
		tinycthread.c \
		tinycthread_extra.c \
		xxhash.c

.PATH:		${LIBRDKAFKA}/src

INCS=		rdkafka.h
INCSDIR=	${INCLUDEDIR}/private/rdkafka

WARNS=		1
CFLAGS+=	-I${LIBRDKAFKA}/src
CFLAGS+=	-Wno-implicit-function-declaration

.include <bsd.lib.mk>
