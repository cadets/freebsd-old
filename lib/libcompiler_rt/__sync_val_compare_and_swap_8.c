/* $FreeBSD: head/lib/libcompiler_rt/__sync_val_compare_and_swap_8.c 249968 2013-04-27 04:56:02Z ed $ */
#define	NAME		__sync_val_compare_and_swap_8
#define	TYPE		int64_t
#define	CMPSET		atomic_cmpset_64

#include "__sync_val_compare_and_swap_n.h"
