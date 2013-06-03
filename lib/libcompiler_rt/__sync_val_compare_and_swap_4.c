/* $FreeBSD: head/lib/libcompiler_rt/__sync_val_compare_and_swap_4.c 249968 2013-04-27 04:56:02Z ed $ */
#define	NAME		__sync_val_compare_and_swap_4
#define	TYPE		int32_t
#define	CMPSET		atomic_cmpset_32

#include "__sync_val_compare_and_swap_n.h"
