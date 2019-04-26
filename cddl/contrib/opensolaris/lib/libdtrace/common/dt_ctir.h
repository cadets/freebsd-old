/*-
 * Copyright (c) 2019 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _DT_CTI_H_
#define _DT_CTI_H_

#include <sys/ctf_api.h>
#include <dt_list.h>

#include <dtrace.h>

/*
 * The Concurrent Tracing Intermediate Representation (CTIR) is a representation
 * that DTrace programs are converted in order to be statically checked for
 * errors that would otherwise be hard to detect. It is currently constructed
 * from DTrace actions (aggregation, DIF, backtrace, etc.) and DTrace probes,
 * and is much simpler.
 *
 * We currently discard information that is not necessary for checking the
 * properties that we are interested in. However, the representation is made
 * to be as extensible as possible. We define the following abstractions
 * informally in order to provide a mental model of how CTIR should be read:
 *
 *  (*) CTIR Instruction: The most basic building-block of CTIR.
 *      Instructions are a part of a CTIR Process (see below), and are expected
 *      to be executed in-order. Each instruction inside a process has 0 or more
 *      predecessors, and 0 or more successors. All instructions except for
 *      branching instructions can have at most one (1) successor, while all of
 *      them could have more predecessors, depending on previous control flow.
 *  (*) CTIR Process: A CTIR primitive used to represent concurrency. They can
 *      be composed sequentially (execute one process, then execute another one)
 *      or using parallel composition (execute two or more processes at the same
 *      time). Parallel composition allows for either process to execute any
 *      number of CTIR instructions non-deterministically. They contain 0 or
 *      more CTIR instructions and are executed on CTIR Execution Units.
 *  (*) CTIR Execution Unit: TODO.
 */

struct ct_globaltype;
struct ct_proctype;
struct ct_proc;
struct ct_static_chan;
struct ct_dynamic_chan;
typedef uint64_t ct_label_t;

typedef struct ct_insdesc {
	uint8_t kind;
#define CT_INSDESC_RRR 1
#define CT_INSDESC_RR  2
#define CT_INSDESC_RRI 3
#define CT_INSDESC_B   4
#define CT_INSDESC_EUL 5
	uint8_t instr;
#define CT_OP_OR      1  /* or rd, rs1, rs2 */
#define CT_OP_XOR     2  /* xor rd, rs1, rs2 */
#define CT_OP_AND     3  /* and rd, rs1, rs2 */
#define CT_OP_SLL     4  /* sll rd, rs1, rs2 */
#define CT_OP_SRL     5  /* srl rd, rs1, rs2 */
#define CT_OP_SRA     6 /* sra rd, rs1, rs2 */
#define CT_OP_SUB     7  /* sub rd, rs1, rs2 */
#define CT_OP_ADD     8  /* add rd, rs1, rs2 */
#define CT_OP_MUL     9  /* mul rd, rs1, rs2 */
#define CT_OP_SDIV    10  /* sdiv rd, rs1, rs2 */
#define CT_OP_UDIV    11 /* udiv rd, rs1, rs2 */
#define CT_OP_SREM    12 /* srem rd, rs1, rs2 */
#define CT_OP_UREM    13 /* urem rd, rs1, rs2 */
#define CT_OP_NOT     14 /* not rd, rs */
#define CT_OP_MOV     15 /* mov, rd, rs */
#define CT_OP_CMP     16 /* cmp rs1, rs2 */
#define CT_OP_TST     17 /* tst rs */
#define CT_OP_BA      18 /* ba label */
#define CT_OP_BE      19 /* be label */
#define CT_OP_BNE     20 /* bne label */
#define CT_OP_BG      21 /* bg label */
#define CT_OP_BGU     22 /* bgu label */
#define CT_OP_BGE     23 /* bge label */
#define CT_OP_BGEU    24 /* bgeu label */
#define CT_OP_BL      25 /* bl label */
#define CT_OP_BLU     26 /* blu label */
#define CT_OP_BLE     27 /* ble label */
#define CT_OP_BLEU    28 /* bleu label */
#define CT_OP_LS8     29 /* ls8 rd, [rs] */
#define CT_OP_LS16    30 /* ls16 rd, [rs] */
#define CT_OP_LS32    31 /* ls32 rd, [rs] */
#define CT_OP_LU8     32 /* lu8 rd, [rs] */
#define CT_OP_LU16    33 /* lu16 rd, [rs] */
#define CT_OP_LU32    34 /* lu32 rd, [rs] */
#define CT_OP_L64     35 /* l64 rd, [rs] */
#define CT_OP_RET     36 /* ret rs */
#define CT_OP_NOP     37 /* nop */
#define CT_OP_SETX    38 /* setx rd, idx */
#define CT_OP_SETS    39 /* sets rd, idx */
#define CT_OP_SCMP    40 /* scmp rs1, rs2 */
#define CT_OP_GRECV   41 /* grecv rd, chan */
#define CT_OP_GSEND   42 /* gsend rd, chan */
#define CT_OP_TSEND   43 /* tsend rd, chan */
#define CT_OP_TRECV   44 /* trecv rd, chan */
#define CT_OP_CALL    45 /* call rd, subr */
#define CT_OP_PUSHTR  46 /* pushtr groundtype, rsize, rref */
#define CT_OP_PUSHTV  47 /* pushtv val */
#define CT_OP_POPTS   50 /* popts */
#define CT_OP_FLUSHTS 51 /* flushts */
#define CT_OP_ALLOCS  52 /* allocs rd, rs */
#define CT_OP_ST8     53 /* st8 [rd], rs */
#define CT_OP_ST16    54 /* st16 [rd], rs */
#define CT_OP_ST32    55 /* st32 [rd], rs */
#define CT_OP_ST64    56 /* st64 [rd], rs */
	union {
		/*
		 * Register-Register-Register instructions.
		 */
		struct {
			uint8_t rs1;
			uint8_t rs2;
			uint8_t rd;
		} rrr;

		/*
		 * Register-Register instructions.
		 */
		struct {
			uint8_t rs;
			uint8_t rd;
		} rr;

		/*
		 * Register-Register-Immediate instructions.
		 */
		struct {
			uint8_t rs;
			uint16_t imm;
			uint8_t rd;
		} rri;

		/*
		 * Branching instructions for control flow _within_ a process.
		 */
		struct {
			uint32_t label;
		} b;

		/*
		 * Static channel operations.
		 */
		struct {
			struct ct_static_chan *chan;
			uint8_t rd;
		} s_chanop;

		/*
		 * Dynamic channel operations.
		 */
		struct {
			struct ct_dynamic_chan *chan;
			uint8_t rd;
		} d_chanop;

		/*
		 * Execution-unit local instructions are those that only
		 * modify state on the current execution unit. From D's
		 * perspective, these include things like aggregations,
		 * "probe-local" variables, etc.
		 */
		struct {
			/*
			 * TODO: Currently these are left empty because we only
			 *       want to do a couple of static checks. However,
			 *       this IR in the future will likely be used for
			 *       optimisation and for workload distribution. In
			 *       a distributed system, it is often desirable to
			 *       figure out where we want to compute certain
			 *       results. Execution units are a part of that
			 *       abstraction and will be created to form event
			 *       structures.
			 */
		} eunit_local;
	} u;
} ct_insdesc_t;

/*
 * ct_ins is a _doubly linked list_ of all instructions within a
 * process. They are constructed from DIF and various other actions
 * such as backtrace actions, aggregations, etc.
 */
typedef struct ct_ins {
	dt_list_t list;
	ct_insdesc_t *desc;
} ct_ins_t;

/*
 * ct_msgtype is a type representing what is being sent through the channel, or
 * a session type. There are three 'classes' of types that can be sent:
 *  (*) D String: A type of any D string (result of copyinstr, etc.);
 *  (*) CTF Type: One of the types known via CTF;
 *  (*) Session Type: A type describing an interaction for a given process.
 */
typedef struct ct_msgtype {
	int type_ident;
#define CT_MSG_TYPE_D_STRING 1
#define CT_MSG_TYPE_CTF      2
#define CT_MSG_TYPE_SESSION  3

	struct {
		struct ct_proctype *ptype;
		struct ct_proc *proc;
	} session;
} ct_msgtype_t;

/*
 * ct_typevar describes a type variable. These are used in global and process
 * types for recursion.
 */
typedef struct ct_typevar {
	int kind;
#define CT_VAR_TYPE_GLOBAL 1
#define CT_VAR_TYPE_PROC   2
	union {
		struct ct_globaltype *global;
		struct ct_proctype *proc;
	} u;
} ct_typevar_t;

/*
 * A static channel is one that can be named statically. ct_static_chan is a
 * structure that describes such channels.
 */
typedef struct ct_static_chan {
	char *name;  /* Human-facing name */
	uint64_t id; /* Identifier of the channel (unique) */
} ct_static_chan_t;

typedef struct ct_dynamic_chan {
	char *name;             /* Human-facing name */
	uint64_t id;            /* Identifier of the channel (unique) */
	ctf_id_t *ground_types; /* Array of CTF types used in resolution */
	size_t n_ground_types;  /* Size of the ground types array */
} ct_dynamic_chan_t;

/*
 * ct_globaltype is a structure that contains all of the information about
 * a global type encoding the programmer's assumptions about the underlying
 * system. This includes things like, "a tid between two processes is guaranteed
 * to be identical", which is then used to construct an ordering relation
 * between processes, if possible. This is the heart of the CTIR for static
 * analysis and is used to automatically generate the type of each process in
 * use in a given script.
 */
typedef struct ct_globaltype {
	int type_ident;
#define CT_GLOBAL_TYPE_ST_VALUE 1
#define CT_GLOBAL_TYPE_BRANCH   2
#define CT_GLOBAL_TYPE_PAR      3
#define CT_GLOBAL_TYPE_REC      4
#define CT_GLOBAL_TYPE_VAR      5
#define CT_GLOBAL_TYPE_END      6
	union {
		struct {
			struct ct_proc *p1;      /* Sending process */
			struct ct_proc *p2;     /* Receiving process */
			ct_msgtype_t *msg_type; /* Type of message being sent */
			ct_static_chan_t *chan;
			                        /* Static channel being communicated through */
		} st_value;

		struct {
			struct ct_proc *p1; /* Sending process */
			struct ct_proc *p2; /* Receiving process */
			struct {
				ct_label_t *label; /* Choice label */
				struct ct_globaltype *interaction;
				                   /* Interaction for that choice */
			} *choices;    /* An array of choices */
			size_t n_choices; /* Number of choices */
		} st_branch;

		struct {
			struct ct_globaltype *g1;
			struct ct_globaltype *g2;
		} parallel;

		struct {
			ct_typevar_t *var; /* Variable being recursed on */
			struct ct_globaltype *g;  /* The type containing the variable */
		} recursive;

		ct_typevar_t *var;
	} u;
} ct_globaltype_t;

/*
 * ct_proctype contains the encoding of a type for every CTIR process. It is
 * generated from ct_globaltype_t and is used for incremental type-checking of
 * the script.
 */
typedef struct ct_proctype {
	int type_ident;
#define CT_PROC_TYPE_SEND   1
#define CT_PROC_TYPE_RECV   2
#define CT_PROC_TYPE_BRANCH 3
#define CT_PROC_TYPE_SELECT 4
#define CT_PROC_TYPE_REC    5
#define CT_PROC_TYPE_VAR    6
#define CT_PROC_TYPE_END    7
	union {
		struct {
			ct_static_chan_t *chan; /* Channel being sent on */
			ct_msgtype_t *msg_type; /* Type of message being sent */
		} st_send;

		struct {
			ct_static_chan_t *chan; /* Channel being received on */
			ct_msgtype_t *msg_type; /* Type of message being received */
		} st_recv;

		struct {
			ct_static_chan_t *chan; /* Channel being received on */
			struct {
				ct_label_t *label; /* Choice label */
				struct ct_proctype *interaction;
				                   /* Interaction for that choice */
			} *choices;    /* An array of choices */
			size_t n_choices; /* Number of choices */
		} st_branch;

		struct {
			ct_static_chan_t *chan; /* Channel being sent on */
			struct {
				ct_label_t *label; /* Choice label */
				struct ct_proctype *interaction;
				                   /* Interaction for that choice */
			} *choices;    /* An array of choices */
			size_t n_choices; /* Number of choices */
		} st_select;

		struct {
			ct_typevar_t *var; /* Variable being recursed on */
			struct ct_proctype *g;  /* The type containing the variable */
		} recursive;

		ct_typevar_t *var;
	} u;
} ct_proctype_t;

/*
 * ct_procdesc is a structure describing the following properties of
 * a CTIR Process:
 *  (*) CTIR Process Name: The name of a process is arbitrary and only used
 *      as human-facing information. It is not relevant for static checking.
 *      However, it is used to construct CTIR, as DTrace probes are named via
 *      human-facing names.
 *  (*) CTIR Process Instructions: A list of all of the CTIR instructions inside
 *      the process.
 *  (*) CTIR Process Type: A type of the process encoding the programmer
 *      assumptions about the underlying system in order to guide the
 *      type-checking process. This type is automatically generated from the
 *      global type of a given DTrace program.
 */
typedef struct ct_procdesc {
	char name[DTRACE_FULLNAMELEN]; /* Process name */
	uint64_t id;                   /* Process identifier */
	ct_ins_t insns;                /* List of instructions */
	ct_proctype_t *type;           /* Process type */
} ct_procdesc_t;

/*
 * ct_proc is a _doubly linked list_ of concurrent processes that
 * have been specified by the programmer. They are constructed
 * from DTrace probes and can be viewed as entities that execute
 * all of the CTIR instructions.
 */
typedef struct ct_proc {
	dt_list_t list;
	ct_procdesc_t *desc;
} ct_proc_t;

typedef struct ct_ctir {
	ct_proc_t proc;
} ct_ctir_t;

ct_ctir_t *ctir_from_daf(dtrace_prog_t *pgp);


#endif
