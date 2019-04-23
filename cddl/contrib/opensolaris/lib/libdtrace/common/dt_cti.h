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

typedef struct ct_insdesc {
	uint8_t kind;
	uint8_t instr;
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
			uint24_t label;
		} b;

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
 * ct_globaltype is a structure that contains all of the information about
 * a global type encoding the programmer's assumptions about the underlying
 * system. This includes things like, "a tid between two processes is guaranteed
 * to be identical", which is then used to construct an ordering relation
 * between processes, if possible. This is the heart of the CTIR for static
 * analysis and is used to automatically generate the type of each process in
 * use in a given script.
 */
typedef struct ct_globaltype {

} ct_globaltype_t;

/*
 * ct_proctype contains the encoding of a type for every CTIR process. It is
 * generated from ct_globaltype_t and is used for incremental type-checking of
 * the script.
 */
typedef struct ct_proctype {

} ct_proctype_t;

/*
 * ct_procdesc is a structure describing the following properties of
 * a CTIR Process:
 *  (*) CTIR Process Name: The name of a process is arbitrary and only used
 *      as human-facing information. It is not relevant for static checking.
 *  (*) CTIR Process Instructions: A list of all of the CTIR instructions inside
 *      the process.
 *  (*) CTIR Process Type: A type of the process encoding the programmer
 *      assumptions about the underlying system in order to guide the
 *      type-checking process. This type is automatically generated from the
 *      global type of a given DTrace program.
 */
typedef struct ct_procdesc {
	char *name;          /* Process name */
	ct_ins_t insns;      /* List of instructions */
	cd_proctype_t *type; /* Process type */
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

#endif
