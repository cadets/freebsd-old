/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 *
 */

#include <sys/types.h>
#include <sys/malloc.h>

#include <dtrace_impl.h>

#include "ddtrace_dof.h"
#include "dl_utils.h"

struct dd_dfo {
	struct bbuf *secs;
	struct bbuf *ldata;
	struct bbuf *strs;
	dof_secidx_t next;
};

static dof_secidx_t dof_add_difo(struct dd_dfo *, const dtrace_difo_t *);
static dof_secidx_t dof_add_lsect(struct dd_dfo *, const void *, uint32_t,
    uint32_t, uint32_t, uint32_t, uint64_t);
static dof_stridx_t dof_add_string(struct dd_dfo*, const char *);
static void dof_hdr(dof_hdr_t *);

static void inline assert_integrity(struct dd_dfo *ddo)
{

	ASSERT(ddo != NULL);
	ASSERT(ddo->secs != NULL);
	ASSERT(ddo->ldata != NULL);
	ASSERT(ddo->strs != NULL);
}

/*
 * Add a DIFOHDR section and the consituent DIF, INTTAB, STRTAB and VARTAB
 * sections.  The section index of the DIFO header is returned.
 */
static dof_secidx_t
dof_add_difo(struct dd_dfo *ddo, const dtrace_difo_t *dp)
{
	dof_secidx_t dsecs[5]; /* enough for all possible DIFO sections */
	uint_t nsecs = 0;
	dof_difohdr_t *dofd;
	dof_secidx_t hdrsec = DOF_SECIDX_NONE;

	assert_integrity(ddo);
	ASSERT(dp != NULL);
	ASSERT(MUTEX_HELD(&dtrace_lock));

	/* Instruction buffer - DOF_SECT_DIF. */
	if (dp->dtdo_buf != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_buf,
		    DOF_SECT_DIF, sizeof(dif_instr_t), 0,
		    sizeof(dif_instr_t), sizeof(dif_instr_t) * dp->dtdo_len);
	}

	/* Integer table - DOF_SECT_INTTAB. */
	if (dp->dtdo_inttab != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_inttab,
		    DOF_SECT_INTTAB, sizeof(uint64_t), 0,
		    sizeof(uint64_t), sizeof(uint64_t) * dp->dtdo_intlen);
	}

	/* String table - DOF_SECT_STRTAB. */
	if (dp->dtdo_strtab != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_strtab,
		    DOF_SECT_STRTAB, sizeof(char), 0, 0, dp->dtdo_strlen);
	}

	/* Variable table - DOF_SECT_VARTAB. */
	if (dp->dtdo_vartab != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_vartab,
		    DOF_SECT_VARTAB, sizeof (uint_t), 0, sizeof (dtrace_difv_t),
		    sizeof (dtrace_difv_t) * dp->dtdo_varlen);
	}

	/*
	 * Copy the return type and the array of section indices that form the
	 * DIFO into a single dof_difohdr_t and then add DOF_SECT_DIFOHDR.
	 */
	ASSERT(nsecs <= sizeof(dsecs) / sizeof(dsecs[0]));
	dofd = malloc(sizeof(dtrace_diftype_t) + sizeof (dsecs), M_TEMP, M_NOWAIT);
	ASSERT(dofd != NULL);
	bcopy(&dp->dtdo_rtype, &dofd->dofd_rtype, sizeof(dtrace_diftype_t));
	bcopy(dsecs, &dofd->dofd_links, sizeof(dof_secidx_t) * nsecs);

	/* DIFO header - DOF_SECTDIFOHDR */
	hdrsec = dof_add_lsect(ddo, dofd, DOF_SECT_DIFOHDR,
	    sizeof (dof_secidx_t), 0, 0,
	    sizeof (dtrace_diftype_t) + sizeof (dof_secidx_t) * nsecs);

	free(dofd, M_TEMP);

	return hdrsec;
}

/*
 * Add a loadable DOF section to the file using the specified data buffer and
 * the specified DOF section attributes. DOF_SECF_LOAD must be set in flags.
 * If 'data' is NULL, the caller is responsible for manipulating the ldata buf.
 */
static dof_secidx_t
dof_add_lsect(struct dd_dfo *ddo, const void *data, uint32_t type,
    uint32_t align, uint32_t flags, uint32_t entsize, uint64_t size)
{
	dof_sec_t s;
	
	assert_integrity(ddo);
	ASSERT(MUTEX_HELD(&dtrace_lock));

	s.dofs_type = type;
	s.dofs_align = align;
	s.dofs_flags = flags | DOF_SECF_LOAD;
	s.dofs_entsize = entsize;
	s.dofs_offset = bbuf_pos_aligned(ddo->ldata, align);
	s.dofs_size = size;

	if (bbuf_bcat_aligned(ddo->secs, (unsigned char *) &s, sizeof(s),
	    sizeof(uint64_t)) != 0) {
		
		return -1;
	}

	if (data != NULL) {

		if (bbuf_bcat_aligned(ddo->ldata, data, size, align) != 0) {
			
			return -1;
		}
	}

	return ddo->next++;
}

/*
 * Add a string to the global string table associated with the DOF.  The offset
 * of the string is returned as an index into the string table.
 */
static dof_stridx_t
dof_add_string(struct dd_dfo *ddo, const char *s)
{
	dof_stridx_t i;
	
	assert_integrity(ddo);
	ASSERT(s != NULL);
	ASSERT(MUTEX_HELD(&dtrace_lock));
	
	i = bbuf_pos(ddo->strs);

	if (i != 0 && (s == NULL || *s == '\0')) {
	
	       	/* string table has \0 at offset 0 */
		return 0;
	}

	if (bbuf_bcat(ddo->strs, s, strlen(s) + 1) != 0) {

		return -1;
	}

	return i;
}

static void 
dof_hdr(dof_hdr_t *hdr)
{

	ASSERT(hdr != NULL);
	ASSERT(MUTEX_HELD(&dtrace_lock));

	bzero(hdr, sizeof(dof_hdr_t));

	hdr->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	hdr->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	hdr->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	hdr->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	hdr->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	hdr->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	hdr->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	hdr->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	hdr->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	hdr->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	hdr->dofh_flags = 0;
	hdr->dofh_hdrsize = sizeof(dof_hdr_t);
	hdr->dofh_secsize = sizeof(dof_sec_t);
	hdr->dofh_secnum = 0;
	hdr->dofh_secoff = sizeof(dof_hdr_t);
	hdr->dofh_loadsz = 0;
	hdr->dofh_filesz = 0;
	hdr->dofh_pad = 0;
}

/*
 * Create DOF out of a currently enabled state.  Right now, we only create
 * DOF containing the run-time options -- but this could be expanded to create
 * complete DOF representing the enabled state.
 */
struct bbuf *
ddtrace_dof_create(dtrace_state_t *state)
{
	dof_hdr_t hdr;
	struct dd_dfo ddo;
	struct bbuf *dof;
	dof_secidx_t strtab;
	dof_sec_t *s;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(state != NULL);

	/* Create the DOF header */
	dof_hdr(&hdr);

	/* Create a binary buffer to store the DOF section headers. */
	bbuf_new_auto(&ddo.secs);

	/* Create a binary buffer to store the DOF loadable sections. */
	bbuf_new_auto(&ddo.ldata);

	/* Create a binary buffer to store the DOF global strings. */
	bbuf_new_auto(&ddo.strs);

	ddo.next = 0;

	strtab = dof_add_lsect(&ddo, NULL, DOF_SECT_STRTAB, 1, 0, 0, 0);
	(void) dof_add_string(&ddo, "");

	/* Iterate through the ecbs, add each to the DOF. */
	for (dtrace_epid_t i = 0; i < state->dts_epid - 1; i++) {

		dof_probedesc_t dofp;
		dof_secidx_t pdesc;
		dof_secidx_t predidx = DOF_SECIDX_NONE;
		dof_ecbdesc_t dofe;
		dof_secidx_t actidx = DOF_SECIDX_NONE;
		dtrace_action_t *ap;
		dtrace_ecb_t *ecb;
		dtrace_probe_t *probe;
		size_t nacts = 0;
		int j;

		ecb = state->dts_ecbs[i];
		ASSERT(ecb != NULL);

		probe = ecb->dte_probe;
		if (probe == NULL) {

			continue;
		}

		/* Add a DOF_SECT_PROBEDESC for the ECB's probe description,
		 * and copy the descirption strings into thestring tableSTRTAB.
		 */
		dofp.dofp_strtab = strtab; 
		dofp.dofp_provider = dof_add_string(&ddo, probe->dtpr_provider->dtpv_name);
		dofp.dofp_mod = dof_add_string(&ddo, probe->dtpr_mod);
		dofp.dofp_func = dof_add_string(&ddo, probe->dtpr_func);
		dofp.dofp_name = dof_add_string(&ddo, probe->dtpr_name);
		dofp.dofp_id = probe->dtpr_id;

		pdesc = dof_add_lsect(&ddo, &dofp, DOF_SECT_PROBEDESC,
    		    sizeof(dof_secidx_t), 0, sizeof(dof_probedesc_t),
		    sizeof(dof_probedesc_t));

		/* Predicate */
		if (ecb->dte_predicate != NULL && ecb->dte_predicate->dtp_difo != NULL) {
	
			predidx = dof_add_difo(&ddo, ecb->dte_predicate->dtp_difo);
		}

		/* Actions */

		/* Iterate through the ECB actions to determine the
		 * number; needed to allocate a dof_actdesc_t array.
		 */
		for (j = 0, ap = ecb->dte_action; ap != NULL;
		    ap = ap->dta_next, j++) {

			nacts++;
		}

		if (nacts > 0) {

			dof_actdesc_t *dofa;

			dofa = malloc(sizeof(dof_actdesc_t) * nacts,
			    M_TEMP, M_NOWAIT);
			ASSERT(dofa != NULL);

			/* Iterate through the actions adding the to
			 * the dof_actdest_t array.
			 */
			for (j = 0, ap = ecb->dte_action; ap != NULL;
			    ap = ap->dta_next, j++) {

				if (ap->dta_difo != NULL) {

					dofa[j].dofa_difo = dof_add_difo(&ddo, ap->dta_difo);
				} else {

					dofa[j].dofa_difo = DOF_SECIDX_NONE;
				}
			
				/* TODO handle other actions than PRINTFLIKE */
				if (ap->dta_rec.dtrd_arg == 0) {

					dofa[j].dofa_arg = ap->dta_rec.dtrd_arg;
					dofa[j].dofa_strtab = DOF_SECIDX_NONE;
				} else {	

					dofa[j].dofa_arg = dof_add_string(&ddo, state->dts_formats[ap->dta_rec.dtrd_format]);
					dofa[j].dofa_strtab = strtab;
				}
			
				dofa[j].dofa_kind = ap->dta_kind;
				dofa[j].dofa_ntuple = 0;
				dofa[j].dofa_uarg = ap->dta_rec.dtrd_uarg;
			}
			
			actidx = dof_add_lsect(&ddo, dofa, DOF_SECT_ACTDESC,
			    sizeof(int64_t), 0, sizeof(dof_actdesc_t),
			    sizeof(dof_actdesc_t) * nacts);

			free(dofa, M_TEMP);
		}

		/* DOF_SECT_ECBDESC */
		dofe.dofe_probes = pdesc; 
		dofe.dofe_pred = predidx;
		dofe.dofe_actions = actidx;
		dofe.dofe_pad = 0;
		dofe.dofe_uarg = ecb->dte_uarg;

		(void) dof_add_lsect(&ddo, &dofe, DOF_SECT_ECBDESC,
    		    sizeof(int64_t), 0, 0, sizeof(dof_ecbdesc_t));
	}

	/* Create a binary buffer to store the DOF. */
	bbuf_new_auto(&dof);

	hdr.dofh_secnum = ddo.next;
	hdr.dofh_loadsz = hdr.dofh_filesz = bbuf_pos(ddo.secs) +
	    bbuf_pos(ddo.ldata) + bbuf_pos(ddo.strs);

	/* Assemble the complete in-memory DOF buffer. */
	bbuf_bcat(dof, (unsigned char *) &hdr, sizeof(hdr));

	/* Rellocate the sections. */
	s = (dof_sec_t *) bbuf_data(ddo.secs);

	for (int i = 0; i < ddo.next; i++) {	

		if (i == strtab) {

			/* Rellocate the STRTAB section. */
			s->dofs_size = bbuf_pos(ddo.strs);
			s->dofs_offset += bbuf_pos(dof) + bbuf_pos(ddo.secs) + bbuf_pos(ddo.ldata);
		} else {

			s->dofs_offset += bbuf_pos(dof) + bbuf_pos(ddo.secs);
		}
		s++;
	}

	bbuf_concat(dof, ddo.secs);
	bbuf_delete(ddo.secs);

	bbuf_concat(dof, ddo.ldata);
	bbuf_delete(ddo.ldata);

	bbuf_concat(dof, ddo.strs);
	bbuf_delete(ddo.strs);

	return dof;
}
