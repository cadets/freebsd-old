#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include <dt_ctir.h>
#include <dt_program.h>

#include <dt_impl.h>

#define CT_PROC_DEFAULT_SIZE 128

static uint64_t cur_proc_id = 1; /* Start from 1 */

ct_ctir_t *
ctir_alloc(void)
{

	ct_ctir_t *ctir;
	ctir = malloc(sizeof(ct_ctir_t));
	return (ctir);
}

static ct_proc_t *
ctir_acquire_proc(ct_proc_t *p, dtrace_probedesc_t *pd)
{
	char probename[DTRACE_FULLNAMELEN];
	char *cp;
	ct_proc_t *it;

	assert(pd != NULL);
	assert(p != NULL);

	/*
	 * Create a full probe name.
	 */
	cp = probename;
	cp = stpncpy(cp, pd->dtpd_provider,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_mod,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_func,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_name,
		     sizeof(probename) - (cp - probename) - 1);

	assert(*cp == 0);

	/*
	 * We go over all of the currently known processes and look for the
	 * one named by the probedesc.
	 */
	for (it = p; it; it = dt_list_next(it)) {
		assert(it->desc != NULL);
		if (strcmp(it->desc->name, probename) == 0)
			return (it);
	}

	/*
	 * If it is NULL, we simply didn't find that process yet. We then
	 * construct it and fill in the name of the process description.
	 * The instructions themselves and the type will be filled out at
	 * a later stage.
	 */
	it = malloc(sizeof(ct_proc_t));
	assert(it != NULL);

	it->desc = malloc(sizeof(ct_procdesc_t));
	assert(it->desc != NULL);

        strncpy(it->desc->name, probename, sizeof(probename));
	it->desc->name[DTRACE_FULLNAMELEN-1] = 0;

	/*
	 * Give it a numeric (unique) identifier for internal handling.
	 */
	assert(cur_proc_id + 1 > cur_proc_id); /* XXX: Bad */
	it->desc->id = cur_proc_id++;

	/*
	 * Append the process into the list, so we can find it in the next run.
	 */
	dt_list_append(&p->list, it);

	return (it);
}

static void
ctir_translate_action(ct_proc_t *p, dtrace_actdesc_t *ap)
{

}

ct_ctir_t *
ctir_from_daf(dtrace_prog_t *pgp)
{
	ct_ctir_t *ctir;
	ct_proc_t *p;

	/*
	 * Here we just allocate a CTIR description to be used later.
	 */
	ctir = ctir_alloc();

	p = &ctir->proc;

	/*
	 * Go over _all_ of the DTrace programs that are present.
	 */
	for (; pgp; pgp = dt_list_next(pgp)) {
		dtrace_stmtdesc_t *stmt;
		dtrace_ecbdesc_t *edp, *last;
		dtrace_probedesc_t *pd;

		/*
		 * Iterate over the statements.
		 */
		for (stmt = dt_list_next(&pgp->dp_stmts);
		     stmt; stmt = dt_list_next(stmt)) {
			dtrace_actdesc_t *ap;

			edp = stmt->dtsd_ecbdesc;

			/*
			 * We don't care about it having many ECBs, just the
			 * statement itself.
			 */
			if (edp == last)
				continue;
			last = edp;
			pd = &edp->dted_probe;

			/*
			 * At this point, we have grabbed the probe description
			 * of the statement which will identify the process for
			 * us. This will let us populate the process with
			 * instructions that it will execute. We will use this
			 * to infer a number of types and statically check some
			 * properties. ctir_acquire_proc will always return a
			 * process or hard-fail. It either creates a new one, or
			 * finds the correct one.
			 */
			p = ctir_acquire_proc(&ctir->proc, pd);

			/*
			 * We now have the correct (or new) process, and we will
			 * populate it with all of the necessary instructions.
			 */
			for (ap = edp->dted_action; ap; ap = ap->dtad_next)
				ctir_translate_action(p, ap);
		}
	}
	return (ctir);
}
