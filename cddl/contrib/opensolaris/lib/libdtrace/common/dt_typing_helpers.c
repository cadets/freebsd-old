/*-
 * Copyright (c) 2021 Domagoj Stolfa
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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

#include <dt_typing.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.h>
#include <dt_basic_block.h>
#include <dt_ifgnode.h>
#include <dt_typefile.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_helpers.h>

ctf_id_t
dt_type_strip_ref(dt_typefile_t *tf, ctf_id_t *orig_id, size_t *n_stars)
{
	ctf_id_t kind;
	ctf_id_t id;
	size_t n_redirects;

	assert(n_stars != NULL);
	assert(orig_id != NULL);

	kind = dt_typefile_typekind(tf, *orig_id);

	*n_stars = 0;

	if (kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER)
		return (kind);

	id = *orig_id;
	n_redirects = 0;

	while (kind == CTF_K_TYPEDEF || kind == CTF_K_POINTER) {
		id = dt_typefile_reference(tf, id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    dt_typefile_error(tf));
			return (CTF_ERR);
		}

		if (kind == CTF_K_POINTER)
			n_redirects++;

		kind = dt_typefile_typekind(tf, id);
	}

	assert(kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER);
	*n_stars = n_redirects;
	*orig_id = id;

	return (kind);
}

ctf_id_t
dt_type_strip_typedef(dt_typefile_t *tf, ctf_id_t *orig_id)
{
	ctf_id_t kind;
	ctf_id_t id;

	assert(orig_id != NULL);

	kind = dt_typefile_typekind(tf, *orig_id);

	if (kind != CTF_K_TYPEDEF)
		return (kind);

	id = *orig_id;

	while (kind == CTF_K_TYPEDEF) {
		id = dt_typefile_reference(tf, id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    dt_typefile_error(tf));
			return (CTF_ERR);
		}

		kind = dt_typefile_typekind(tf, id);
	}

	assert(kind != CTF_K_TYPEDEF);
	*orig_id = id;

	return (kind);
}

int
dt_ctf_type_compare(dt_typefile_t *tf1, ctf_id_t id1,
    dt_typefile_t *tf2, ctf_id_t id2)
{

	size_t n_stars1, n_stars2;
	ctf_id_t kind1, kind2;
	void *memb1, *memb2;
	char type1_name[4096], type2_name[4096];
	char memb1_name[4096], memb2_name[4096];
	void *s1, *s2;

	assert(tf1 != NULL);
	assert(tf2 != NULL);

	/*
	 * If we're comparing the same type, it's just equal.
	 */
	if (tf1 == tf2 && id1 == id2)
		return (0);

	if (dt_typefile_typename(tf1, id1, type1_name, sizeof(type1_name)) !=
	    (char *)type1_name) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    dt_typefile_error(tf1));
		return (-1);
	}

	if (dt_typefile_typename(tf2, id2, type2_name, sizeof(type2_name)) !=
	    (char *)type2_name) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    dt_typefile_error(tf2));
		return (-1);
	}

	kind1 = dt_type_strip_ref(tf1, &id1, &n_stars1);
	kind2 = dt_type_strip_ref(tf2, &id2, &n_stars2);

	/*
	 * Give integers some leeway.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		if (dt_typefile_compat(tf1, id1, tf2, id2) == 0) {
			fprintf(stderr, "%s and %s are incompatible integers\n",
			    type1_name, type2_name);
			return (-1);
		}

		return (0);
	}

	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	/*
	 * Names must match
	 */
	if (strcmp(type1_name, type2_name) != 0) {
		fprintf(stderr, "subtyping not possible: %s != %s\n",
		    type1_name, type2_name);
		return (-1);
	}

	assert(kind1 == kind2);

	if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		if (dt_typefile_compat(tf1, id1, tf2, id2) == 0) {
			fprintf(stderr,
			    "dt_typefile_compat() %s is not "
			    "compatible with %s\n",
			    type1_name, type2_name);
			return (-1);
		}

		return (0);
	}

	if (kind1 == CTF_K_STRUCT) {
		s1 = dt_typefile_buildup_struct(tf1, id1);
		if (s1 == NULL) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    dt_typefile_stringof(tf1), type1_name,
			    dt_typefile_error(tf1));
			return (-1);
		}

		s2 = dt_typefile_buildup_struct(tf2, id2);
		if (s2 == NULL) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    dt_typefile_stringof(tf2), type2_name,
			    dt_typefile_error(tf2));
			return (-1);
		}

		memb1 = dt_typefile_struct_next(s1);
		memb2 = dt_typefile_struct_next(s2);

		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		while (memb1 && memb2) {
			if (dt_typefile_typename(tf1,
			    dt_typefile_memb_ctfid(memb1), memb1_name,
			    sizeof(memb1_name)) != (char *)memb1_name) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    dt_typefile_error(tf1));
				return (-1);
			}

			if (dt_typefile_typename(tf2,
			    dt_typefile_memb_ctfid(memb2), memb2_name,
			    sizeof(memb2_name)) != (char *)memb2_name) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    dt_typefile_error(tf2));
				return (-1);
			}

			if (dt_ctf_type_compare(tf1,
			    dt_typefile_memb_ctfid(memb1), tf2,
			    dt_typefile_memb_ctfid(memb2))) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name, memb2_name);
				return (-1);
			}

			memb1 = dt_typefile_struct_next(s1);
			memb2 = dt_typefile_struct_next(s2);
		}

		assert(memb1 == NULL || memb2 == NULL);

		if (memb1 != memb2) {
			fprintf(stderr,
			    "structures %s (%s) and %s (%s) "
			    "don't match\n",
			    type1_name, dt_typefile_stringof(tf1), type2_name,
			    dt_typefile_stringof(tf2));
			return (-1);
		}

		return (0);
	}

	return (0);
}

static int
dt_is_void(char *t_name)
{

	return (strcmp(t_name, "void *") == 0 ||
	    strcmp(t_name, "const void *") == 0);
}

int
dt_type_subtype(dt_typefile_t *tf1, ctf_id_t id1, dt_typefile_t *tf2,
    ctf_id_t id2, int *which)
{
	ctf_id_t kind1, kind2;
	void *memb1, *memb2;
	size_t n_stars1, n_stars2;
	uint32_t size1, size2;
	int isvoid1, isvoid2;
	char memb1_name[4096], memb2_name[4096];
	char type1_name[4096], type2_name[4096];
	void *s1, *s2;

	*which = SUBTYPE_NONE;

	assert(tf1 != NULL);
	assert(tf2 != NULL);

	if (dt_typefile_typename(tf1, id1, type1_name, sizeof(type1_name)) !=
	    (char *)type1_name) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    dt_typefile_error(tf1));
		return (-1);
	}

	if (dt_typefile_typename(tf2, id2, type2_name, sizeof(type2_name)) !=
	    (char *)type2_name) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    dt_typefile_error(tf2));
		return (-1);
	}

	isvoid1 = dt_is_void(type1_name);
	isvoid2 = dt_is_void(type2_name);

	if (isvoid1 && isvoid2) {
		*which = SUBTYPE_EQUAL;
		return (0);
	} else if (isvoid1) {
		*which = SUBTYPE_FST;
		return (0);
	} else if (isvoid2) {
		*which = SUBTYPE_SND;
		return (0);
	}

	kind1 = dt_type_strip_ref(tf1, &id1, &n_stars1);
	kind2 = dt_type_strip_ref(tf2, &id2, &n_stars2);
	/*
	 * In case number of stars in a pointer didn't match.
	 */
	if (n_stars1 != n_stars2) {
		fprintf(stderr,
		    "mismatched pointer %s != %s "
		    "(%zu stars != %zu stars)\n",
		    type1_name, type2_name, n_stars1, n_stars2);
		return (-1);
	}

	/*
	 * We don't want bogus values, functions or floats here.
	 */
	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	/*
	 * For integers, we just want to check if they are compatible and then
	 * pick the one that is larger as the one to use for our storage.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		ctf_encoding_t enc1, enc2;

		if (dt_typefile_encoding(tf1, id1, &enc1) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    dt_typefile_stringof(tf1), dt_typefile_error(tf1));
			return (-1);
		}

		if (dt_typefile_encoding(tf2, id2, &enc2) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    dt_typefile_stringof(tf2), dt_typefile_error(tf2));
			return (-1);
		}

		size1 = dt_typefile_typesize(tf1, id1);
		size2 = dt_typefile_typesize(tf2, id2);

#if 0
		if (enc1.cte_format != enc2.cte_format && size1 == size2) {
			fprintf(stderr,
			    "dt_type_subtype(): both arguments types "
			    "need to have same signedness\n");
			return (-1);
		}
#endif

		if (size1 == size2)
			*which = SUBTYPE_EQUAL;
		else
			*which = size1 > size2 ? SUBTYPE_FST : SUBTYPE_SND;

		return (0);
	}

	/*
	 * We require that arrays are fully compatible
	 */
	if (kind1 == CTF_K_ARRAY && kind2 == CTF_K_ARRAY) {
		if (dt_ctf_type_compare(tf1, id1, tf2, id2))
			return (-1);

		*which = SUBTYPE_EQUAL;
		return (0);
	}

	/*
	 * Since this is C, we do a comparison by name first. If the names don't
	 * match identically, we aren't really interested.
	 *
	 * Note that this is not really a requirement and we could require a
	 * definition of equivalence defined by a bijection which is far more
	 * relaxed, but for now we require that the name matches. This is easily
	 * removed later.
	 */
	if (strcmp(type1_name, type2_name) != 0) {
		fprintf(stderr, "subtyping not possible: %s != %s\n",
		    type1_name, type2_name);
		return (-1);
	}

	/*
	 * Because we've identified that they are matching 1:1 in name, we
	 * expect that they are going to be matching in CTF kind and a few other
	 * things...
	 */
	assert(kind1 == kind2);

	size1 = dt_typefile_typesize(tf1, id1);
	size2 = dt_typefile_typesize(tf2, id2);

	/*
	 * We should never have gotten to this point if we were going to get
	 * CTF_ERR.
	 */
	assert(size1 != CTF_ERR);
	assert(size2 != CTF_ERR);

	if (kind1 == CTF_K_STRUCT) {
		/*
		 * We have a few conditions for subtyping of structs.
		 *
		 * s1 is a subtype of s2 iff:
		 *  (1) sizeof(s1) <= sizeof(s2)
		 *  (2) s1 is a slice of s2 (s1 = s2 up to a point, but s2 has
		 *                           more stuff afterwards)
		 *
		 * We could loosen this restriction quite a bit, but for now
		 * this is sufficient.
		 */

		s1 = dt_typefile_buildup_struct(tf1, id1);
		if (s1 == NULL) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    dt_typefile_stringof(tf1), type1_name,
			    dt_typefile_error(tf1));
			return (-1);
		}

		s2 = dt_typefile_buildup_struct(tf2, id2);
		if (s2 == NULL) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    dt_typefile_stringof(tf2), type2_name,
			    dt_typefile_error(tf2));
			return (-1);
		}

		memb1 = dt_typefile_struct_next(s1);
		memb2 = dt_typefile_struct_next(s2);

		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		while (memb1 && memb2) {
			if (dt_typefile_typename(tf1,
			    dt_typefile_memb_ctfid(memb1), memb1_name,
			    sizeof(memb1_name)) != (char *)memb1_name) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    dt_typefile_error(tf1));
				return (-1);
			}

			if (dt_typefile_typename(tf2,
			    dt_typefile_memb_ctfid(memb2), memb2_name,
			    sizeof(memb2_name)) != (char *)memb2_name) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    dt_typefile_error(tf2));
				return (-1);
			}

			if (dt_ctf_type_compare(tf1,
			    dt_typefile_memb_ctfid(memb1), tf2,
			    dt_typefile_memb_ctfid(memb2))) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name, memb2_name);
				return (-1);
			}

			memb1 = dt_typefile_struct_next(s1);
			memb2 = dt_typefile_struct_next(s2);
		}

		assert(memb1 == NULL || memb2 == NULL);

		if (memb1 == NULL && memb2 != NULL)
			*which = SUBTYPE_FST;
		else if (memb1 != NULL && memb2 == NULL)
			*which = SUBTYPE_SND;
		else
			*which = SUBTYPE_EQUAL;

		return (0);
	} else if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		/*
		 * It doesn't really make sense to support different unions or
		 * enum types. We only check pointwise equality.
		 */
		if (dt_ctf_type_compare(tf1, id1, tf2, id2))
			return (-1);

		*which = SUBTYPE_EQUAL;
		return (0);
	}

	fprintf(stderr, "unknown typing error (%s != %s)\n", type1_name,
	    type2_name);
	return (-1);
}

/*
 * dt_get_class() takes in a buffer containing the type name and returns
 * the internal DTrace class it belongs to (DTC_INT, DTC_BOTTOM, DTC_STRUCT).
 */
int
dt_get_class(dt_typefile_t *tf, ctf_id_t id)
{
	ctf_id_t ot, k;
	char buf[DT_TYPE_NAMELEN];

	ot = -1;
	k = 0;

	if (dt_typefile_typename(tf, id, buf, sizeof(buf)) != ((char *)buf))
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_get_class(%s, %d): failed at "
		    "getting type name: %s",
		    dt_typefile_stringof(tf), id, dt_typefile_error(tf));

	do {

		if ((k = dt_typefile_typekind(tf, id)) == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed getting type (%s) kind: %s", buf,
			    dt_typefile_error(tf));

		if (id == ot)
			break;

		ot = id;
	} while (((id = dt_typefile_reference(tf, id)) != CTF_ERR));

	if (k == CTF_K_INTEGER)
		return (DTC_INT);

	if (k == CTF_K_STRUCT)
		return (DTC_STRUCT);

	return (DTC_BOTTOM);
}

/*
 * dt_type_compare() takes in two IFG nodes and "compares" their types.
 * Specifically, BOTTOM is the smallest element and no matter what it is
 * compared to, it is smaller than it (reflexivity applies). By convention,
 * we check dr1 for a BOTTOM type first and return dn2 if dr1 is BOTTOM
 * regardless of what dn2 is (could be BOTTOM). Both STRUCT and STRING are
 * considered to be greater than INT (because in DIF when we are adding an
 * integer onto a struct pointer or a string, we still expect to use it as
 * a string or a structure, rather than as a number).
 */
int
dt_type_compare(dt_ifg_node_t *dn1, dt_ifg_node_t *dn2)
{
	char buf1[4096] = {0};
	char buf2[4096] = {0};
	int class1, class2;

	class1 = 0;
	class2 = 0;

	if (dn1->din_type == DIF_TYPE_BOTTOM &&
	    dn2->din_type == DIF_TYPE_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "both types are bottom");

	assert(dn1->din_type != DIF_TYPE_BOTTOM ||
	    dn2->din_type != DIF_TYPE_BOTTOM);

	if (dn1->din_type == DIF_TYPE_BOTTOM)
		return (2);

	if (dn2->din_type == DIF_TYPE_BOTTOM)
		return (1);

	assert(dn1->din_type != DIF_TYPE_NONE);
	assert(dn2->din_type != DIF_TYPE_NONE);

	if (dn1->din_type == DIF_TYPE_CTF) {
		if (dt_typefile_typename(dn1->din_tf, dn1->din_ctfid, buf1,
		    sizeof(buf1)) != ((char *)buf1))
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn1->din_ctfid, dt_typefile_error(dn1->din_tf));
	}

	if (dn2->din_type == DIF_TYPE_CTF) {
		if (dt_typefile_typename(dn2->din_tf, dn2->din_ctfid, buf2,
		    sizeof(buf2)) != ((char *)buf2))
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn2->din_ctfid, dt_typefile_error(dn2->din_tf));
	}

	class1 = dn1->din_type == DIF_TYPE_CTF ?
	    dt_get_class(dn1->din_tf, dn1->din_ctfid) :
	    DTC_STRING;
	class2 = dn2->din_type == DIF_TYPE_CTF ?
	    dt_get_class(dn2->din_tf, dn2->din_ctfid) :
	    DTC_STRING;

	if (class1 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_type_compare(): class1 is bottom because of %s", buf1);

	if (class2 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_type_compare(): class2 is bottom because of %s", buf2);

	if (class1 == DTC_STRING && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_STRUCT && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_INT && (class2 == DTC_STRUCT || class2 == DTC_STRING))
		return (2);

	/*
	 * If the types are of the same class, we return the the first type
	 * by convention.
	 */
	if (class1 == DTC_INT && class2 == DTC_INT)
		return (1);

	return (-1);
}

dt_typefile_t *
dt_get_typename_tfcheck(dt_ifg_node_t *n, dt_typefile_t **tfs, size_t ntfs,
    char *buf, size_t bufsize, const char *loc)
{
	dt_typefile_t *tf;
	size_t i;

	for (i = 0; i < ntfs; i++) {
		tf = tfs[i];

		if (n->din_tf == tf)
			break;
	}

	assert(i <= ntfs);

	if (i == ntfs)
		dt_set_progerr(g_dtp, g_pgp,
		    "%s: node %zu' could not find typefile '%s'", loc,
		    n->din_uidx, dt_typefile_stringof(n->din_tf));

	if (dt_typefile_typename(n->din_tf, n->din_ctfid, buf, bufsize) != buf)
		dt_set_progerr(g_dtp, g_pgp,
		    "%s: (%zu) failed getting type name %ld: %s", loc,
		    n->din_uidx, n->din_ctfid, dt_typefile_error(n->din_tf));

	return (tf);
}

void
dt_get_typename(dt_ifg_node_t *n, char *buf, size_t bufsize, const char *loc)
{

	(void) dt_get_typename_tfcheck(n, &n->din_tf, 1, buf, bufsize, loc);
}
