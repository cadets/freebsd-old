#ifndef _DT_TYPING_HELPERS_H_
#define _DT_TYPING_HELPERS_H_

#include <sys/types.h>
#include <sys/ctf.h>

#include <dtrace.h>
#include <dt_program.h>
#include <dt_typefile.h>

extern dtrace_hdl_t *g_dtp;
extern dtrace_prog_t *g_pgp;

extern ctf_id_t dt_type_strip_ref(dt_typefile_t *, ctf_id_t *, size_t *);
extern ctf_id_t dt_type_strip_typedef(dt_typefile_t *, ctf_id_t *);
extern int dt_ctf_type_compare(dt_typefile_t *, ctf_id_t, dt_typefile_t *,
    ctf_id_t);
extern int dt_type_subtype(dt_typefile_t *, ctf_id_t, dt_typefile_t *, ctf_id_t,
    int *);
extern int dt_get_class(dt_typefile_t *, char *);
extern int dt_type_compare(dt_ifg_node_t *, dt_ifg_node_t *);

#endif /* _DT_TYPING_HELPERS_H_ */
