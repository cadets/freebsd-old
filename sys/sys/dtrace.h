#ifndef _SYS_DTRACE_H_
#define _SYS_DTRACE_H_

__BEGIN_DECLS
int dt_probe(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
__END_DECLS

#endif
