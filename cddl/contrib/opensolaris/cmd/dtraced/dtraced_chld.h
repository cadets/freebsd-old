#ifndef _DTRACE_CHLD_H_
#define _DTRACE_CHLD_H_

#include <sys/types.h>

#include <dt_list.h>

typedef struct pidlist {
	dt_list_t list; /* next element */
	pid_t pid;
} pidlist_t;

void *manage_children(void *);
void *reap_children(void *);

#endif // _DTRACE_CHLD_H_
