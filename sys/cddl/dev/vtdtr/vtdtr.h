#ifndef _DEV_VTDTR_H_
#define _DEV_VTDTR_H_

#include <sys/vtdtr.h>

void vtdtr_enqueue(struct vtdtr_event *);
void vtdtr_enqueue_install(int);
void vtdtr_enqueue_uninstall(int);
void vtdtr_enqueue_reconf(size_t, char *);
void vtdtr_enqueue_go(void);
void vtdtr_enqueue_stop(void);
void vtdtr_enqueue_start_adjusting(size_t, char *);
void vtdtr_enqueue_probeid_adjust(size_t, char *, int,
				  char *, char *, char *, char *);
void vtdtr_enqueue_adjust_commit(size_t, char *);

#endif
