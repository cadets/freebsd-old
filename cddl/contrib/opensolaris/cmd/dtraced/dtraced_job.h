#ifndef _DTRACED_JOB_H_
#define _DTRACED_JOB_H_

#include <sys/event.h>

#include <dt_list.h>

#include "dtraced_directory.h"

typedef struct dtd_joblist {
	dt_list_t list;       /* next element */
	int       job;        /* job kind */
	int       connsockfd; /* which socket do we send this on? */
#define NOTIFY_ELFWRITE    1
#define KILL               2
#define READ_DATA          3
#define JOB_LAST           3

	union {
		struct {
			size_t    pathlen; /* how long is path? */
			char      *path;   /* path to file (based on dir) */
			dtd_dir_t *dir;    /* base directory of path */
			int       nosha;   /* do we want to checksum? */
		} notify_elfwrite;

		struct {
			pid_t    pid;   /* pid to kill */
			uint16_t vmid;  /* vmid to kill the pid on */
		} kill;

		struct {
		} read;
	} j;
} dtd_joblist_t;

int  dispatch_event(struct dtd_state *, struct kevent *);
void *process_joblist(void *);

#endif // _DTRACED_JOB_H_
