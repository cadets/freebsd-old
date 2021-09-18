#ifndef _DTRACED_CONNECTION_H_
#define _DTRACED_CONNECTION_H_

#include <dt_list.h>

struct dtd_state;

typedef struct dtd_fdlist {
	dt_list_t list; /* next element */
	int fd;         /* the actual filedesc */
	int kind;       /* consumer/forwarder */
	uint64_t subs;  /* events that efd subscribed to */
} dtd_fdlist_t;


void *process_consumers(void *);
int  setup_sockfd(struct dtd_state *);
int  destroy_sockfd(struct dtd_state *);

#endif // _DTRACED_CONNECTION_H_
