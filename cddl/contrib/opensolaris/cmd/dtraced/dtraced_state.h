#ifndef _DTRACED_STATE_H_
#define _DTRACED_STATE_H_

#include <dt_list.h>
#include <pthread.h>
#include <stdatomic.h>

#include "dtraced_directory.h"
#include "dtraced_lock.h"

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
struct dtd_state {
	int ctrlmachine;        /* is this a control machine? */

	dtd_dir_t *inbounddir;  /* /var/ddtrace/inbound */
	dtd_dir_t *outbounddir; /* /var/ddtrace/outbound */
	dtd_dir_t *basedir;     /* /var/ddtrace/base */

	pthread_t inboundtd;    /* inbound monitoring thread */
	pthread_t basetd;       /* base monitoring thread */
	/* the outbound monitoring thread is the main thread */

	/*
	 * Sockets.
	 */
	mutex_t socklistmtx; /* mutex fos sockfds */
	dt_list_t sockfds;   /* list of sockets we know about */

	/*
	 * Configuration socket.
	 */
	mutex_t sockmtx;  /* config socket mutex */
	pthread_t socktd; /* config socket thread */
	int sockfd;       /* config socket filedesc */
	sem_t socksema;   /* config socket semaphore */

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;             /* dttransport filedesc */
	pthread_t dtt_listentd; /* read() on dtt_fd */
	pthread_t dtt_writetd;  /* write() on dtt_fd */

	/*
	 * Thread pool management.
	 */
	pthread_t *workers;       /* thread pool for the joblist */
	mutex_t joblistcvmtx;     /* joblist condvar mutex */
	pthread_cond_t joblistcv; /* joblist condvar */
	mutex_t joblistmtx;       /* joblist mutex */
	dt_list_t joblist;        /* the joblist itself */

	/*
	 * Children management.
	 */
	pthread_t killtd;      /* handle sending kill(SIGTERM) to the guest */
	mutex_t kill_listmtx;  /* mutex of the kill list */
	mutex_t killcvmtx;     /* kill list condvar mutex */
	dt_list_t kill_list;   /* a list of pids to kill */
	pthread_cond_t killcv; /* kill list condvar */
	pthread_t reaptd;      /* handle reaping children */

	/*
	 * Consumer threads
	 */
	pthread_t consumer_listentd; /* handle consumer messages */
	pthread_t consumer_writetd;  /* send messages to consumers */

	_Atomic int shutdown;        /* shutdown flag */
	int dirfd;                   /* /var/ddtrace */
	int nosha;                   /* do we want to checksum? */
	struct pidfh *pid_fileh;     /* lockfile */
	int kq_hdl;                  /* event loop kqueue */

	dt_list_t identlist;         /* list of identifiers */
	mutex_t identlistmtx;        /* mutex protecting the ident list */
};

int init_state(struct dtd_state *);
int destroy_state(struct dtd_state *);

#endif // _DTRACED_STATE_H_
