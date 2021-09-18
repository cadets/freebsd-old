#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_lock.h"
#include "dtraced_state.h"

int
init_state(struct dtd_state *s, int ctrlmachine)
{
	int err;

	memset(s, 0, sizeof(struct dtd_state));
	s->sockfd = -1;
	s->ctrlmachine = ctrlmachine;

	if ((err = mutex_init(
	    &s->socklistmtx, NULL, "socklist", CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create sock list mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->sockmtx, NULL, "socket", CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create socket mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistcvmtx, NULL, "joblist condvar", CHECKOWNER_NO)) != 0) {
		dump_errmsg("Failed to create joblist condvar mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistmtx, NULL, "joblist", CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create joblist mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->kill_listmtx, NULL, "kill list", CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create kill list mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->killcvmtx, NULL, "", CHECKOWNER_NO)) != 0) {
		dump_errmsg("Failed to create kill condvar mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->identlistmtx, NULL, "", CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create identlist mutex: %m");
		return (-1);
	}

	if ((err = pthread_cond_init(&s->killcv, NULL)) != 0) {
		dump_errmsg("Failed to create kill list condvar: %m");
		return (-1);
	}

	if ((err = pthread_cond_init(&s->joblistcv, NULL)) != 0) {
		dump_errmsg("Failed to create joblist condvar: %m");
		return (-1);
	}

	if (s->ctrlmachine == 0) {
		s->dtt_fd = open("/dev/dttransport", O_RDWR);
		if (s->dtt_fd == -1) {
			dump_errmsg("Failed to open /dev/dttransport: %m");
			return (-1);
		}
	}

	s->outbounddir = dtd_mkdir(DTRACED_OUTBOUNDDIR, &process_outbound);
	s->inbounddir = dtd_mkdir(DTRACED_INBOUNDDIR, &process_inbound);
	s->basedir = dtd_mkdir(DTRACED_BASEDIR, &process_base);

	s->outbounddir->state = s;
	s->inbounddir->state = s;
	s->basedir->state = s;

	return (0);
}

int
destroy_state(struct dtd_state *s)
{
	int err;
	size_t i;
	char *path;
	struct dtd_joblist *j, *next;

	LOCK(&s->joblistmtx);
	for (j = dt_list_next(&s->joblist); j; j = next) {
		next = dt_list_next(j);
		free(j);
	}
	UNLOCK(&s->joblistmtx);

	if ((err = mutex_destroy(&s->socklistmtx)) != 0) {
		dump_errmsg("Failed to destroy sock list mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->sockmtx)) != 0) {
		dump_errmsg("Failed to destroy socket mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->joblistcvmtx)) != 0) {
		dump_errmsg("Failed to destroy joblist condvar mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->joblistmtx)) != 0) {
		dump_errmsg("Failed to destroy joblist mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->kill_listmtx)) != 0) {
		dump_errmsg("Failed to destroy kill list mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->killcvmtx)) != 0) {
		dump_errmsg("Failed to destroy kill list cv mutex: %m");
		return (-1);
	}

	if ((err = pthread_cond_destroy(&s->killcv)) != 0) {
		dump_errmsg("Failed to destroy kill condvar: %m");
		return (-1);
	}

	if ((err = pthread_cond_destroy(&s->joblistcv)) != 0) {
		dump_errmsg("Failed to destroy joblist condvar: %m");
		return (-1);
	}

	dtd_closedir(s->outbounddir);
	dtd_closedir(s->inbounddir);
	dtd_closedir(s->basedir);

	sem_destroy(&s->socksema);

	destroy_sockfd(s);
	s->sockfd = -1;

	free(s->workers);

	if (s->ctrlmachine == 0) {
		close(s->dtt_fd);
		s->dtt_fd = -1;
	}

	return (0);
}
