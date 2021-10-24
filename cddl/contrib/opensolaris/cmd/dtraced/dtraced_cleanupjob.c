#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced.h"
#include "dtraced_cleanupjob.h"
#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

void
handle_cleanup(struct dtd_state *s, struct dtd_joblist *curjob)
{
	int fd, _send;
	dtraced_hdr_t header;
	size_t hdrlen, buflen, i;
	ssize_t r;
	__cleanup(releasefd) dtraced_fd_t *dfd = curjob->connsockfd;
	__cleanup(freep) unsigned char *msg = NULL;
	__cleanup(freep) char **entries = curjob->j.cleanup.entries;
	size_t n_entries = curjob->j.cleanup.n_entries;
	
	fd = dfd->fd;
	dump_debugmsg("    CLEANUP to %d", fd);
	assert(fd != -1);

	hdrlen = DTRACED_MSGHDRSIZE;
	DTRACED_MSG_TYPE(header) = DTRACED_MSG_CLEANUP;
	DTRACED_MSG_NUMENTRIES(header) = curjob->j.cleanup.n_entries;

	if (send(fd, &hdrlen, sizeof(hdrlen), 0) < 0) {
		if (errno != EPIPE)
			dump_errmsg("Failed to write to %d (%zu): %m",
			    fd, hdrlen);
		return;
	}

	if ((r = send(fd, &header, hdrlen, 0)) < 0) {
		if (errno != EPIPE)
			dump_errmsg("Failed to write to %d: %m", fd);
		return;
	}

	_send = 1;
	for (i = 0; i < n_entries; i++) {
		buflen = _send ? strlen(entries[i]) + 1 : 0;

		/*
		 * We don't want to exit here because we actually want to free
		 * up all the entries and process the job. If we returned from
		 * the function here, we would have a memory leak. So instead,
		 * we simply don't send anything if we fail once, and free up
		 * all the entries.
		 */
		if (_send && send(fd, &buflen, sizeof(buflen), 0) < 0) {
			if (errno != EPIPE)
				dump_errmsg("Failed to write to %d: %m", fd);
			_send = 0;
		}

		if (_send && send(fd, entries[i], buflen, 0) < 0) {
			if (errno != EPIPE)
				dump_errmsg("Failed to write to %d: %m", fd);
			_send = 0;
		}

		free(entries[i]);
	}

	if (reenable_fd(s->kq_hdl, fd, EVFILT_WRITE))
		dump_errmsg("%s(): reenable_fd() failed with: %m", __func__);
}
