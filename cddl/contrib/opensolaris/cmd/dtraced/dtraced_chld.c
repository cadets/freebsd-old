#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_chld.h"
#include "dtraced_lock.h"
#include "dtraced_state.h"

void *
manage_children(void *_s)
{
	struct dtd_state *s = (struct dtd_state *)_s;
	pidlist_t *kill_entry;
	int status;

	while (atomic_load(&s->shutdown) == 0) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		LOCK(&s->killcvmtx);
		LOCK(&s->kill_listmtx);
		while (dt_list_next(&s->kill_list) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			UNLOCK(&s->kill_listmtx);
			WAIT(&s->killcv, pmutex_of(&s->killcvmtx));
			LOCK(&s->kill_listmtx);
		}
		UNLOCK(&s->kill_listmtx);
		UNLOCK(&s->killcvmtx);

		if (atomic_load(&s->shutdown) == 1)
			pthread_exit(_s);

		LOCK(&s->kill_listmtx);
		kill_entry = dt_list_next(&s->kill_list);
		if (kill_entry == NULL) {
			fprintf(stderr, "kill message pulled from under us");
			UNLOCK(&s->kill_listmtx);
			continue;
		}

		dt_list_delete(&s->kill_list, kill_entry);
		UNLOCK(&s->kill_listmtx);

		if (kill(kill_entry->pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH) {
				dump_errmsg("pid %d does not exist",
				    kill_entry->pid);
			}
		}

		free(kill_entry);
	}

	return (_s);
}

void *
reap_children(void *_s)
{
	struct dtd_state *s = _s;
	int status, rv;

	for (;;) {
		sleep(30);
		do {
			rv = waitpid(-1, &status, WNOHANG);
		} while (rv != -1 && rv != 0);

		if (atomic_load(&s->shutdown) != 0)
			pthread_exit(_s);
	}
}

