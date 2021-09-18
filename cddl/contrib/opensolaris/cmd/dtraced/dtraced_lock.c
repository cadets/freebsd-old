#include <sys/param.h>

#include <string.h>

#include "dtraced_errmsg.h"
#include "dtraced_lock.h"

void
LOCK(mutex_t *m)
{
	int err;

	err = pthread_mutex_lock(&(m)->_m);
	if (err != 0) {
		dump_errmsg("Failed to lock mutex: %m");
		exit(EXIT_FAILURE);
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&(m)->_owner, pthread_self());
}

void
UNLOCK(mutex_t *m)
{
	int err;

	if (m->_checkowner != CHECKOWNER_NO) {
		if (OWNED(m) == 0) {
			dump_errmsg(
			    "attempted unlock of %s which is not owned",
			    m->_name);
			dump_backtrace();
			exit(EXIT_FAILURE);
		}

		assert(OWNED(m));
		if (atomic_load(&m->_owner) != pthread_self()) {
			dump_errmsg(
			    "attempted unlock of %s by thread %p (!= %p)",
			    m->_name, pthread_self(), atomic_load(&m->_owner));
			dump_backtrace();
			exit(EXIT_FAILURE);
		}
	}

	err = pthread_mutex_unlock(&(m)->_m);
	if (err != 0) {
		dump_errmsg("Failed to unlock mutex: %m");
		return;
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&m->_owner, NULL);
}


int
mutex_init(mutex_t *m, const pthread_mutexattr_t *restrict attr,
    const char *name, int checkowner)
{
	size_t l;

	assert(m != NULL);

	if (name == NULL)
		return (-1);

	l = strlcpy(m->_name, name, MAXPATHLEN);
	if (l >= MAXPATHLEN)
		return (-1);

	m->_checkowner = checkowner;

	atomic_store(&m->_owner, NULL);
	return (pthread_mutex_init(&m->_m, attr));
}

int
mutex_destroy(mutex_t *m)
{

	assert(atomic_load(&m->_owner) == NULL);
	return (pthread_mutex_destroy(&m->_m));
}

pthread_mutex_t *
pmutex_of(mutex_t *m)
{

	return (&m->_m);
}

