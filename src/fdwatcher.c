/*
 * FdWatcher - File Descriptor Watcher Interface.
 *
 * See the accompanying header file for more information.
 */

/*
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: April 21, 2021
 * License: MIT
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#if USE_KQUEUE
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#include "fdwatcher.h"

/*
 * Return event interface type as a string.
 */
const char *
fdwatcher_ev_interface(void)
{
#if USE_KQUEUE
	return "kqueue";
#else
	return "epoll";
#endif
}

/*
 * Create an FdWatcher object.
 */
FdWatcher *
fdwatcher_create(void)
{
	FdWatcher *fdw = malloc(sizeof (FdWatcher));

	if (fdw == NULL) {
		return NULL;
	}

#if USE_KQUEUE
	fdw->kq = kqueue();
	if (fdw->kq == -1) {
		goto fail;
	}
#else
	fdw->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (fdw->epoll_fd == -1) {
		goto fail;
	}
#endif

	return fdw;

fail:
	free(fdw);
	return NULL;
}

/*
 * Add a file descriptor to the watchlist.
 */
int
fdwatcher_add(FdWatcher *fdw, int fd, void *ptr)
{
	int ret = -1;

#if USE_KQUEUE
	struct kevent ev;

	EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ev.udata = ptr;

	ret = kevent(fdw->kq, &ev, 1, NULL, 0, NULL);
#else
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.ptr = ptr;

	ret = epoll_ctl(fdw->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
#endif

	return ret;
}

/*
 * Remove a file descriptor from the watchlist.
 */
int
fdwatcher_remove(FdWatcher *fdw, int fd)
{
	int ret = -1;

#if USE_KQUEUE
	struct kevent ev;

	EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

	ret = kevent(fdw->kq, &ev, 1, NULL, 0, NULL);
#else
	ret = epoll_ctl(fdw->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
#endif

	return ret;
}

/*
 * Wait for fd events.
 */
int
fdwatcher_wait(FdWatcher *fdw, void **events, int nevents, int timeout)
{
	int num_events = -1;

#if USE_KQUEUE
	// kqueue requires a timespec for the timeout.
	struct kevent kq_events[nevents];
	struct timespec ts;
	struct timespec *tsp = NULL;

	if (timeout != -1) {
		// timeout is milleseconds, convert to timespec
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = timeout % 1000 * 1000 * 1000;
		tsp = &ts;
	}

	num_events = kevent(fdw->kq, NULL, 0, kq_events, nevents, tsp);
	for (int i = 0; i < nevents; i++) {
		struct kevent ev = kq_events[i];
		events[i] = ev.udata;
	}
#else
	struct epoll_event ep_events[nevents];

	num_events = epoll_wait(fdw->epoll_fd, ep_events, nevents, timeout);
	for (int i = 0; i < nevents; i++) {
		struct epoll_event ev = ep_events[i];
		events[i] = ev.data.ptr;
	}
#endif

	return num_events;
}

/*
 * Destroy an FdWatcher object.
 */
void
fdwatcher_destroy(FdWatcher *fdw)
{
	if (fdw == NULL) {
		return;
	}

#if USE_KQUEUE
	assert(fdw->kq >= 0);
	close(fdw->kq);
#else
	assert(fdw->epoll_fd >= 0);
	close(fdw->epoll_fd);
#endif

	free(fdw);
}
