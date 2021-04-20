#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#if USE_KQUEUE
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#include "fdwatcher.h"

FdWatcher *
fdwatcher_create()
{
	FdWatcher *fdw = malloc(sizeof (FdWatcher));

	if (fdw == NULL) {
		return NULL;
	}

#if USE_KQUEUE
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

int
fdwatcher_add(FdWatcher *fdw, int fd, void *ptr)
{
#if USE_KQUEUE
#else
	struct epoll_event ev;

        ev.events = EPOLLIN;
        ev.data.ptr = ptr;

        if (epoll_ctl(fdw->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		return -1;
        }
#endif
	return 0;
}

int
fdwatcher_remove(FdWatcher *fdw, int fd)
{
#if USE_KQUEUE
#else
	return epoll_ctl(fdw->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
#endif
}

int
fdwatcher_wait(FdWatcher *fdw, void **events, int nevents)
{
	fdw = fdw;
	events = events;
	nevents = nevents;
	int timeout = -1;
	int num_events = -1;
#if USE_KQUEUE
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

void
fdwatcher_destroy(FdWatcher *fdw)
{
	if (fdw == NULL) {
		return;
	}

#if USE_KQUEUE
#else
	assert(fdw->epoll_fd >= 0);
	close(fdw->epoll_fd);
#endif

	free(fdw);
}
