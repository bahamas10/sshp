#include <stdlib.h>

#if USE_KQUEUE
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

typedef struct fdwatcher {
#if USE_KQUEUE
	// kqueue
#else
	// epoll
	int epoll_fd;
#endif
} FdWatcher;

FdWatcher *fdwatcher_create();
void fdwatcher_destroy(FdWatcher *);
