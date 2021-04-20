
typedef struct fdwatcher {
#if USE_KQUEUE
	// kqueue
	int kq;
#else
	// epoll
	int epoll_fd;
#endif
} FdWatcher;

FdWatcher *fdwatcher_create();
int fdwatcher_add(FdWatcher *fdw, int fd, void *ptr);
int fdwatcher_remove(FdWatcher *fdw, int fd);
int fdwatcher_wait(FdWatcher *fdw, void **events, int nevents);
void fdwatcher_destroy(FdWatcher *fdw);
