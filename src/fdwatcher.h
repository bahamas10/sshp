/*
 * FdWatcher - File Descriptor Watcher Interface.
 *
 * Watch File Descriptors for readable events.  This interface wraps epoll or
 * kqueue to expose a higher-level abstraction to watch for fds to become
 * available (ready to be read).  A simple example looks like this:
 *
 * ```
 * #include <err.h>
 * #include <stdio.h>
 *
 * #include "fdwatcher.h"
 *
 * // can store anything in this
 * struct fd_ev {
 *	int fd;
 * };
 *
 * int
 * main()
 * {
 *	struct fd_ev tevent; // trigger event to watch for
 *	void *events[5];     // events seen by fdwatcher_wait
 *	FdWatcher *fdw = fdwatcher_create();
 *
 *	if (fdw == NULL) {
 *		err(3, "fdwatcher_create");
 *	}
 *
 *	tevent.fd = 0;
 *	if (fdwatcher_add(fdw, tevent.fd, &tevent) == -1) {
 *		err(3, "fdwatcher_add stdin");
 *	}
 *
 *	while (1) {
 *		int nevents = fdwatcher_wait(fdw, events, 5, -1);
 *		printf("fdwatcher_wait saw %d events\n", nevents);
 *		for (int i = 0; i < nevents; i++) {
 *			struct fd_ev *event = events[i];
 *			printf("-> event seen on fd %d\n", event->fd);
 *		}
 *		break; // just for this example
 *	}
 *
 *	fdwatcher_destroy(fdw);
 *	return 0;
 * }
 * ```
 *
 * yields:
 *
 * $ echo hello | ./test-fdwatcher
 * fdwatcher_wait saw 1 events
 * -> event seen on fd 0
 * $
 */

/*
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: April 21, 2021
 * License: MIT
 */

/*
 * FdWatcher Opaque object.
 *
 * This type should not be created manually, but instead created with
 * `fdwatcher_create()`.  This object will be used for the `fdwatcher_*`
 * functions below.
 */
typedef struct fdwatcher {
#if USE_KQUEUE
	// kqueue
	int kq;
#else
	// epoll
	int epoll_fd;
#endif
} FdWatcher;

/*
 * Return the event interface that is being used.  This will return a string
 * like: "epoll" or "kqueue" depending on how it was compiled.
 */
const char *fdwatcher_ev_interface(void);

/*
 * Create an FdWatcher object.  This object will be passed to the rest of the
 * functions defined below.  This object will be allocated on the heap and
 * must be destroyed with `fdwatcher_destroy` when done.
 *
 * Returns NULL and sets errno on error.
 */
FdWatcher *fdwatcher_create(void);

/*
 * Add a file descriptor with the given user data (called `ptr`) to the watch
 * list.  The `ptr` data can be anything - this data is opaque to this
 * interface and will be returned back to the caller when an event is seen with
 * `fdwatcher_wait`.
 *
 * Returns -1 and sets errno on error.
 */
int fdwatcher_add(FdWatcher *fdw, int fd, void *ptr);

/*
 * Remove a file descriptor from the watchlist.
 *
 * Returns -1 and sets errno on error.
 */
int fdwatcher_remove(FdWatcher *fdw, int fd);

/*
 * Wait for events and return when one or more are seen.  `events` and
 * `nevents` are an array of pointers (type agnostic) and the number of
 * pointers in the array to fill.  `timeout` is an optional timeout (in
 * milliseconds) to wait for events, set to -1 to wait indefinitely.
 *
 * This function will return the number of events that were seen.  For each
 * event that was seen, its user data pointer (set in `fdwatcher_add`) will be
 * set on the `events` argument (up to `nevents`).
 *
 * Returns -1 and sets errno on error.
 */
int fdwatcher_wait(FdWatcher *fdw, void **events, int nevents, int timeout);

/*
 * Destroy the FdWatcher object.  This will close any underlying file
 * descriptor created by epoll or kqueue, and free the memory allocated for the
 * FdWatcher object itself.
 */
void fdwatcher_destroy(FdWatcher *fdw);
