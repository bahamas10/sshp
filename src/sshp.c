/*
 * sshp: Parallel SSH Executor.
 *
 * ----------------------------------------------------------------------------
 *
 * Synopsis
 *
 * sshp manages multiple ssh processes and handles coalescing their output.
 * By default, sshp will read a file of newline-separated hostnames or IPs and
 * fork ssh subprocesses for them, redirecting the stdout and stderr
 * streams of the child line-by-line to stdout of `sshp` itself.
 *
 * For more information on program usage, see the usage message of this
 * program as well as the included README.md file or sshp(1) manpage. This
 * block comment will focus mainly on the implementation details of sshp and
 * not the operator usage (unless relevant).
 *
 * From a high level sshp works by doing the following:
 *
 * 1. Parse arguments (in function `parse_arguments`).
 * 2. Read hosts file input (in function `parse_hosts`).
 * 3. Start the "Main loop" (in function `main_loop`).
 *   a. Loop the hosts and create subprocesses as required.
 *     1. Create pipes for child stdio.
 *     2. Add the pipes to FdWatcher to watch for events.
 *   b. Process fd events for any subprocess stdio pipes.
 *     1. Read the data until done or EWOULDBLOCK.
 *     2. Check if all stdio streams are done.
 *       a. Reap the process if all stdio streams are done.
 * 4. Clean up and exit.
 *
 * Note that all of sshp works in a single thread and relies on FdWatcher and
 * non-blocking fd reads to handle data as it comes in.
 *
 * Each child process will have one or two pipe(s) created to capture their
 * output.  These fds will be added to fdwatcher to watch for any events
 * (child output), and `fdwatcher_wait` will be invoked to react to new data.
 * When all the stdio pipes for a single child process have finished, (1) the
 * fd will be closed, (2) the fd will be unregistered from FdWatcher, and (3)
 * waitpid will be called on the child to reap it and capture its exit status.
 *
 * ----------------------------------------------------------------------------
 *
 * Program Modes
 *
 * sshp has 3 modes of execution:
 *
 * - line mode (line-by-line output, default).
 * - group mode (grouped by hostname output, `-g`).
 * - join mode (grouped by unique output, `-j`).
 *
 * The first 2 modes, line and group, operate in largely the same way,
 * differing only in how data is buffered from the child processes and
 * printed to the screen.  Line mode buffers the data line-by-line, whereas
 * group mode does no buffering at all and prints the data once it is read from
 * the child.
 *
 * The last mode, join, however, buffers *all* of the data from all of the child
 * processes and outputs once all processes have finished.  Instead of grouping
 * the output by host, it is grouped by the output itself to show which hosts
 * had the same output.
 *
 * ----------------------------------------------------------------------------
 *
 * Structures
 *
 * There are 3 types (structs) defined for use by sshp:
 *
 * 1. Host.
 * 2. ChildProcess.
 * 3. FdEvent.
 *
 * All 3 types follow the convention of having a `<name>_create` and
 * `<name>_destroy` function to allocate and free the object created.
 *
 * - Host
 *
 * The Host type represents a single host that should be ssh'd into.  Each line
 * in the hosts file that is passed in via stdin or `-f` will have a
 * corresponding Host object created.  The Host type is created to be a
 * linked-list, retaining a pointer to "next", which represents the next host
 * that was read in.  As files are read in by `parse_hosts` a new Host is
 * created and added to the end of the linked-list.  This way, the order of the
 * list will match the order of the input file.
 *
 * - ChildProcess
 *
 * The ChildProcess type represents a single child process that should be
 * executed.  This is responsible for storing information for and about the
 * child such as the stdio pipe fds, the exit code (once available), current
 * state, etc.  A ChildProcess starts in the "ready" state and goes through
 * the following stages:
 *
 * 1. CP_STATE_READY ("ready").
 * 2. CP_STATE_RUNNING ("running").
 * 3. CP_STATE_DONE ("done").
 *
 * - FdEvent
 *
 * The FdEvent type represents a single file descriptor and its corresponding
 * Host object.  This struct will be given to FdWatcher, which in turn will be
 * given back to us whenever there is an event seen.  This allows for
 * connecting the fd that had the event to the Host and ChildProcess that
 * corresponds to it.
 *
 * The relationship of all of the objects is illustrated below:
 *
 * static Host *hosts;
 *                |
 *   +------------+
 *   |
 *   |   +--------------+       +--------------+
 *   |   |              |       |              |
 *   |   | ChildProcess |       | ChildProcess |
 *   |   |              |       |              |
 *   |   +--------------+       +--------------+
 *   |      ^                      ^
 *   |      |                      |
 *   |      | (owner)              | (owner)
 *   |      |                      |
 *   |   +-----------+          +-----------+
 *   |   |           | ->next   |           |  ->next        ->next
 *   +-> | Host      |--------> | Host      | --------> ... --------> NULL
 *       |           |          |           |
 *       +-----------+          +-----------+
 *          ^                      ^
 *          |                      |
 *          | (reference)          | (reference)
 *          |                      |
 *       +-----------+          +-----------+
 *       |           |          |           |
 *       | FdEvent   |          | FdEvent   |
 *       |           |          |           |
 *       +-----------+          +-----------+
 *
 * The Host objects will be created first in the execution of sshp and stored
 * in a linked-list that is globally accessible as the variable "hosts".  Each
 * Host object "owns" a ChildProcess object - meaning that when a Host object
 * is created a corresponding ChildProcess object will be created with it.
 * Simply put: `host_create` will handle calling `child_process_create` and
 * `host_destroy` will handle calling `child_process_destroy` - a ChildProcess
 * should never need to be created manually.  These objects will be created at
 * the beginning of execution and destroyed right before process exit.
 *
 * The FdEvent objects will be created when file descriptors are added to
 * FdWatcher and will be destroyed when the fd has closed and has had its final
 * event.  Each FdEvent object will have a pointer to its corresponding Host
 * object, but this will just be a reference.  This means that destroying an
 * FdEvent will not result in the connected Host object being destroyed.
 *
 * ----------------------------------------------------------------------------
 *
 * Signals
 *
 * sshp captures the 3 following signals:
 *
 * - SIGTERM
 * - SIGINT
 * - SIGUSR1
 *
 * SIGUSR1 prints a status message (similar to dd(1)) to stdout.  This includes
 * how many children have ran, are running, and are waiting to run, as well as
 * the PIDs and hostnames for any currently running children.
 *
 * SIGTERM and SIGINT both result in the same actions being taken: all running
 * child processes are killed via SIGTERM and the program exits with code 4.
 * There may be a better way to take care of this situation (killing all
 * outstanding children in the event of an early process death) - if so, this
 * code should be updated.
 *
 * ----------------------------------------------------------------------------
 *
 *  Exit Codes
 *
 *  sshp will exit with the following codes:
 *
 *  0: Everything worked and all child processes exited successfully.
 *  1: Everything worked but 1 or more children exited with a non-zero code.
 *  2: Incorrect usage - the user supplied something incorrect preventing sshp
 *     from being able to run (unknown options, invalid host file, etc.).
 *  3: Program failure - the program experienced some failing in the system
 *     preventing `sshp` from being able to run (`malloc` failure, `epoll`
 *     failure, etc.).
 *  4: sshp killed by SIGTERM or SIGINT.
 *  *: Anything else - probably a blown assertion.
 *
 */

/*
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: March 26, 2021
 * License: MIT
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fdwatcher.h"

// app details
#define PROG_NAME	"sshp"
#define PROG_VERSION	"v1.1.3"
#define PROG_FULL_NAME	"Parallel SSH Executor"
#define PROG_SOURCE	"https://github.com/bahamas10/sshp"
#define PROG_LICENSE	"MIT License"

// FdWatcher options
#define FDW_MAX_EVENTS		50
#define FDW_WAIT_TIMEOUT	-1

// maximum number of arguments for a child process
#define MAX_ARGS	256

// max characters to process in line and join mode respectively
#define DEFAULT_MAX_LINE_LENGTH		(1 * 1024) // 1k
#define DEFAULT_MAX_OUTPUT_LENGTH	(8 * 1024) // 8k

// pipe ends
#define PIPE_READ_END	0
#define PIPE_WRITE_END	1

// ANSI color codes
#define COLOR_BLACK	"\033[0;30m"
#define COLOR_RED	"\033[0;31m"
#define COLOR_GREEN	"\033[0;32m"
#define COLOR_YELLOW	"\033[0;33m"
#define COLOR_BLUE	"\033[0;34m"
#define COLOR_MAGENTA	"\033[0;35m"
#define COLOR_CYAN	"\033[0;36m"
#define COLOR_WHITE	"\033[0;37m"
#define COLOR_RESET	"\033[0m"

// printf-like function that runs if "debug" mode is enabled
#define DEBUG(...) { \
	if (opts.debug) { \
		printf("[%s%s%s] ", colors.cyan, PROG_NAME, colors.reset); \
		printf(__VA_ARGS__); \
	} \
}

/*
 * Program modes of execution.
 */
enum ProgMode {
	MODE_LINE = 0,		// line mode, default
	MODE_GROUP,		// group mode, `-g` or `--group`
	MODE_JOIN		// join mode, `-j` or `--join`
};

/*
 * Pipe types.
 */
enum PipeType {
	PIPE_STDOUT = 1,	// stdout pipe
	PIPE_STDERR,		// stderr pipe
	PIPE_STDIO		// both stdout and stderr (used in join mode)
};

/*
 * ChildProcess state.
 */
enum CpState {
	CP_STATE_READY = 0,
	CP_STATE_RUNNING,
	CP_STATE_DONE
};

/*
 * A struct that represents a single child process.
 *
 * - stdout_fd and stderr_fd are used in group and line mode.
 * - stdio_fd represents both output streams and is used in join mode, as well
 *   as the buffer object to store the output.
 */
typedef struct child_process {
	pid_t pid;		// child pid, -1 = hasn't started
	int stdout_fd;		// stdout fd, -1 = hasn't started, -2 = closed
	int stderr_fd;		// stderr fd, -1 = hasn't started, -2 = closed
	int stdio_fd;		// stdio fd,  -1 = hasn't started, -2 = closed
	char *output;		// output buffer (used by join mode)
	int output_idx;		// output index (used by join mode)
	int exit_code;		// exit code, -1 = hasn't exited
	long started_time;	// monotonic time (in ms) when child forked
	long finished_time;	// monotonic time (in ms) when child reaped
	enum CpState state;	// process state, defaults to CP_STATE_READY
} ChildProcess;

/*
 * A struct that represents a single host (as a linked-list).
 */
typedef struct host {
	char *name;		// host name
	ChildProcess *cp;	// child process
	struct host *next;	// next Host in the list
} Host;

/*
 * Wrapper struct for use when an fd sees an event.
 */
typedef struct fd_event {
	Host *host;		// related Host struct
	int fd;			// fd number
	char *buffer;		// buffer used by line and join mode
	int offset;		// buffer offset used as noted above
	enum PipeType type;	// type of fd this event represents
} FdEvent;

// Linked-list of Hosts
static Host *hosts = NULL;

// Command to execute
static char **remote_command = {NULL};

// Base SSH Command
static char *base_ssh_command[MAX_ARGS] = {NULL};

// FdWatcher instance
static FdWatcher *fdw = NULL;

// If a newline was printed (used for group mode only)
static bool newline_printed = true;

// If stdout is a tty
static bool stdout_isatty;

// CLI options for getopt_long
static char *short_options = "+ac:def:ghi:jl:m:no:p:qstvx:";
static struct option long_options[] = {
	{"max-line-length", required_argument, NULL, 1000},
	{"max-output-length", required_argument, NULL, 1001},
	{"anonymous", no_argument, NULL, 'a'},
	{"color", required_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"exit-codes", no_argument, NULL, 'e'},
	{"file", required_argument, NULL, 'f'},
	{"group", no_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"identity", required_argument, NULL, 'i'},
	{"join", no_argument, NULL, 'j'},
	{"login", required_argument, NULL, 'l'},
	{"max-jobs", required_argument, NULL, 'm'},
	{"dry-run", no_argument, NULL, 'n'},
	{"option", required_argument, NULL, 'o'},
	{"port", required_argument, NULL, 'p'},
	{"quiet", no_argument, NULL, 'q'},
	{"silent", no_argument, NULL, 's'},
	{"trim", no_argument, NULL, 't'},
	{"version", no_argument, NULL, 'v'},
	{"exec", required_argument, NULL, 'x'},
	{NULL, 0, NULL, 0}
};

// options set via CLI opts
static struct opts {
	// user options (program)
	bool anonymous;		// -a, --anonymous
	char *color;		// -c, --color <on|off|auto>
	bool debug;		// -d, --debug
	bool exit_codes;	// -e, --exit-codes
	char *file;		// -f, --file <file>
	bool group;		// -g, --group
	bool join;		// -j, --join
	int max_jobs;		// -m, --max-jobs <num>
	bool dry_run;		// -n, --dry-run
	char *port;		// -p, --port <port>
	bool silent;		// -s, --silent
	bool trim;		// -t, --trim
	int max_line_length;	// --max-line-length <num>
	int max_output_length;	// --max-output-length <num>

	// user options (passed directly to ssh)
	char *identity;		// -i, --ident <file>
	char *login;		// -l, --login <name>
	bool quiet;		// -q, --quiet

	// derived options
	enum ProgMode mode;	// set by program based on `-j` or `-g`
} opts;

// colors to use when printing if coloring is enabled
static struct colors {
	char *black;
	char *blue;
	char *cyan;
	char *green;
	char *magenta;
	char *red;
	char *reset;
	char *white;
	char *yellow;
} colors;

/*
 * Print the usage message to the given filestream.
 */
static void
print_usage(FILE *s)
{
	const char *grn = colors.green;
	const char *ylw = colors.yellow;
	const char *mag = colors.magenta;
	const char *rst = colors.reset;

	// print banner
	fprintf(s, "%s        _         %s\n", mag, rst);
	fprintf(s, "%s  _____| |_  _ __ %s   ", mag, rst);
	fprintf(s, "%s %s (%s)%s\n", grn, PROG_FULL_NAME, PROG_VERSION, rst);
	fprintf(s, "%s (_-<_-< ' \\| '_ \\%s   ", mag, rst);
	fprintf(s, "%s Source: %s%s\n", grn, PROG_SOURCE, rst);
	fprintf(s, "%s /__/__/_||_| .__/%s   ", mag, rst);
	fprintf(s, "%s Compiled: %s %s (using %s)%s\n", grn, __DATE__,
	    __TIME__, fdwatcher_ev_interface(), rst);
	fprintf(s, "%s            |_|   %s   ", mag, rst);
	fprintf(s, "%s %s%s\n", grn, PROG_LICENSE, rst);
	fprintf(s, "\n");
	fprintf(s, "Parallel ssh with streaming output.\n");
	fprintf(s, "\n");
	// usage
	fprintf(s, "%sUSAGE:%s\n", ylw, rst);
	fprintf(s, "%s    %s [-m maxjobs] [-f file] command ...%s\n",
	    grn, PROG_NAME, rst);
	fprintf(s, "\n");
	// examples
	fprintf(s, "%sEXAMPLES:%s\n", ylw, rst);
	fprintf(s, "    ssh into a list of hosts passed via stdin and get ");
	fprintf(s, "the output of %suname -v%s.\n", grn, rst);
	fprintf(s, "\n");
	fprintf(s, "%s      %s uname -v < hosts%s\n", grn, PROG_NAME, rst);
	fprintf(s, "\n");
	fprintf(s, "    ssh into a list of hosts passed on the command line, ");
	fprintf(s, "limit max parallel\n");
	fprintf(s, "    connections to 3, and grab the output of %spgrep%s.\n",
	    grn, rst);
	fprintf(s, "\n");
	fprintf(s, "%s      %s -m 3 -f hosts.txt pgrep -fl process%s\n",
	    grn, PROG_NAME, rst);
	fprintf(s, "\n");
	fprintf(s, "    Upgrade packages on all hosts in the list ");
	fprintf(s, "one-by-one, grouping the output\n");
	fprintf(s, "    by host, with debugging output enabled.\n");
	fprintf(s, "\n");
	fprintf(s, "%s      %s -m 1 -f hosts.txt -d -g pkg-manager update%s\n",
	    grn, PROG_NAME, rst);
	fprintf(s, "\n");
	// options
	fprintf(s, "%sOPTIONS:%s\n", ylw, rst);
	fprintf(s, "%s  -a%s,%s --anonymous            %s", grn, rst, grn, rst);
	fprintf(s, "Hide hostname prefix, defaults to %sfalse%s.\n", grn, rst);
	fprintf(s, "%s  -c%s,%s --color <on|off|auto>  %s", grn, rst, grn, rst);
	fprintf(s, "Set color output, defaults to %sauto%s.\n", grn, rst);
	fprintf(s, "%s  -d%s,%s --debug                %s", grn, rst, grn, rst);
	fprintf(s, "Enable debug info, defaults to %sfalse%s.\n", grn, rst);
	fprintf(s, "%s  -e%s,%s --exit-codes           %s", grn, rst, grn, rst);
	fprintf(s, "Show command exit codes, defaults to %sfalse%s.\n",
	    grn, rst);
	fprintf(s, "%s  -f%s,%s --file <file>          %s", grn, rst, grn, rst);
	fprintf(s, "A file of hosts separated by newlines, ");
	fprintf(s, "defaults to %sstdin%s.\n", grn, rst);
	fprintf(s, "%s  -g%s,%s --group                %s", grn, rst, grn, rst);
	fprintf(s, "Group output by hostname (%sgroup mode%s).\n", grn, rst);
	fprintf(s, "%s  -h%s,%s --help                 %s", grn, rst, grn, rst);
	fprintf(s, "Print this message and exit.\n");
	fprintf(s, "%s  -j%s,%s --join                 %s", grn, rst, grn, rst);
	fprintf(s, "Join hosts together by output (%sjoin mode%s).\n",
	    grn, rst);
	fprintf(s, "%s  -m%s,%s --max-jobs <num>       %s", grn, rst, grn, rst);
	fprintf(s, "Max processes to run concurrently, defaults to %s50%s.\n",
	    grn, rst);
	fprintf(s, "%s  -n%s,%s --dry-run              %s", grn, rst, grn, rst);
	fprintf(s, "Don't actually execute subprocesses.\n");
	fprintf(s, "%s  -s%s,%s --silent               %s", grn, rst, grn, rst);
	fprintf(s, "Silence all output subprocess stdio, ");
	fprintf(s, "defaults to %sfalse%s.\n", grn, rst);
	fprintf(s, "%s  -t%s,%s --trim                 %s", grn, rst, grn, rst);
	fprintf(s, "Trim hostnames (remove domain) on output, ");
	fprintf(s, "defaults to %sfalse%s.\n", grn, rst);
	fprintf(s, "%s  -v%s,%s --version              %s", grn, rst, grn, rst);
	fprintf(s, "Print the version number and exit.\n");
	fprintf(s, "%s  -x%s,%s --exec <prog>          %s", grn, rst, grn, rst);
	fprintf(s, "Program to execute, defaults to %sssh%s.\n", grn, rst);
	fprintf(s, "%s  --max-line-length <num>    %s", grn, rst);
	fprintf(s, "Maximum line length (in %sline mode%s), ", grn, rst);
	fprintf(s, "defaults to %s%d%s.\n", grn, DEFAULT_MAX_LINE_LENGTH, rst);
	fprintf(s, "%s  --max-output-length <num>  %s", grn, rst);
	fprintf(s, "Maximum output length (in %sjoin mode%s), ", grn, rst);
	fprintf(s, "defaults to %s%d%s.\n",
	    grn, DEFAULT_MAX_OUTPUT_LENGTH, rst);
	fprintf(s, "\n");
	// ssh options
	fprintf(s, "%sSSH OPTIONS:%s (passed directly to ssh)\n",
	    ylw, rst);
	fprintf(s, "%s  -i%s,%s --identity <ident>     %s", grn, rst, grn, rst);
	fprintf(s, "ssh identity file to use.\n");
	fprintf(s, "%s  -l%s,%s --login <name>         %s", grn, rst, grn, rst);
	fprintf(s, "The username to login as.\n");
	fprintf(s, "%s  -o%s,%s --option <key=val>     %s", grn, rst, grn, rst);
	fprintf(s, "ssh option passed in key=value form.\n");
	fprintf(s, "%s  -p%s,%s --port <port>          %s", grn, rst, grn, rst);
	fprintf(s, "The ssh port.\n");
	fprintf(s, "%s  -q%s,%s --quiet                %s", grn, rst, grn, rst);
	fprintf(s, "Run ssh in quiet mode.\n");
	fprintf(s, "\n");
	// see more
	fprintf(s, "%sMORE:%s\n", ylw, rst);
	fprintf(s, "    See %s%s%s(1) for more information.\n",
	    grn, PROG_NAME, rst);
}

/*
 * Return an "s" if the number of items (given as an int) should be plural.
 */
static const char *
pluralize(int num)
{
	return num == 1 ? "" : "s";
}

/*
 * Convert the given mode to a string.
 */
static const char *
prog_mode_to_string(enum ProgMode mode)
{
	switch (mode) {
	case MODE_LINE: return "line";
	case MODE_GROUP: return "group";
	case MODE_JOIN: return "join";
	default: errx(3, "unknown ProgMode: %d", mode);
	}
}

/*
 * Print status - called via SIGUSR1 handler.
 */
static void
print_status(void)
{
	int num_hosts = 0;
	int cp_ready = 0;
	int cp_running = 0;
	int cp_done = 0;

	// calculate number of hosts in various state
	for (Host *h = hosts; h != NULL; h = h->next) {
		assert(h->cp != NULL);
		switch (h->cp->state) {
		case CP_STATE_READY: cp_ready++; break;
		case CP_STATE_RUNNING: cp_running++; break;
		case CP_STATE_DONE: cp_done++; break;
		default: errx(3, "unknown cp->state: %d", h->cp->state);
		}
		num_hosts++;
	}

	printf("status: ");
	printf("%s%d%s running, ", colors.magenta, cp_running, colors.reset);
	printf("%s%d%s finished, ", colors.magenta, cp_done, colors.reset);
	printf("%s%d%s remaining ", colors.magenta, cp_ready, colors.reset);
	printf("(%s%d%s total)\n", colors.magenta, num_hosts, colors.reset);

	// print each child process with their pid
	if (cp_running > 0) {
		printf("running processes:\n");
		for (Host *h = hosts; h != NULL; h = h->next) {
			assert(h->cp != NULL);
			if (h->cp->state != CP_STATE_RUNNING) {
				continue;
			}
			printf("--> pid %s%d%s %s%s%s\n",
			    colors.magenta, h->cp->pid, colors.reset,
			    colors.cyan, h->name, colors.reset);
		}
	}
}

/*
 * Kill all running child processes.
 */
static void
kill_running_processes(void)
{
	for (Host *h = hosts; h != NULL; h = h->next) {
		assert(h->cp != NULL);
		if (h->cp->state != CP_STATE_RUNNING) {
			continue;
		}
		assert(h->cp->pid > 0);

		DEBUG("killing pid %s%d%s %s%s%s\n",
		    colors.magenta, h->cp->pid, colors.reset,
		    colors.cyan, h->name, colors.reset);

		if (kill(h->cp->pid, SIGTERM) == -1) {
			warn("send SIGTERM to pid %d", h->cp->pid);
		}
	}
}

/*
 * Simple signal num -> string converter.
 */
static const char *
signal_to_str(int signum)
{
	switch (signum) {
	case SIGTERM: return "SIGTERM";
	case SIGUSR1: return "SIGUSR1";
	case SIGINT: return "SIGINT";
	default: return "(unknown signal)";
	}
}

/*
 * Signal handler.
 */
static void
signal_handler(int signum)
{
	printf("\n%s%s%s received\n",
	    colors.yellow, signal_to_str(signum), colors.reset);

	switch (signum) {
	case SIGUSR1: print_status(); break;
	case SIGINT: exit(4);
	case SIGTERM: exit(4);
	default: errx(3, "unknown signal handled: %d", signum);
	}

	printf("\n");
}

/*
 * atexit handler.  Kill any running child processes that are possibly
 * outstanding when exit is called.
 */
static void
atexit_handler(void)
{
	kill_running_processes();
}

/*
 * Wrapper for malloc that takes an error message as the second argument and
 * exits on failure.
 */
static void *
safe_malloc(size_t size, const char *msg)
{
	void *ptr;

	assert(size > 0);
	assert(msg != NULL);

	ptr = malloc(size);

	if (ptr == NULL) {
		err(3, "malloc %s", msg);
	}

	return ptr;
}

/*
 * Create a ChildProcess object.
 */
static ChildProcess *
child_process_create(void)
{
	ChildProcess *cp = safe_malloc(sizeof (ChildProcess),
	    "child_process_create");

	cp->exit_code = -1;
	cp->finished_time = -1;
	cp->output = NULL;
	cp->output_idx = -1;
	cp->pid = -1;
	cp->started_time = -1;
	cp->state = CP_STATE_READY;
	cp->stderr_fd = -1;
	cp->stdio_fd = -1;
	cp->stdout_fd = -1;

	return cp;
}

/*
 * Check if the given Host object has had both of its stdio pipes closed.
 */
static bool
child_process_stdio_done(ChildProcess *cp)
{
	assert(cp != NULL);

	return (cp->stdout_fd == -2 && cp->stderr_fd == -2) ||
	    cp->stdio_fd == -2;
}

/*
 * Free a ChildProcess object (and the optionally created output buffer).
 */
static void
child_process_destroy(ChildProcess *cp)
{
	if (cp == NULL) {
		return;
	}

	free(cp->output);
	free(cp);
}

/*
 * Allocate and create a new Host object given its hostname.  The hostname will
 * be copied from the given argument.
 */
static Host *
host_create(const char *name)
{
	assert(name != NULL);

	Host *host = safe_malloc(sizeof (Host), "host_create");
	char *name_dup = strdup(name);

	if (name_dup == NULL) {
		err(3, "strdup hostname %s", name);
	}

	host->name = name_dup;
	host->cp = child_process_create();
	host->next = NULL;

	return host;
}

/*
 * Free an allocated Host object.
 */
static void
host_destroy(Host *host)
{
	if (host == NULL) {
		return;
	}

	child_process_destroy(host->cp);

	free(host->name);
	free(host);
}

/*
 * Create and FdEvent object given a host pointer and pipetype.
 */
static FdEvent *
fdev_create(Host *host, enum PipeType type)
{
	assert(host != NULL);
	assert(host->cp != NULL);

	FdEvent *fdev = safe_malloc(sizeof (FdEvent), "FdEvent");

	fdev->host = host;
	fdev->type = type;
	fdev->offset = 0;
	fdev->buffer = NULL;

	// initailize stdio buffers
	switch (opts.mode) {
	case MODE_LINE:
		fdev->buffer = safe_malloc(opts.max_line_length + 2,
		    "fdev->buffer");
		break;
	case MODE_JOIN:
		fdev->buffer = safe_malloc(opts.max_output_length + 1,
		    "fdev->buffer");
		break;
	case MODE_GROUP:
		// stdio is not buffered in group mode
		break;
	default: errx(3, "unknown mode: %d", opts.mode);
	}

	// get fd
	switch (type) {
	case PIPE_STDOUT: fdev->fd = host->cp->stdout_fd; break;
	case PIPE_STDERR: fdev->fd = host->cp->stderr_fd; break;
	case PIPE_STDIO:  fdev->fd = host->cp->stdio_fd;  break;
	default: errx(3, "unknown type: %d", type);
	}
	assert(fdev->fd >= 0);

	return fdev;
}

/*
 * Given an FdEvent pointer return the event relevant color.
 */
static char *
fdev_get_color(FdEvent *fdev)
{
	assert(fdev != NULL);

	switch (fdev->type) {
	case PIPE_STDOUT: return colors.green;
	case PIPE_STDERR: return colors.red;
	case PIPE_STDIO: return "";
	default: errx(3, "unknown fdev->type: %d", fdev->type);
	}
}

/*
 * Free an allocated FdEvent object.
 */
static void
fdev_destroy(FdEvent *fdev)
{
	if (fdev == NULL) {
		return;
	}

	free(fdev->buffer);
	free(fdev);
}

/*
 * Create a pipe with both ends set to non-blocking and cloexec.
 */
static void
make_pipe(int *fd)
{
	assert(fd != NULL);

	if (pipe(fd) == -1) {
		err(3, "pipe");
	}
	if (fcntl(fd[PIPE_READ_END], F_SETFL, O_NONBLOCK) == -1) {
		err(3, "set read end nonblocking");
	}
	if (fcntl(fd[PIPE_WRITE_END], F_SETFL, O_NONBLOCK) == -1) {
		err(3, "set write end nonblocking");
	}
	if (fcntl(fd[PIPE_READ_END], F_SETFD, FD_CLOEXEC) == -1) {
		err(3, "set read end cloexec");
	}
	if (fcntl(fd[PIPE_WRITE_END], F_SETFD, FD_CLOEXEC) == -1) {
		err(3, "set write end cloexec");
	}
}

/*
 * Push an argument to the ssh base command and bounds check it.
 * The strings passed to this function need to be allocated or constantly
 * defined.
 */
static void
push_arguments(char *s, ...)
{
	assert(s != NULL);

	static int idx = 0;
	va_list args;

	va_start(args, s);
	while (s != NULL) {
		if (idx >= MAX_ARGS - 2) {
			errx(2, "too many command arguments");
		}
		base_ssh_command[idx] = s;
		idx++;
		s = va_arg(args, char *);
	}
	va_end(args);
}

/*
 * Replace the first occurrence of char c with '\0' in a string.
 * Returns true if a replacement was made and false otherwise.
 */
static bool
lsplit_str(char *s, char c)
{
	assert(s != NULL);

	for (int i = 0; s[i] != '\0'; i++) {
		if (s[i] == c) {
			s[i] = '\0';
			return true;
		}
	}

	return false;
}

/*
 * Given a null terminated stream return whether it ends in a newline
 * character.
 */
static bool
ends_in_newline(const char *s)
{
	assert(s != NULL);

	int idx = strlen(s);

	if (idx == 0) {
		return false;
	}

	return s[idx - 1] == '\n';
}

/*
 * Get the current monotonic time in ms.
 */
static long
monotonic_time_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		err(3, "clock_gettime");
	}

	return (t.tv_sec * 1e3) + (t.tv_nsec / 1e6);
}

/*
 * Print the header for a given host.
 */
static void
print_host_header(Host *host)
{
	assert(host != NULL);

	printf("[%s%s%s]", colors.cyan, host->name, colors.reset);
}

/*
 * Given a Host object and a buffer of a suitable size, fill the buffer with
 * the required arguments to exec a child process.
 */
static void
build_ssh_command(Host *host, char **command, int size)
{
	assert(host != NULL);
	assert(command != NULL);
	assert(size > 0);

	char *name_array[] = {host->name, NULL};
	int idx = 0;

	/*
	 * construct SSH command like:
	 * base_ssh_command + host name + remote_command
	 * as a null terminated array called "command"
	 */
	char **items_arr[] = {
		base_ssh_command,
		name_array,
		remote_command,
		NULL
	};
	char ***items = items_arr;
	while (*items != NULL) {
		char **item = *items;
		while (*item != NULL) {
			char *arg = *item;
			command[idx++] = arg;
			if (idx >= size) {
				errx(2, "too many arguments (<= %d)", size);
			}

			item++;
		}

		items++;
	}

	assert(idx < size);
	assert(command[size - 1] == NULL);
}

/*
 * Fork and exec a subprocess.  This function is responsible for creating and
 * initializing the stdio pipes and attaching them to the given Host object.
 */
static void
spawn_child_process(Host *host)
{
	assert(host != NULL);
	assert(host->name != NULL);
	assert(host->cp != NULL);

	char *command[MAX_ARGS] = {NULL};
	int stderr_fd[2];
	int stdio_fd[2];
	int stdout_fd[2];
	pid_t pid;

	// build the ssh command
	build_ssh_command(host, command, MAX_ARGS);

	// create the stdio pipes
	switch (opts.mode) {
	case MODE_JOIN:
		// join mode uses a sharded stdout/stderr pipe
		make_pipe(stdio_fd);
		break;
	default:
		// all other modes use a pipe per stream
		make_pipe(stdout_fd);
		make_pipe(stderr_fd);
	}

	// fork the process
	pid = fork();
	if (pid == -1) {
		err(3, "fork");
	}

	// in child
	if (pid == 0) {
		int *err_fd;
		int *out_fd;
		switch (opts.mode) {
		case MODE_JOIN:
			out_fd = stdio_fd;
			err_fd = stdio_fd;
			break;
		default:
			out_fd = stdout_fd;
			err_fd = stderr_fd;
			break;
		}

		if (dup2(out_fd[PIPE_WRITE_END], STDOUT_FILENO) == -1) {
			err(3, "dup2 stdout");
		}
		if (dup2(err_fd[PIPE_WRITE_END], STDERR_FILENO) == -1) {
			err(3, "dup2 stderr");
		}

		execvp(command[0], command);
		err(3, "exec");
	}

	// in parent

	// close write ends and save read ends
	switch (opts.mode) {
	case MODE_JOIN:
		close(stdio_fd[PIPE_WRITE_END]);
		host->cp->stdio_fd = stdio_fd[PIPE_READ_END];
		break;
	default:
		close(stdout_fd[PIPE_WRITE_END]);
		close(stderr_fd[PIPE_WRITE_END]);
		host->cp->stdout_fd = stdout_fd[PIPE_READ_END];
		host->cp->stderr_fd = stderr_fd[PIPE_READ_END];
		break;
	}

	// save data
	host->cp->pid = pid;
	host->cp->started_time = monotonic_time_ms();
	host->cp->state = CP_STATE_RUNNING;

	DEBUG("%s%d%s %s%s%s spawned\n",
	    colors.magenta, host->cp->pid, colors.reset,
	    colors.cyan, host->name, colors.reset);
}

/*
 * Register a specific fd to the fdwatcher..
 */
static void
register_child_process_fd(Host *host, enum PipeType type)
{
	FdEvent *fdev = fdev_create(host, type);

	fdwatcher_add(fdw, fdev->fd, fdev);
}

/*
 * Given a Host object that has had its child process spawned add both of its
 * pipes fds to the fdwatcher for events.
 */
static void
register_child_process_fds(Host *host)
{
	assert(host != NULL);

	switch (opts.mode) {
	case MODE_JOIN:
		register_child_process_fd(host, PIPE_STDIO);
		break;
	default:
		register_child_process_fd(host, PIPE_STDOUT);
		register_child_process_fd(host, PIPE_STDERR);
		break;
	}
}

/*
 * Call waitpid on the subprocess associated with the given Host object.  This
 * function will reap the process, set the exit code and remove the pid from
 * the Host object, and optionally print the exited message if opts.exit_codes
 * or opts.debug is set.
 */
static void
wait_for_child(Host *host)
{
	assert(host != NULL);
	assert(host->cp != NULL);

	ChildProcess *cp = host->cp;
	int status;
	pid_t pid;

	// reap the child
	pid = waitpid(cp->pid, &status, 0);

	if (pid < 0) {
		err(3, "waitpid");
	}

	// set the host as closed
	cp->exit_code = WEXITSTATUS(status);
	cp->pid = -2;
	cp->finished_time = monotonic_time_ms();
	cp->state = CP_STATE_DONE;

	// print the exit message
	if (opts.exit_codes || opts.debug) {
		char *code_color = cp->exit_code == 0 ?
		    colors.green : colors.red;
		long delta = cp->finished_time - cp->started_time;

		// check if a newline is needed
		if (!newline_printed) {
			printf("\n");
			newline_printed = true;
		}

		// print the exit status
		if (opts.debug) {
			printf("[%s%s%s] %s%d%s %s%s%s exited: %s%d%s ",
			    colors.cyan, PROG_NAME, colors.reset,
			    colors.magenta, pid, colors.reset,
			    colors.cyan, host->name, colors.reset,
			    code_color, cp->exit_code, colors.reset);
		} else {
			assert(opts.exit_codes);
			printf("[%s%s%s] exited: %s%d%s ",
			    colors.cyan, host->name, colors.reset,
			    code_color, cp->exit_code, colors.reset);
		}
		printf("(%s%ld%s ms)\n", colors.magenta, delta, colors.reset);
	}
}

/*
 * Prints the given linebuf with the given color as well as the host header.
 *
 * (used for line mode).
 */
static void
print_line_buffer(FdEvent *fdev)
{
	assert(fdev != NULL);
	assert(fdev->host != NULL);
	assert(fdev->buffer != NULL);

	char *color = fdev_get_color(fdev);

	if (!opts.anonymous) {
		print_host_header(fdev->host);
		printf(" ");
	}

	printf("%s%s%s", color, fdev->buffer, colors.reset);
}

/*
 * Called by read_active_fd when processing read bytes in line mode.
 */
static void
process_data_line(FdEvent *fdev, char *buf, int bytes)
{
	assert(fdev != NULL);
	assert(fdev->host != NULL);
	assert(fdev->buffer != NULL);
	assert(buf != NULL);
	assert(bytes > 0);

	// loop data character-by-character
	for (int i = 0; i < bytes; i++) {
		char c = buf[i];

		if (fdev->offset < opts.max_line_length) {
			// buffer has room for character
			fdev->buffer[fdev->offset] = c;
			fdev->offset++;
		} else if (fdev->offset == opts.max_line_length) {
			// no more room, call it a newline
			fdev->buffer[fdev->offset] = '\n';
			fdev->offset++;
		}

		// got a newline! print it
		if (c == '\n') {
			assert(fdev->offset > 0);
			assert(fdev->offset < opts.max_line_length + 2);

			fdev->buffer[fdev->offset] = '\0';
			print_line_buffer(fdev);
			fdev->offset = 0;
		}
	}
}

/*
 * Called by read_active_fd when processing read bytes in group mode.
 */
static void
process_data_group(FdEvent *fdev, char *buf, int bytes)
{
	assert(fdev != NULL);
	assert(fdev->host != NULL);
	assert(buf != NULL);
	assert(bytes > 0);

	static Host *last_host = NULL;

	// processing a new host from last time
	if (last_host != fdev->host) {
		// print a newline if needed
		if (!newline_printed) {
			printf("\n");
		}

		// print the host name
		if (!opts.anonymous) {
			print_host_header(fdev->host);
			printf("\n");
		}
	}

	// write the fd data to stdout
	printf("%s", fdev_get_color(fdev));
	fflush(stdout);
	if (write(STDOUT_FILENO, buf, bytes) < bytes) {
		err(3, "write failed");
	}
	printf("%s", colors.reset);

	// check if a newline was printed, save the last host
	newline_printed = buf[bytes - 1] == '\n';
	last_host = fdev->host;
}

/*
 * Called by read_active_fd when processing read bytes in join mode.
 */
static void
process_data_join(FdEvent *fdev, char *buf, int bytes)
{
	assert(fdev != NULL);
	assert(fdev->host != NULL);
	assert(fdev->buffer != NULL);
	assert(buf != NULL);
	assert(bytes > 0);

	// loop data character-by-character
	for (int i = 0; i < bytes; i++) {
		char c = buf[i];

		// line is too long
		if (fdev->offset < opts.max_output_length) {
			// room for the character
			fdev->buffer[fdev->offset] = c;
			fdev->offset++;
		} else if (fdev->offset == opts.max_line_length) {
			// no more room, pad it with a nul byte
			fdev->buffer[fdev->offset] = '\0';
			fdev->offset++;
		} else {
			// we are overbook, just break
			break;
		}
	}
}

/*
 * Called by read_active_fd when finishing an fd in line mode.
 */
static void
fd_done_line(FdEvent *fdev)
{
	// check for a remaining line
	if (fdev->offset == 0) {
		return;
	}

	// data remaining! put a newline if it didn't have one
	if (fdev->buffer[fdev->offset - 1] != '\n') {
		fdev->buffer[fdev->offset] = '\n';
		fdev->offset++;
	}
	assert(fdev->offset < opts.max_line_length + 2);

	fdev->buffer[fdev->offset] = '\0';
	print_line_buffer(fdev);
	fdev->offset = 0;
}

/*
 * Called by read_active_fd when finishing an fd in group mode.
 */
static void
fd_done_group(FdEvent *fdev)
{
	assert(fdev != NULL);

	// do nothing
}

/*
 * Called by read_active_fd when finishing an fd in join mode.
 */
static void
fd_done_join(FdEvent *fdev)
{
	assert(fdev != NULL);
	assert(fdev->host != NULL);
	assert(fdev->host->cp != NULL);

	// copy fdev buffer to host object for later analysis
	if (fdev->offset <= opts.max_output_length) {
		fdev->buffer[fdev->offset] = '\0';
		fdev->offset++;
	}
	fdev->host->cp->output = fdev->buffer;
	fdev->buffer = NULL;
}

/*
 * Read data from FdEvent until end or would-block
 */
static bool
read_active_fd(FdEvent *fdev)
{
	Host *host;
	char buf[BUFSIZ];
	int *fd;
	int bytes;

	assert(fdev != NULL);
	assert(fdev->host != NULL);

	host = fdev->host;

	switch (fdev->type) {
	case PIPE_STDOUT: fd = &host->cp->stdout_fd; break;
	case PIPE_STDERR: fd = &host->cp->stderr_fd; break;
	case PIPE_STDIO: fd = &host->cp->stdio_fd; break;
	default: errx(3, "unknown type %d", fdev->type);
	}

	// loop while bytes available
	while ((bytes = read(*fd, buf, BUFSIZ)) > -1) {
		// done reading!
		if (bytes == 0) {
			// remove the fd and close it
			fdwatcher_remove(fdw, *fd);
			close(*fd);
			*fd = -2;

			switch (opts.mode) {
			case MODE_LINE: fd_done_line(fdev); break;
			case MODE_GROUP: fd_done_group(fdev); break;
			case MODE_JOIN: fd_done_join(fdev); break;
			default: errx(3, "unknown mode: %d", opts.mode);
			}

			fdev_destroy(fdev);

			return true;
		}

		// do nothing if in silent mode
		if (opts.silent) {
			continue;
		}

		// handle bytes in different modes
		switch (opts.mode) {
		case MODE_JOIN: process_data_join(fdev, buf, bytes); break;
		case MODE_LINE: process_data_line(fdev, buf, bytes); break;
		case MODE_GROUP: process_data_group(fdev, buf, bytes); break;
		default: errx(3, "unknown mode: %d", opts.mode); break;
		}
	}

	assert(bytes < 0);

	// handle read error
	if (errno == EWOULDBLOCK) {
		return false;
	}

	err(3, "read failed");
}

/*
 * Finish analysis for join mode.
 *
 * In join mode, all of the stdout and stderr has been buffered and is
 * processed in this function.
 *
 * This function could possibly be made simpler with hash tables, but for now
 * it seems to work just fine.  The way it works is:
 *
 * 1. Loop all hosts.
 *   a. Assign each "output" an index (stored as cp->output_idx), the first
 *      host encountered is index 0.
 *   b. For each host looped, do *another* loop of the hosts starting at our
 *      current host and strcmp the output.  If the output is the same, assign
 *      it the same index.  If the output is different, skip it for now.
 *   c. Move onto the next host without an index and assign it idx + 1.
 * 2. Print the number of unique results seen (how many indices were created).
 * 3. Loop the indices and print the unique output + the hostnames.
 */
static void
finish_join_mode(int num_hosts)
{
	int idx = 0;
	int *count = safe_malloc(sizeof (int) * num_hosts,
	    "finish_join_mode count");

	// loop the hosts to check and categorize their output
	for (Host *h1 = hosts; h1 != NULL; h1 = h1->next) {
		int num_same = 1;

		// this host already processed
		if (h1->cp->output_idx >= 0) {
			continue;
		}

		h1->cp->output_idx = idx;

		for (Host *h2 = h1->next; h2 != NULL; h2 = h2->next) {
			// skip already processed host
			if (h2->cp->output_idx >= 0) {
				continue;
			}

			// check if output is the same
			if (strcmp(h1->cp->output, h2->cp->output) == 0) {
				h2->cp->output_idx = idx;
				num_same++;
			}

		}

		count[idx] = num_same;
		idx++;
	}

	printf("finished with %s%d%s unique result%s\n\n",
	    colors.magenta, idx, colors.reset, pluralize(idx));

	// loop the unique results
	for (int i = 0; i < idx; i++) {
		char *output = NULL;

		printf("hosts (%s%d%s/%s%d%s):%s",
		    colors.magenta, count[i], colors.reset,
		    colors.magenta, num_hosts, colors.reset,
		    colors.cyan);

		for (Host *h = hosts; h != NULL; h = h->next) {
			if (h->cp->output_idx != i) {
				continue;
			}

			output = h->cp->output;
			printf(" %s", h->name);
		}
		assert(output != NULL);

		// print the output
		printf("%s\n%s", colors.reset, output);

		// alert if the output is empty
		if (output[0] == '\0') {
			printf("%s- no output -%s",
			    colors.magenta, colors.reset);
		}

		// print a newline if there isn't one
		if (!ends_in_newline(output)) {
			printf("\n");
		}

		printf("\n");
	}

	free(count);
}

/*
 * Print the progress line as hosts finish in join mode.
 */
static void
print_progress_line(int done, int num_hosts)
{
	printf("[%s%s%s] finished %s%d%s/%s%d%s\r",
	    colors.cyan, PROG_NAME, colors.reset,
	    colors.magenta, done, colors.reset,
	    colors.magenta, num_hosts, colors.reset);
	fflush(stdout);
}

/*
 * The main program loop that should be called from main().
 */
static void
main_loop(int num_hosts)
{
	Host *cur_host = hosts;
	int done = 0;
	int outstanding = 0;
	void *fdevs[FDW_MAX_EVENTS];

	if (opts.mode == MODE_JOIN && stdout_isatty) {
		print_progress_line(done, num_hosts);
	}

	// loop while there are still child processes
	while (cur_host != NULL || outstanding > 0) {
		assert(outstanding <= opts.max_jobs);

		int num_events;

		// create child processes
		while (cur_host != NULL && outstanding < opts.max_jobs) {
			spawn_child_process(cur_host);

			// chop off the domain portion of the name if -t
			if (opts.trim) {
				lsplit_str(cur_host->name, '.');
			}

			register_child_process_fds(cur_host);

			outstanding++;
			cur_host = cur_host->next;
		}

		// wait for fd events
		num_events = fdwatcher_wait(fdw, fdevs, FDW_MAX_EVENTS,
		    FDW_WAIT_TIMEOUT);
		if (num_events == -1) {
			if (errno == EINTR) {
				continue;
			}
			err(3, "fdwatcher_wait");
		}

		// loop fd events
		for (int i = 0; i < num_events; i++) {
			FdEvent *fdev = fdevs[i];
			Host *host = fdev->host;

			assert(host != NULL);

			// read the active fd until it would block or is done
			bool fd_closed = read_active_fd(fdev);

			// check if the childs stdio is done and reap it
			if (fd_closed && child_process_stdio_done(host->cp)) {
				wait_for_child(host);
				outstanding--;
				done++;

				if (opts.mode == MODE_JOIN && stdout_isatty) {
					print_progress_line(done, num_hosts);
					if (done == num_hosts) {
						printf("\n\n");
					}
				}
			}
		}
	}
}

/*
 * Parse the hosts file and create the Host structs
 */
static int
parse_hosts(FILE *f)
{
	Host *tail = NULL;
	char hostname[_POSIX_HOST_NAME_MAX];
	int lineno = 1;
	int num_hosts = 0;

	assert(f != NULL);

	while (fgets(hostname, _POSIX_HOST_NAME_MAX, f) != NULL) {
		Host *host;
		char prefix = hostname[0];

		// skip comments and blank lines
		switch (prefix) {
		case '#':
		case ' ':
		case '\n':
		case '\0':
			goto next;
		}

		/*
		 * remove the ending newline - if a newline is not present the
		 * line is too long
		 */
		if (!lsplit_str(hostname, '\n')) {
			errx(2, "hosts file line %d too long (>= %d chars)\n%s",
			    lineno, _POSIX_HOST_NAME_MAX, hostname);
		}

		// create Host
		host = host_create(hostname);

		// set head of list
		if (hosts == NULL) {
			hosts = host;
		}

		// set tail of list
		if (tail != NULL) {
			tail->next = host;
		}

		tail = host;
		num_hosts++;

next:
		lineno++;
	}

	if (ferror(f)) {
		errx(2, "failed to read hosts file");
	}
	assert(feof(f));

	return num_hosts;
}

/*
 * Parse command line arguments
 */
static void
parse_arguments(int argc, char **argv)
{
	bool help_option = false;
	bool unknown_option = false;
	int opt;

	// get options
	while ((opt = getopt_long(argc, argv, short_options, long_options,
	    NULL)) != -1) {
		switch (opt) {
		case 1000: opts.max_line_length = atoi(optarg); break;
		case 1001: opts.max_output_length = atoi(optarg); break;
		case 'a': opts.anonymous = true; break;
		case 'c': opts.color = optarg; break;
		case 'd': opts.debug = true; break;
		case 'e': opts.exit_codes = true; break;
		case 'f': opts.file = optarg; break;
		case 'g': opts.group = true; break;
		case 'h': help_option = true; break;
		case 'i': opts.identity = optarg; break;
		case 'j': opts.join = true; break;
		case 'l': opts.login = optarg; break;
		case 'm': opts.max_jobs = atoi(optarg); break;
		case 'n': opts.dry_run = true; break;
		case 'o': push_arguments("-o", optarg, NULL); break;
		case 'p': opts.port = optarg; break;
		case 'q': opts.quiet = true; break;
		case 's': opts.silent = true; break;
		case 't': opts.trim = true; break;
		case 'v': printf("%s\n", PROG_VERSION); exit(0);
		case 'x': base_ssh_command[0] = optarg; break;
		default: unknown_option = true; break;
		}
	}
	argc -= optind;
	argv += optind;

	// sanity check options
	if (opts.max_jobs < 1) {
		errx(2, "invalid value for `-m`: '%d'", opts.max_jobs);
	}
	if (opts.join && opts.group) {
		errx(2, "`-j` and `-g` are mutually exclusive");
	}
	if (opts.join && opts.silent) {
		errx(2, "`-j` and `-s` are mutually exclusive");
	}
	if (opts.join && opts.anonymous) {
		errx(2, "`-j` and `-a` are mutually exclusive");
	}
	if (opts.max_line_length <= 0) {
		errx(2, "invalid value for `--max-line-length`: %d",
		    opts.max_line_length);
	}
	if (opts.max_output_length <= 0) {
		errx(2, "invalid value for `--max-output-length`: %d",
		    opts.max_output_length);
	}

	// set current sshp mode
	assert(!(opts.join && opts.group));
	if (opts.join) {
		opts.mode = MODE_JOIN;
	} else if (opts.group) {
		opts.mode = MODE_GROUP;
	}

	// check if colorized output should be enabled
	if (opts.color == NULL || strcmp(opts.color, "auto") == 0) {
		opts.color = stdout_isatty ? "on" : "off";
	}
	if (strcmp(opts.color, "on") == 0) {
		colors.black = COLOR_BLACK;
		colors.red = COLOR_RED;
		colors.green = COLOR_GREEN;
		colors.yellow = COLOR_YELLOW;
		colors.blue = COLOR_BLUE;
		colors.magenta = COLOR_MAGENTA;
		colors.cyan = COLOR_CYAN;
		colors.white = COLOR_WHITE;
		colors.reset = COLOR_RESET;
	} else if (strcmp(opts.color, "off") == 0) {
		// pass, this is default
	} else {
		errx(2, "invalid value for '-c': '%s'", opts.color);
	}

	// -h or unknown option
	if (unknown_option) {
		print_usage(stderr);
		exit(2);
	} else if (help_option) {
		print_usage(stdout);
		exit(0);
	}

	if (argc < 1) {
		errx(2, "no command specified");
	}

	// add options to command
	if (opts.quiet) {
		push_arguments("-q", NULL);
	}
	if (opts.identity != NULL) {
		push_arguments("-i", opts.identity, NULL);
	}
	if (opts.login != NULL) {
		push_arguments("-l", opts.login, NULL);
	}
	if (opts.port != NULL) {
		push_arguments("-p", opts.port, NULL);
	}

	// save the remaining arguments as the command
	remote_command = argv;
}

/*
 * Main method
 */
int
main(int argc, char **argv)
{
	FILE *hosts_file = stdin;
	int dev_null_fd;
	int exit_code = 0;
	int num_hosts;
	struct sigaction sig;
	long delta;
	long end_time;
	long start_time;

	// record start time
	start_time = monotonic_time_ms();

	// check stdout tty
	stdout_isatty = isatty(STDOUT_FILENO) == 1;

	// initalize options
	opts.max_line_length = DEFAULT_MAX_LINE_LENGTH;
	opts.max_output_length = DEFAULT_MAX_OUTPUT_LENGTH;
	opts.anonymous = false;
	opts.color = NULL;
	opts.debug = false;
	opts.exit_codes = false;
	opts.file = NULL;
	opts.group = false;
	opts.identity = NULL;
	opts.join = false;
	opts.login = NULL;
	opts.max_jobs = 50;
	opts.mode = MODE_LINE;
	opts.dry_run = false;
	opts.port = NULL;
	opts.quiet = false;
	opts.silent = false;
	opts.trim = false;

	// initialize colors
	colors.black = "";
	colors.red = "";
	colors.green = "";
	colors.yellow = "";
	colors.blue = "";
	colors.magenta = "";
	colors.cyan = "";
	colors.white = "";
	colors.reset = "";

	// initialized the base ssh command
	push_arguments("ssh", NULL);

	// handle CLI options
	parse_arguments(argc, argv);

	// open /dev/null to overwrite stdin
	dev_null_fd = open("/dev/null", O_RDONLY);
	if (dev_null_fd == -1) {
		err(3, "open /dev/null");
	}

	// figure out where to read hosts from (stdin or a file)
	if (opts.file != NULL && strcmp(opts.file, "-") != 0) {
		hosts_file = fopen(opts.file, "r");
		if (hosts_file == NULL) {
			err(2, "open %s", opts.file);
		}
	}
	assert(hosts_file != NULL);

	// read in hosts and create structure for each one
	num_hosts = parse_hosts(hosts_file);

	// ensure at least 1 host is specified
	if (num_hosts < 1) {
		errx(2, "no hosts specified");
	}

	// close the hosts file if it wasn't from stdin
	if (hosts_file != stdin) {
		fclose(hosts_file);
	}

	// copy over stdin with /dev/null
	if (dup2(dev_null_fd, STDIN_FILENO) == -1) {
		err(3, "dup2 /dev/null stdin");
	}
	close(dev_null_fd);

	// create shared fdwatcher instance
	fdw = fdwatcher_create();
	if (fdw == NULL) {
		err(3, "fdwatcher_create");
	}

	// handle signals and exit
	sig.sa_handler = signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	if (atexit(atexit_handler) != 0) {
		err(3, "register atexit");
	}
	if (sigaction(SIGUSR1, &sig, NULL) != 0) {
		err(3, "register SIGUSR1");
	}
	if (sigaction(SIGTERM, &sig, NULL) != 0) {
		err(3, "register SIGTERM");
	}
	if (sigaction(SIGINT, &sig, NULL) != 0) {
		err(3, "register SIGINT");
	}

	// print debug output
	if (opts.debug) {
		// print hosts
		DEBUG("hosts (%s%d%s): [ ",
		    colors.magenta, num_hosts, colors.reset);
		for (Host *h = hosts; h != NULL; h = h->next) {
			printf("%s'%s'%s ",
			    colors.green, h->name, colors.reset);
		}
		printf("]\n");

		// print base command
		DEBUG("ssh command: [ ");
		for (char **arg = base_ssh_command; *arg != NULL; arg++) {
			printf("%s'%s'%s ", colors.green, *arg, colors.reset);
		}
		printf("]\n");

		// print command
		DEBUG("remote command: [ ");
		for (char **arg = remote_command; *arg != NULL; arg++) {
			printf("%s'%s'%s ", colors.green, *arg, colors.reset);
		}
		printf("]\n");

		// print pid
		DEBUG("pid: %s%d%s\n", colors.green, getpid(), colors.reset);

		// print mode
		DEBUG("mode: %s%s%s\n",
		    colors.green, prog_mode_to_string(opts.mode), colors.reset);

		// print max jobs
		DEBUG("max-jobs: %s%d%s\n",
		    colors.green, opts.max_jobs, colors.reset);
	}

	// start the main loop!
	if (opts.dry_run) {
		printf("(dry run)\n");
	} else {
		main_loop(num_hosts);

		// finish up
		switch (opts.mode) {
		case MODE_JOIN:
			finish_join_mode(num_hosts);
			break;
		default:
			break;
		}
	}

	// tidy up
	fdwatcher_destroy(fdw);

	// check exit codes and free memory
	while (hosts != NULL) {
		Host *host = hosts;
		assert(host->cp != NULL);

		if (!opts.dry_run) {
			assert(host->cp->exit_code >= 0);
			if (host->cp->exit_code != 0) {
				exit_code = 1;
			}
		}

		hosts = host->next;
		host_destroy(host);
	}

	// get end time and calculate time taken
	end_time = monotonic_time_ms();
	delta = end_time - start_time;
	DEBUG("finished (%s%ld%s ms)\n", colors.magenta, delta, colors.reset);

	return exit_code;
}
