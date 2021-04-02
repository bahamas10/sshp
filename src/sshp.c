/*
 * Parallel ssh
 *
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
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

// version
#define SSHP_VERSION "v0.0.0"

// epoll max events
#define EPOLL_MAX_EVENTS 10

// maximum number of arguments for a child process
#define MAX_ARGS 256

// pipe ends
#define READ_END 0
#define WRITE_END 1

// ANSI color codes
#define COLOR_BLACK "\033[0;30m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_WHITE "\033[0;37m"
#define COLOR_RESET "\033[0m"

// printf-like function that runs if "debug" mode is enabled
#define DEBUG(...) { \
	if (opts.debug) { \
		printf("[%ssshp%s] ", colors.log_id, colors.reset); \
		printf(__VA_ARGS__); \
	} \
}

/*
 * sshp modes of execution.
 */
enum SSHPMode {
	MODE_LINE_BY_LINE = 0,
	MODE_GROUP,
	MODE_JOIN
};

/*
 * A struct that represents a single host (as a linked-list).
 */
typedef struct host {
	char *name;
	pid_t pid;
	int stdout_fd;
	int stderr_fd;
	struct host *next;
} Host;

/*
 * Pipe types.
 */
enum PipeType {
	PIPE_STDOUT = 1,
	PIPE_STDERR
};

/*
 * Wrapper struct for use when an fd sees an event.
 */
typedef struct fd_event {
	Host *host;
	enum PipeType type;
} FdEvent;

// Linked-list of Hosts
static Host *hosts = NULL;

// Command to execute
static char **remote_command = {NULL};

// Base SSH Command
static char *base_ssh_command[MAX_ARGS] = {NULL};

// Epoll instance
int epoll_fd;

/*
 * A struct that represents the global state of this program.  This is used
 * mainly to synhcronize data between the 2 threads.
 */
static struct global_state {
	pthread_mutex_t lock;
	int num_fds;
	int num_hosts;
	bool all_children_exited;
} global_state;

// CLI options for getopt_long
static char *short_options = "ac:def:ghi:jl:m:nNp:qstvy";
static struct option long_options[] = {
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
	{"no-strict", no_argument, NULL, 'N'},
	{"port", required_argument, NULL, 'p'},
	{"quiet", no_argument, NULL, 'q'},
	{"silent", no_argument, NULL, 's'},
	{"trim", no_argument, NULL, 't'},
	{"version", no_argument, NULL, 'v'},
	{"tty", no_argument, NULL, 'y'},
	{NULL, 0, NULL, 0}
};

// options set via CLI opts
static struct opts {
	bool anonymous;
	char *color;
	bool debug;
	bool exit_codes;
	char *file;
	bool group;
	char *identity;
	bool join;
	char *login;
	int max_jobs;
	int mode;
	bool dry_run;
	bool no_strict;
	char *port;
	bool quiet;
	bool silent;
	bool trim;
	bool tty;
} opts;

// colors to use when printing if coloring is enabled
static struct colors {
	char *host;
	char *important;
	char *log_id;
	char *reset;
	char *stderr;
	char *stdout;
	char *value;
} colors;

/*
 * Print the usages message to the given filestream
 */
static void
print_usage(FILE *s)
{
	fprintf(s,
		"Usage: sshp [-m maxjobs] [-f file] command ...\n"
		"\n"
		"parallel ssh with streaming output\n"
		"\n"
		"examples\n"
		"  ssh into a list of hosts passed via stdin and get the output of `uname -v`\n"
		"\n"
		"    sshp uname -v < hosts\n"
		"\n"
		"  ssh into a list of hosts passed on the command line, limit max parallel\n"
		"  connections to 3, and grab the output of ps piped to grep on the remote end\n"
		"\n"
		"    sshp -m 3 -f my_hosts.txt \"ps -ef | grep process\"\n"
		"\n"
		"options\n"
		"  -a, --anonymous   hide hostname prefix, defaults to false\n"
		"  -d, --debug       turn on debugging information, defaults to false\n"
		"  -e, --exit-codes  print the exit code of the remote processes, defaults to false\n"
		"  -f, --file        a file of hosts separated by newlines, defaults to stdin\n"
		"  -g, --group       group the output together as it comes in by hostname, not line-by-line\n"
		"  -h, --help        print this message and exit\n"
		"  -j, --join        join hosts together by unique output (aggregation mode)\n"
		"  -m, --max-jobs    the maximum number of jobs to run concurrently, defaults to 300\n"
		"  -n, --dry-run     print debug information without actually running any commands\n"
		"  -N, --no-strict   disable strict host key checking for ssh, defaults to false\n"
		"  -s, --silent      silence all stdout and stderr from remote hosts, defaults to false\n"
		"  -t, --trim        trim hostnames from fqdn to short name (remove domain), defaults to false\n"
		"  -v, --version     print the version number and exit\n"
		"\n"
		"ssh options (options passed directly to ssh)\n"
		"  -i, --identity    ssh identity file to use\n"
		"  -l, --login       the username to login as\n"
		"  -q, --quiet       run ssh in quiet mode\n"
		"  -p, --port        the ssh port\n"
		"  -y, --tty         allocate a pseudo-tty for the ssh session\n"
	);
}

/*
 * Wrapper for malloc that takes an error message as the second argument and
 * exits on failure.
 */
static void *
safe_malloc(size_t size, const char *msg)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		err(3, "malloc %s", msg);
	}
	return ptr;
}

/*
 * Push an argument to the ssh base command and bounds check it.
 */
static void
push_argument(char *s)
{
	static int idx = 0;

	if (idx >= MAX_ARGS - 2) {
		errx(2, "too many command arguments");
	}

	base_ssh_command[idx] = s;

	idx++;
}

/*
 * Replace the first occurence of '\n' with '\0' in a string.
 */
static bool
trim_newline(char *s)
{
	for (int i = 0; s[i] != '\0'; i++) {
		if (s[i] == '\n') {
			s[i] = '\0';
			return true;
		}
	}
	return false;
}

/*
 * Get the current monotonic time in ms
 */
static long
monotonic_time_ms()
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		err(3, "clock_gettime");
	}

	return (t.tv_sec * 1e3) + (t.tv_nsec / 1e6);
}

int
fdev_get_fd(FdEvent *fdev)
{
	assert(fdev != NULL);

	switch (fdev->type) {
		case PIPE_STDOUT: return fdev->host->stdout_fd;
		case PIPE_STDERR: return fdev->host->stderr_fd;
		default: errx(3, "unknown fdev->type '%d'", fdev->type);
	}
}

/*
 * Fork and exec a subprocess
 */
void
spawn_child_process(Host *host)
{
	assert(host != NULL);
	assert(host->name != NULL);

	int idx = 0;
	char *command[MAX_ARGS] = {NULL};
	char *name_array[] = {host->name, NULL};
	pid_t pid;
	int stdout_fd[2];
	int stderr_fd[2];


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
			printf("command[%d] = '%s'\n", idx, arg);
			command[idx++] = arg;
			if (idx >= MAX_ARGS) {
				errx(2, "too many arguments (<= %d)", MAX_ARGS);
			}

			item++;
		}

		items++;
	}
	assert(idx < MAX_ARGS);
	assert(command[MAX_ARGS - 1] == NULL);

	printf("fork+exec %s\n", host->name);

	// create the stdio pipes
	if (pipe(stdout_fd) == -1) {
		err(3, "pipe");
	}
	if (pipe(stderr_fd) == -1) {
		err(3, "pipe");
	}

	// fork the process
	pid = fork();
	if (pid == -1) {
		err(3, "fork");
	}

	// in child
	if (pid == 0) {
		close(stdout_fd[READ_END]);
		close(stderr_fd[READ_END]);
		if (dup2(stdout_fd[WRITE_END], STDOUT_FILENO) == -1) {
			err(3, "dup2 stdout");
		}
		if (dup2(stderr_fd[WRITE_END], STDERR_FILENO) == -1) {
			err(3, "dup2 stderr");
		}

		execvp(command[0], command);
		err(3, "exec");
	}

	// in parent
	// close unused fds
	close(stdout_fd[WRITE_END]);
	close(stderr_fd[WRITE_END]);

	// save data
	host->pid = pid;
	host->stdout_fd = stdout_fd[READ_END];
	host->stderr_fd = stderr_fd[READ_END];

	// set read pipes nonblocking
	if (fcntl(host->stdout_fd, F_SETFL, O_NONBLOCK) == -1) {
		err(3, "set nonblocking");
	}
	if (fcntl(host->stderr_fd, F_SETFL, O_NONBLOCK) == -1) {
		err(3, "set nonblocking");
	}
}

void
register_child_process_fds(Host *host)
{
	enum PipeType types[] = { PIPE_STDOUT, PIPE_STDERR };
	int count = sizeof (types) / sizeof (types[0]);

	assert(host->stdout_fd != -1);
	assert(host->stderr_fd != -1);

	for (int i = 0; i < count; i++) {
		// create an epoll event
		struct epoll_event ev;
		FdEvent *fdev = safe_malloc(sizeof (FdEvent), "FdEvent");

		ev.events = EPOLLIN;
		ev.data.ptr = fdev;

		fdev->host = host;
		fdev->type = types[i];

		int fd = fdev_get_fd(fdev);

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			err(3, "epoll_ctl add");
		}
	}
}

/*
 * Thread to manage subprocess execution
 */
void *
thread_subprocess_execution_manager()
{
	Host *cur_host = hosts;

	printf("in thread_subprocess_execution_manager\n");

	// loop over all hosts
	while (cur_host != NULL) {
		spawn_child_process(cur_host);
		register_child_process_fds(cur_host);

		cur_host = cur_host->next;
	}

	return NULL;
}

/*
 * Read data from FdEvent until end or would-block
 */
bool
read_active_fd(FdEvent *fdev)
{
	char buf[BUFSIZ];
	int fd = fdev_get_fd(fdev);

	printf("trying to read fd %d\n", fd);
	int bytes = read(fd, buf, BUFSIZ);

	// read error
	if (bytes < 0) {
		if (errno == EWOULDBLOCK) {
			printf("would block\n");
			return false;
		}
		err(3, "read failed");
	}

	// done reading!
	if (bytes == 0) {
		printf("fd %d done\n", fd);
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
		close(fd);
		return false;
	}
	char *color = fdev->type == PIPE_STDOUT ? colors.stdout : colors.stderr;

	printf("%s", color);
	if (write(STDOUT_FILENO, buf, bytes) < bytes) {
		err(3, "write failed");
	}
	printf("%s", colors.reset);

	return true;
}

/*
 * Thread to manage subprocess stdio
 */
void *
thread_subprocess_stdio_manager()
{
	//struct epoll_event event;
	struct epoll_event events[EPOLL_MAX_EVENTS];

	printf("in thread_subprocess_stdio_manager\n");

	char *last_host_printed = NULL;

	while (true) {
		// XXX -1? probably should use timeout?
		printf("called epoll_wait\n");
		int num_events = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 3000);

		printf("epoll_wait returned - got %d events\n", num_events);

		if (num_events == -1) {
			err(3, "epoll_wait");
		}

		for (int i = 0; i < num_events; i++) {
			struct epoll_event ev = events[i];
			FdEvent *fdev = ev.data.ptr;
			//Host *host = fdev->host;
			printf("looking at event %d\n", i);
			printf("fdev->type = %d\n", fdev->type);

			if (last_host_printed == NULL || last_host_printed != fdev->host->name) {
				printf("[%s%s%s]\n", colors.log_id, fdev->host->name, colors.reset);
				last_host_printed = fdev->host->name;
			}

			while (read_active_fd(fdev));
		}
	}

	return NULL;
}

/*
 * Parse the hosts file and create the Host structs
 */
static void
parse_hosts(FILE *f)
{
	Host *tail = NULL;
	char hostname[HOST_NAME_MAX];
	int lineno = 1;

	while (fgets(hostname, HOST_NAME_MAX, f) != NULL) {
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

		host = safe_malloc(sizeof (Host), "Host");

		/*
		 * remove the ending newline - if a newline is not present the
		 * line is too long
		 */
		if (!trim_newline(hostname)) {
			errx(2, "hosts file line %d too long (>= %d chars)\n%s",
			    lineno, HOST_NAME_MAX, hostname);
		}

		host->name = strdup(hostname);
		host->stdout_fd = -1;
		host->stderr_fd = -1;
		host->pid = -1;
		host->next = NULL;

		if (host->name == NULL) {
			err(3, "strdup hostname %s", hostname);
		}

		if (hosts == NULL) {
			hosts = host;
		}

		if (tail != NULL) {
			tail->next = host;
		}

		tail = host;
		global_state.num_hosts++;

next:
		lineno++;
	}

	if (ferror(f)) {
		errx(2, "failed to read hosts file");
	}
	assert(feof(f));
}

/*
 * Parse command line arguments
 */
static void
parse_arguments(int argc, char **argv)
{
	int opt;

	// get options
	while ((opt = getopt_long(argc, argv, short_options, long_options,
	    NULL)) != -1) {

		switch (opt) {
		case 'a': opts.anonymous = true; break;
		case 'c': opts.color = optarg; break;
		case 'd': opts.debug = true; break;
		case 'e': opts.exit_codes = true; break;
		case 'f': opts.file = optarg; break;
		case 'g': opts.group = true; break;
		case 'h': print_usage(stdout); exit(0);
		case 'i': opts.identity = optarg; break;
		case 'j': opts.join = true; break;
		case 'l': opts.login = optarg; break;
		case 'm': opts.max_jobs = atoi(optarg); break;
		case 'n': opts.dry_run = true; break;
		case 'N': opts.no_strict = true; break;
		case 'p': opts.port = optarg; break;
		case 'q': opts.quiet = true; break;
		case 's': opts.silent = true; break;
		case 't': opts.trim = true; break;
		case 'v': printf("%s\n", SSHP_VERSION); exit(0);
		case 'y': opts.tty = true; break;
		default: print_usage(stderr); exit(2);
		}
	}
	argc -= optind;
	argv += optind;

	// sanity check options
	if (opts.max_jobs < 1) {
		errx(2, "invalid value for '-m': '%d'", opts.max_jobs);
	}
	if (opts.join && opts.group) {
		errx(2, "`-j` and `-g` are mutually exclusive");
	}
	if (opts.join && opts.silent) {
		errx(2, "`-j` and `-s` are mutually exclusive");
	}
	if (argc < 1) {
		errx(2, "no command specified");
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
		opts.color = isatty(STDOUT_FILENO) == 1 ? "on" : "off";
	}
	if (strcmp(opts.color, "on") == 0) {
		colors.host = COLOR_YELLOW;
		colors.important = COLOR_MAGENTA;
		colors.log_id = COLOR_CYAN;
		colors.reset = COLOR_RESET;
		colors.stderr = COLOR_RED;
		colors.stdout = COLOR_GREEN;
		colors.value = COLOR_GREEN;
	} else if (strcmp(opts.color, "off") == 0) {
		// pass, this is default
	} else {
		errx(2, "invalid value for '-c': '%s'", opts.color);
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
	long delta;
	long end_time;
	long start_time;
	pthread_t subprocess_execution_manager;
	pthread_t subprocess_stdio_manager;

	// record start time
	start_time = monotonic_time_ms();

	// initalize options
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
	opts.mode = MODE_LINE_BY_LINE;
	opts.dry_run = false;
	opts.no_strict = false;
	opts.port = NULL;
	opts.quiet = false;
	opts.silent = false;
	opts.trim = false;
	opts.tty = false;

	// initialize colors
	colors.host = "";
	colors.important = "";
	colors.log_id = "";
	colors.reset = "";
	colors.stderr = "";
	colors.stdout = "";
	colors.value = "";

	// initaialize global state
	global_state.num_fds = 0;
	global_state.num_hosts = 0;
	global_state.all_children_exited = false;
	if (pthread_mutex_init(&global_state.lock, NULL) != 0) {
		err(3, "mutex init global_state.lock");
	}

	// handle CLI options
	parse_arguments(argc, argv);

	// initalized the base ssh command
	push_argument("echo");
	push_argument("ssh");
	if (opts.login != NULL) {
		push_argument("-l");
		push_argument(opts.login);
	}
	if (opts.port != NULL) {
		push_argument("-p");
		push_argument(opts.port);
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
	parse_hosts(hosts_file);
	fclose(hosts_file);

	// ensure at least 1 host is specified
	if (global_state.num_hosts < 1) {
		errx(2, "no hosts specified");
	}

	// create shared epoll instance
	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd == -1) {
		err(3, "epoll_create1");
	}

	// print debug output
	if (opts.debug) {
		// print base command
		DEBUG("ssh command: [ ");
		for (char **arg = base_ssh_command; *arg != NULL; arg++) {
			printf("%s'%s'%s ",
			    colors.value, *arg, colors.reset);
		}
		printf("]\n");

		// print hosts
		DEBUG("hosts (%s%d%s): [ ",
		    colors.important, global_state.num_hosts, colors.reset);
		for (Host *h = hosts; h != NULL; h = h->next) {
			printf("%s'%s'%s ",
			    colors.value, h->name, colors.reset);
		}
		printf("]\n");

		// print command
		DEBUG("remote command: [ ");
		for (char **arg = remote_command; *arg != NULL; arg++) {
			printf("%s'%s'%s ",
			    colors.value, *arg, colors.reset);
		}
		printf("]\n");

		// print max jobs
		DEBUG("max-jobs: %s%d%s\n",
		    colors.value, opts.max_jobs, colors.reset);
	}

	// disable stdout printf buffering
	setvbuf(stdout, NULL, _IONBF, 0);

	// create both threads
	if (pthread_create(&subprocess_stdio_manager, NULL,
	    thread_subprocess_stdio_manager, NULL) != 0) {
		err(3, "pthread_create subprocess_stdio_manager");
	}
	if (pthread_create(&subprocess_execution_manager, NULL,
	    thread_subprocess_execution_manager, NULL) != 0) {
		err(3, "pthread_create subprocess_execution_manager");
	}

	// block on both threads
	if (pthread_join(subprocess_stdio_manager, NULL) != 0) {
		err(3, "pthread_join subprocess_stdio_manager");
	}
	if (pthread_join(subprocess_execution_manager, NULL) != 0) {
		err(3, "pthread_join subprocess_execution_manager");
	}

	// tidy up
	close(epoll_fd);

	// get end time and calculate time taken
	end_time = monotonic_time_ms();
	delta = end_time - start_time;
	DEBUG("finished (%s%ld%s ms)\n",
	    colors.important, delta, colors.reset);

	return 0;
}
