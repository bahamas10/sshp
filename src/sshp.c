/*
 * Parallel ssh
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: March 26, 2021
 * License: MIT
 */

#include <assert.h>
#include <err.h>
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

#define SSHP_VERSION "v0.0.0"

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
 * sshp modes of execution
 */
enum SSHPMode {
	ModeLineByLine,
	ModeGroup,
	ModeJoin
};

/*
 * A struct that represents a single host (as a linked-list)
 */
typedef struct Host {
	char *name;
	struct Host *next;
} Host;

// Linked-list of Hosts
static Host *hosts = NULL;

// Command to execute
static char **command = {NULL};

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
	int port;
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
 * Wrapper for malloc that takes an error message as the second argument and
 * exits on failure.
 */
static void*
safe_malloc(size_t size, const char *msg)
{
	void *ptr = malloc(size);
	if (ptr == NULL) {
		err(3, "malloc %s", msg);
	}
	return ptr;
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

		host = safe_malloc(sizeof(Host), "Host");

		// remove the ending newline - if a newline is not present the
		// line is too long
		if (!trim_newline(hostname)) {
			errx(2, "hosts file line %d too long (>= %d chars)\n%s",
			    lineno, HOST_NAME_MAX, hostname);
		}

		host->name = strdup(hostname);
		host->next = NULL;

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
		case 'p': opts.port = atoi(optarg); break;
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
		opts.mode = ModeJoin;
	} else if (opts.group) {
		opts.mode = ModeGroup;
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
	command = argv;
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
	opts.mode = ModeLineByLine;
	opts.dry_run = false;
	opts.no_strict = false;
	opts.port = -1;
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

	// figure out where to read hosts from (stdin or a file)
	if (opts.file != NULL && strcmp(opts.file, "-") != 0) {
		hosts_file = fopen(opts.file, "r");
		if (hosts_file == NULL) {
			err(2, "open %s", opts.file);
		}
	}
	assert(hosts_file != NULL);

	// record start time
	start_time = monotonic_time_ms();

	// read in hosts and create structure for each one
	parse_hosts(hosts_file);
	fclose(hosts_file);

	// ensure at least 1 host is specified
	if (global_state.num_hosts < 1) {
		errx(2, "no hosts specified");
	}

	// print optional debug output
	if (opts.debug) {
		// print hosts
		DEBUG("hosts (%s%d%s): [ ",
		    colors.important, global_state.num_hosts, colors.reset);
		for (Host *h = hosts; h != NULL; h = h->next) {
			printf("%s'%s'%s ",
			    colors.value, h->name, colors.reset);
		}
		printf("]\n");

		// print command
		DEBUG("command: [ ");
		for (char **arg = command; *arg != NULL; arg++) {
			printf("%s'%s'%s ",
			    colors.value, *arg, colors.reset);
		}
		printf("]\n");

		// print max jobs
		DEBUG("max-jobs: %s%d%s\n",
		    colors.value, opts.max_jobs, colors.reset);
	}

	// do work here

	// get end time and calculate time taken
	end_time = monotonic_time_ms();
	delta = end_time - start_time;
	DEBUG("finished (%s%ld%s ms)\n",
	    colors.important, delta, colors.reset);

	return 0;
}
