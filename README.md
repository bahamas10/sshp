![sshp-logo](https://www.daveeddy.com/static/media/github/sshp/c/logo.jpg)

`sshp` - Parallel SSH Executor
==============================

`sshp` manages multiple ssh processes and handles coalescing the output to the
terminal.  By default, `sshp` will read a file of newline-separated hostnames
or IPs and fork ssh subprocesses for them, redirecting the stdout and stderr
streams of the child line-by-line to stdout of `sshp` itself.

- [Installation](#installation)
- [About](#about)
- [Examples](#examples)
- [Tips and Tricks](#tips-and-tricks)
- [Exit Codes](#exit-codes)
- [Usage](#usage)
- [Tests and Style](#tests-and-style)
- [Comparison to Node.js sshp](#comparison-to-nodejs-sshp)
- [License](#license)

Installation
------------

Pull the source code and run `make` to compile `sshp`:

``` console
$ make
cc -o src/fdwatcher.o -c -D USE_KQUEUE=0 -Wall -Werror -Wextra -Wpedantic -O2 src/fdwatcher.c
cc -o sshp -Wall -Werror -Wextra -Wpedantic -O2 src/sshp.c src/fdwatcher.o
$ ./sshp -v
v1.0.0
```

Then optionally run `make install` to install `sshp`:

``` console
$ sudo make install
cp man/sshp.1 /usr/local/man/man1
cp sshp /usr/local/bin
$ sshp -v
v1.0.0
```

If you use Arch Linux, you can instead use the AUR package [sshp](https://aur.archlinux.org/packages/sshp) or [sshp-git](https://aur.archlinux.org/packages/sshp-git) to compile and install.

Note: `sshp` requires a kernel that supports `epoll` or `kqueue` to run.  This has
been tested on Linux, illumos, MacOS, and FreeBSD.

About
-----

`sshp` has 3 modes of execution:

- `line mode` (line-by-line output, default).
- `group mode` (grouped by hostname output, `-g`).
- `join mode` (grouped by unique output, `-j`).

The first 2 modes, `line` and `group`, operate in largely the same way,
differing only in how data is buffered from the child processes and printed to
the screen.  Line mode buffers the data line-by-line, whereas group mode does
no buffering at all and prints the data once it is read from the child.

The last mode, `join`, however, buffers *all* of the data from all of the child
processes and outputs once all processes have finished.  Instead of grouping
the output by host, it is grouped by the output itself to show which hosts had
the same output.

Examples
--------

Given the following hosts file called `hosts.txt`:

```
# example hosts file

arbiter.rapture.com
cifs.rapture.com
decomp.rapture.com
```

Parallel ssh into hosts supplied by a file running `uname -v`:

![line-by-line](https://www.daveeddy.com/static/media/github/sshp/c/line-by-line.jpg)

Pass in `-e` to get the exit codes of the commands on the remote end.  The
local exit code will be 0 if all ssh processes exit successfully, or 1 if any
of the ssh processes exit with a failure:

![exit-codes](https://www.daveeddy.com/static/media/github/sshp/c/exit-codes.jpg)

Also note that the hosts file can be passed in via stdin if `-f` is not
supplied.

Run with `-d` to get debug information making it clear what `sshp` is doing:

![debug-id](https://www.daveeddy.com/static/media/github/sshp/c/debug-id.jpg)

Run with `-g` (`group mode`) to group the output by hostname as it comes in.
To illustrate this, `-m` is set to 1 to limit the maximum number of concurrent
child processes to 1, effectively turning `sshp` into an `ssh` serializer:

![serialize-group](https://www.daveeddy.com/static/media/github/sshp/c/serialize-group-mode.jpg)

Run with `-j` (`join mode`) to join the output by the output itself and not the
hostname:

![join-mode](https://www.daveeddy.com/static/media/github/sshp/c/join-mode.jpg)

Send the `sshp` process a `SIGSUR1` signal to print out process status
information while it is running.  In this example, a signal was sent twice to
the process:

![sigusr1-status](https://www.daveeddy.com/static/media/github/sshp/c/sigusr1-status.jpg)

Tips and Tricks
---------------

If one or more of the hosts you want to ssh into are not in your `known_hosts`
file it can be really overwhelming to get all of the warning messages / prompts
to save the host key.  You can manually accept any new keys 1-by-1 with:

    sshp -f hosts.txt -m 1 true

Or, accept all keys without any confirmation or validation (use at your own
risk):

    sshp -f hosts.txt -o StrictHostKeyChecking=no true

Exit Codes
----------

- `0` Everything worked and all child processes exited successfully.
- `1` Everything worked, but 1 or more children exited with a non-zero code.
- `2` Incorrect usage - the user supplied something incorrect preventing `sshp`
  from being able to run (unknown options, invalid host file, etc.).
- `3` Program failure - the program experienced some failing in the system
  preventing `sshp` from being able to run (`malloc` failure, `epoll` failure,
  etc.).
- `4` `sshp` killed by `SIGTERM` or `SIGINT`.
- `*` Anything else - probably a blown assertion.

Usage
-----

``` console
$ sshp -h
        _
  _____| |_  _ __     Parallel SSH Executor (v1.1.0)
 (_-<_-< ' \| '_ \    Source: https://github.com/bahamas10/sshp
 /__/__/_||_| .__/    Compiled: Jun  2 2021 12:23:56 (using kqueue)
            |_|       MIT License

Parallel ssh with streaming output.

USAGE:
    sshp [-m maxjobs] [-f file] command ...

EXAMPLES:
    ssh into a list of hosts passed via stdin and get the output of uname -v.

      sshp uname -v < hosts

    ssh into a list of hosts passed on the command line, limit max parallel
    connections to 3, and grab the output of pgrep.

      sshp -m 3 -f hosts.txt pgrep -fl process

    Upgrade packages on all hosts in the list one-by-one, grouping the output
    by host, with debugging output enabled.

      sshp -m 1 -f hosts.txt -d -g pkg-manager update

OPTIONS:
  -a, --anonymous            Hide hostname prefix, defaults to false.
  -c, --color <on|off|auto>  Set color output, defaults to auto.
  -d, --debug                Enable debug info, defaults to false.
  -e, --exit-codes           Show command exit codes, defaults to false.
  -f, --file <file>          A file of hosts separated by newlines, defaults to stdin.
  -g, --group                Group output by hostname (group mode).
  -h, --help                 Print this message and exit.
  -j, --join                 Join hosts together by output (join mode).
  -m, --max-jobs <num>       Max processes to run concurrently, defaults to 50.
  -n, --dry-run              Don't actually execute subprocesses.
  -s, --silent               Silence all output subprocess stdio, defaults to false.
  -t, --trim                 Trim hostnames (remove domain) on output, defaults to false.
  -v, --version              Print the version number and exit.
  -x, --exec <prog>          Program to execute, defaults to ssh.
  --max-line-length <num>    Maximum line length (in line mode), defaults to 1024.
  --max-output-length <num>  Maximum output length (in join mode), defaults to 8192.

SSH OPTIONS: (passed directly to ssh)
  -i, --identity <ident>     ssh identity file to use.
  -l, --login <name>         The username to login as.
  -o, --option <key=val>     ssh option passed in key=value form.
  -p, --port <port>          The ssh port.
  -q, --quiet                Run ssh in quiet mode.

MORE:
    See sshp(1) for more information.
```

Tests and Style
----------------

`sshp` comes with a very simple test suite.  It checks for just basic usage and
sanity.  It can be run with `make test`:

``` console
$ make test
cd test && ./runtest test_*
running:  ./test_00_usage
sshp -v  is 0 ... ok
sshp -h  is 0 ... ok
sshp  is 2 ... ok
sshp -f / cmd  is 2 ... ok
sshp -f /should-not-exist cmd  is 2 ... ok
sshp -f /dev/null cmd  is 2 ... ok
sshp -f ./assets/hosts/empty-hosts.txt cmd  is 2 ... ok
sshp -m  is 2 ... ok
sshp -m 0  is 2 ... ok
sshp -m foo  is 2 ... ok
sshp -m -17  is 2 ... ok
sshp -g -j  is 2 ... ok
sshp -n -f ./assets/hosts/simple-hosts.txt cmd  is 0 ... ok
sshp -n -f - cmd  is 0 ... ok
sshp -n cmd  is 0 ... ok
sshp -n -f ./assets/hosts/long-hosts-good.txt cmd  is 0 ... ok
sshp -n -f ./assets/hosts/long-hosts-bad.txt cmd  is 2 ... ok

running:  ./test_10_exec
sshp -x ./assets/cmd/true arg  is 0 ... ok
sshp -x ./assets/cmd/true -j arg  is 0 ... ok
sshp -x ./assets/cmd/true -g arg  is 0 ... ok
sshp -x ./assets/cmd/false arg  is 1 ... ok
sshp -x ./assets/cmd/false -j arg  is 1 ... ok
sshp -x ./assets/cmd/false -g arg  is 1 ... ok
sshp -x ./assets/cmd/hello -a arg code  is 0 ... ok
sshp -x ./assets/cmd/hello -a arg stdout  is hello ... ok

running:  ./test_20_signals
../sshp -x ./assets/cmd/sleep arg TERM code  is 4 ... ok
../sshp -x ./assets/cmd/sleep arg INT code  is 4 ... ok
```

Style can be checked with `make check`, this does not require the program to be
compiled:

``` console
$ make check
./test/check src/*.h src/*.c test/* man/*.md
checking:  src/fdwatcher.h
checking:  src/fdwatcher.c
checking:  src/sshp.c
checking:  test/check
checking:  test/hosts.txt
checking:  test/test
checking:  man/sshp.md
```

The style check is *very* simple.  It ensures:

1. No line exceeds 80 columns.
2. No consecutive blank lines.
3. Consistent use of tabs and spaces.

Comparison to Node.js `sshp`
----------------------------

This program was originally written in Node.js and released as
[node-sshp](https://github.com/bahamas10/node-sshp).  This C variant is mostly
compatible with the original Node.js version with some slight alterations:

- `-b` has been changed to `-c off` (disable color output).
- `-N` has been removed in favor of `-o StrictHostKeyChecking=no`.
- `-o` has been added to allow for any ssh option to be passed in.
- `-u` has been removed (not applicable without `npm`).
- `-y` has been removed in favor of `-o RequestTTY=force`.

For more information on why `sshp` was ported from JavaScript to C, see [this
blog post](https://www.daveeddy.com/2021/05/20/sshp-rewrite-from-javascript-to-c/).

License
-------

MIT License
