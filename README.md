`sshp` - Parallel SSH Executor
==============================

`sshp` manages multiple ssh processes and handles coalescing the output to the
terminal.  By default, `sshp` will read a file of newline-separated hostnames
or IPs and fork ssh subprocesses for them, redirecting the stdout and stderr
streams of the child line-by-line to stdout of `sshp` itself.

Installation
------------

Pull the source code and run `make` to compile `sshp`:

    $ make
    cc -o sshp -Wall -Werror -Wextra -Wpedantic -O2 src/sshp.c
    $ ./sshp -v
    v0.0.0

Then optionally run `make install` to install `sshp`:

    $ sudo make install
    cp man/sshp.1 /usr/local/man/man1
    cp sshp /usr/local/bin
    $ sshp -v
    v0.0.0

`sshp` requires a kernel that supports `epoll` to run.  This has been tested on
both Linux and illumos Operating Systems.

Introduction
------------

`sshp` has 3 modes of execution:

- `line mode` (line-by-line output, default).
- `group mode` (grouped by hostname output, `-g`).
- `join mode` (grouped by unique output, `-j`).

The first 2 modes, `line` and `group`, operate in largely the same way,
differing only in how data is buffered from the child processes and printed to
the screen.  Line mode buffers the data line-by-line, whereas group mode does
no buffering at all and prints the data once it is read from the child.

The last mode however, `join`, buffers *all* of the data from all of the child
processes and outputs once all processes have finished.  Instead of grouping
the output by host, it is grouped by the output itself to show which hosts had
the same output.

Examples
---------

Given the following hosts file called `hosts.txt`:

```
# example hosts file

arbiter.rapture.com
cifs.rapture.com
decomp.rapture.com
```

Parallel ssh into hosts supplied by a file running `uname -v`:

![line-by-line](https://www.daveeddy.com/static/media/github/sshp/c/line-by-line.png)

Pass in `-e` to get the exit codes of the commands on the remote end.  The
local exit code will be 0 if all ssh processes exit successfully, or 1 if any
of the ssh processes exit with a failure:

![exit-codes](https://www.daveeddy.com/static/media/github/sshp/c/exit-codes.png)

Also note that the hosts file can be passed in via stdin if `-f` is not
supplied.

Run with `-d` to get debug information making it clear what `sshp` is doing:

![debug-id](https://www.daveeddy.com/static/media/github/sshp/c/debug-id.png)

Run with `-g` (`group mode`) to group the output by hostname as it comes in.
To illustrate this, `-m` is set to 1 to limit the maximum number of concurrent
child processes to 1, effectively turning `sshp` into an `ssh` serializer:

![serialize-group](https://www.daveeddy.com/static/media/github/sshp/c/serialize-group-mode.png)

Run with `-j` (`join mode`) to join the output by the output itself and not the
hostname:

![join-mode](https://www.daveeddy.com/static/media/github/sshp/c/join-mode.png)

Send the `sshp` process a `SIGSUR1` signal to print out process status
information while it is running.  In this example a signal was sent twice to
the process:

![sigusr1-status](https://www.daveeddy.com/static/media/github/sshp/c/sigusr1-status.png)

Comparison to Node.js `sshp`
----------------------------

This program was originally written in Node.js and released as
[node-sshp](https://github.com/bahamas10/node-sshp).  This C variant is mostly
compatible with the original Node.js version with some slight alterations:

- `-b` has been changed to `-c off` (disable color output).
- `-N` has been removed in favor of `-o StrictHostKeyChecking=no`.
- `-o` has been added to allow for any ssh option to be passed in.
- `-u` has been removed.
- `-y` has been removed.

For more information on why `sshp` was ported from JavaScript to C see [This
blog post](blog).

Usage
-----

```
$ sshp -h
        _
  _____| |_  _ __     Parallel SSH Executor (v0.0.0)
 (_-<_-< ' \| '_ \    Source: https://github.com/bahamas10/sshp
 /__/__/_||_| .__/    MIT License
            |_|

Parallel ssh with streaming output.

USAGE:
    sshp [-m maxjobs] [-f file] command ...

EXAMPLES:
    ssh into a list of hosts passed via stdin and get the output of uname -v.

      sshp uname -v < hosts

    ssh into a list of hosts passed on the command line, limit max parallel
    connections to 3, and grab the output of pgrep.

      sshp -m 3 -f hosts.txt pgrep -fl process

    Upgrade packages on all hosts in the list, one-by-one, grouping the output
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
  --max-line-length <num>    Maximum line length (in line mode), defaults to 1024.
  --max-output-length <num>  Maximum output length (in join mode), defaults to 8192.

SSH OPTIONS: (passed directly to ssh)
  -i, --identity <ident>     ssh identity file to use.
  -l, --login <name>         The username to login as.
  -o, --option <key=val>     ssh option passed in key=value form.
  -p, --port <port>          The ssh port.
  -q, --quiet                Run ssh in quiet mode.

MORE:
    see sshp(1) for more information.
```

License
-------

MIT License
