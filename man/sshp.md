SSHP 1 "2021" "General Commands Manual"
=======================================

NAME
----

`sshp` - Parallel SSH Executor.

SYNOPSIS
--------

`sshp [OPTIONS] <command> [args] ...`

`sshp [-f <hosts.txt>] [-j | -g] <command>`

DESCRIPTION
-----------

Parallel SSH executor and manager.

`sshp` manages multiple ssh processes and handles coalescing the output to the
terminal.  By default, `sshp` will read a file of newline-separated hostnames
or IPs and fork ssh subprocesses for them, redirecting the stdout and stderr
streams of the child line-by-line to stdout of `sshp` itself.

MODES
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

OPTIONS
--------

`-a`, `--anonymous`
  Hide hostname prefix, defaults to `false`.

`-c`, `--color` *on|off|auto*
  Set color output, defaults to `auto`.

`-d`, `--debug`
  Enable debug info, defaults to `false`.

`-e`, `--exit-codes`
  Show command exit codes, defaults to `false`.

`-f`, `--file` *file*
  A file of hosts separated by newlines, defaults to `stdin`.

`-g`, `--group`
  Group output by hostname (`group mode`).

`-h`, `--help`
  Print this message and exit.

`-j`, `--join`
  Join hosts together by output (`join mode`).

`-m`, `--max-jobs` *num*
  Max processes to run concurrently, defaults to `50`.

`-n`, `--dry-run`
  Don't actually execute subprocesses.

`-s`, `--silent`
  Silence all output subprocess stdio, defaults to `false`.

`-t`, `--trim`
  Trim hostnames (remove domain) on output, defaults to `false`.

`-v`, `--version`
  Print the version number and exit.

`-x`, `--exec`
  Program to execute, defaults to `ssh`.

`--max-line-length` *num*
  Maximum line length (in `line mode` only), defaults to `1024`.

`--max-output-length` *num*
  Maximum output length (in `join mode` only), defaults to `8192`.

SSH OPTIONS: (passed directly to ssh)
-------------------------------------

`-i`, `--identity` *ident*
  ssh identity file to use.

`-l`, `--login` *name*
  The username to login as.

`-o`, `--option` *key=val*
  ssh option passed in key=value form.

`-p`, `--port` *port*
  The ssh port.

`-q`, `--quiet`
  Run ssh in quiet mode.

EXAMPLES
--------

Given the following hosts file called `hosts.txt`:

```
# example hosts file
arbiter.rapture.com
cifs.rapture.com
decomp.rapture.com
```

`sshp -f hosts.txt uname -v`

  Parallel ssh into hosts supplied by a file running `uname -v`.

`cat hosts.txt | sshp -e exit 0`

  Parallel ssh into hosts (via `stdin`) and print the exit codes (`-e`).

`sshp -d id -un < hosts.txt`

  Parallel ssh into hosts and run `id -un` with debug (`-d`) output enabled.

`sshp -f hosts.txt -m 1 -g command-to-run`

  Run with `-g` (`group mode`) to group the output by hostname as it comes in.
  Setting `-m` to `1` effectively turns `sshp` into an `ssh` serializer.

`sshp -f hosts.txt -j hostname`

  Run with `-j` (`join mode`) to join the output by the output itself and not
  the hostname.

SIGNALS
-------

`SIGUSR1`

  Send a `SIGUSR1` signal to `sshp` to print a status message to stdout.

BUGS
----

https://github.com/bahamas10/sshp

AUTHOR
------

`Dave Eddy <bahamas10> <dave@daveeddy.com> (https://www.daveeddy.com)`

SEE ALSO
--------

ssh(1)

LICENSE
-------

MIT License
