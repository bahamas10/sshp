SSHP 1 "October 9, 2026" "General Commands Manual"
==================================================

NAME
----

`sshp` - Parallel SSH Executor.

SYNOPSIS
--------

`sshp [OPTIONS] <command> [arg ...]`

`sshp [-f hosts.txt] [-g | -j] <command> [arg ...]`

DESCRIPTION
-----------

Parallel SSH executor and manager.

`sshp` manages multiple ssh processes and handles coalescing their output to
the terminal.  It reads newline-separated hostnames or IP addresses from
standard input or a file specified with `-f`, then starts an ssh subprocess
for each host.  Child stdout and stderr are written to `sshp`'s standard
output.

MODES
-----

`sshp` has three modes of execution:

- `line mode` (line-by-line output, default).
- `group mode` (grouped by hostname output, `-g`).
- `join mode` (grouped by unique output, `-j`).

The first two modes, `line` and `group`, operate in largely the same
way.  They differ only in how data is buffered from the child processes and
printed to the screen.  Line mode buffers the data line-by-line, whereas group
mode does no buffering at all and prints the data once it is read from the
child.

The last mode, `join`, however, buffers *all* data from all child
processes and produces output once every process has finished.  Instead of
grouping the output by host, it groups identical output and lists the hosts
that produced it.

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
  Join hosts together by output (`join mode`).  This option is mutually
  exclusive with `-a`, `-g`, and `-s`.

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

`-x`, `--exec` *prog*
  Program to execute, defaults to `ssh`.

`--max-line-length` *num*
  Maximum line length (in `line mode` only), defaults to `1024`.

`--max-output-length` *num*
  Maximum output length (in `join mode` only), defaults to `8192`.

SSH OPTIONS
-----------

The following options are passed directly to `ssh`:

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

  Run `uname -v` in parallel on hosts supplied by a file.

`sshp -e exit 0 < hosts.txt`

  Parallel ssh into hosts (via `stdin`) and print the exit codes (`-e`).

`sshp -d id -un < hosts.txt`

  Parallel ssh into hosts and run `id -un` with debug (`-d`) output
  enabled.

`sshp -f hosts.txt -m 1 -g command-to-run`

  Run with `-g` (`group mode`) to group the output by hostname as it
  comes in.  Setting `-m` to `1` effectively turns `sshp` into an
  `ssh` serializer.

`sshp -f hosts.txt -j hostname`

  Run with `-j` (`join mode`) to group hosts that produce identical
  output.

EXIT STATUS
-----------

`0`

  All child processes exited successfully.

`1`

  One or more child processes exited with a non-zero status.

`2`

  Incorrect usage, such as an unknown option or invalid hosts file.

`3`

  A system or internal program failure prevented `sshp` from running.

`4`

  `sshp` exited after receiving `SIGTERM` or `SIGINT`.

SIGNALS
-------

`SIGUSR1`

  Send a `SIGUSR1` signal to `sshp` to print a status message to stdout.

`SIGINT`, `SIGTERM`

  Terminate running child processes and exit with status `4`.

BUGS
----

https://github.com/bahamas10/sshp/issues

AUTHOR
------

Dave Eddy (`bahamas10`) <dave@daveeddy.com> (https://www.daveeddy.com)

SEE ALSO
--------

ssh(1)

ssh_config(5)

LICENSE
-------

MIT License
