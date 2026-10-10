sshp tests
==========

This directory contains program tests for `sshp`.

Files
-----

- `test_*`

These files are scripts (can be any form of executable really) that test
various parts of `sshp` functionality.  They handle printing some meaningful
output to the console, and die with a code of 0 on success, or anything else on
failure.

- `runtest`

This script is a helper program to run multiple tests serially.  This is the
main entry point from `make test` in the above directory, and can be invoked
with 1 or many tests, for example:

``` console
$ ./runtest test_usage
...
...
...
$ ./runtest test_*
...
...
...
```

- `lib/`

Helper scripts or bash functions for use by the tests.

- `assets/`

Non-executable or sourceable helper files for use by the tests.

Common assertions
-----------------

Source `lib/helpers` to use the common assertions.  For deterministic output
store the expected output in `assets/output/` and compare it exactly:

``` bash
verify-sshp-output 0 ./assets/hosts/simple-hosts.txt \
	./assets/output/join-output.txt -x ./assets/cmd/join-output -j arg
```

Or just count the number of lines generated:

``` bash
verify-sshp-lines 0 ./assets/hosts/single-host.txt \
	200000 -x ./assets/cmd/large-output -a arg
```

### Usage

- `verify-sshp-output <code> <input> <output> [sshp args ...]`
- `verify-sshp-lines <code> <input> <lines> [sshp args ...]`
