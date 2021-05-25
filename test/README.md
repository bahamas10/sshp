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
