# `sshp` changelog

## not yet released

## `v1.1.5`

- Add GitHub Actions CI for Linux and macOS.
- Make signal handling safer and add coverage for `SIGUSR1`, `SIGTERM`, and
    `SIGINT`.
- [Issue 17](https://github.com/bahamas10/sshp/issues/17) - prevent child
    output from being silently truncated.
- [Issue 19](https://github.com/bahamas10/sshp/issues/19) - correctly report
    children terminated by signals as failures.
- [Issue 21](https://github.com/bahamas10/sshp/issues/21) - reject SSH
    destinations that begin with `-` or contain whitespace or control
    characters.
- [Issue 23](https://github.com/bahamas10/sshp/issues/23) - avoid blocking
    indefinitely when a running child closes its output streams.
- [Issue 25](https://github.com/bahamas10/sshp/issues/25) - prevent forked
    children from running inherited signal and exit handlers or flushing
    inherited output buffers.
- [PR 27](https://github.com/bahamas10/sshp/pull/27) - handle fd watcher
    registration errors.
- Avoid reading uninitialized entries returned by the fd watcher.
- [PR 28](https://github.com/bahamas10/sshp/pull/28) - reject malformed and
    out-of-range numeric options.
- [PR 29](https://github.com/bahamas10/sshp/pull/29) - retry interrupted and
    partial writes in group mode.
- Refresh the README, man page, and screenshots.

## `v1.1.4`

- [PR16](https://github.com/bahamas10/sshp/pull/16) - support hostnames
    without a trailing newline

## `v1.1.3`

- [Issue 5](https://github.com/bahamas10/sshp/issues/5) - define fdwatcher
    timeout unit

## `v1.1.2`

- [PR3](https://github.com/bahamas10/sshp/pull/3) - resolve compilation error on
    clang 15+

## `v1.1.1`

- Fix crash when receiving multiple signals.

## `v1.1.0`

- Add `-x` / `--exec` option.

## `v1.0.2`

- Fix segfault when destroying host objects in `join` mode.

## `v1.0.1`

- Use `atexit` to handle kill outstanding children if any exist.
- Add `make check` for style check.
- Add sick new logo :).

## `v1.0.0`

- Initial release.
