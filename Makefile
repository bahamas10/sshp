CC := cc
CFLAGS := -Wall -Werror -Wextra -Wpedantic -O2
PREFIX ?= /usr/local

# build targets
sshp: src/sshp.c
	$(CC) -o $@ $(CFLAGS) $^

.PHONY: man
man: man/sshp.1
man/sshp.1: man/sshp.md
	md2man-roff $^ > $@

.PHONY: all
all: sshp man

# clean targets
.PHONY: clean
clean:
	rm -f sshp

.PHONY: clean-man
clean-man:
	rm -f man/sshp.1

.PHONY: clean-all
clean-all: clean clean-man

# test targets
.PHONY: test
test: sshp
	./test

# install/uninstall targets
.PHONY: install
install: sshp man/sshp.1
	cp man/sshp.1 $(PREFIX)/man/man1
	cp sshp $(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/sshp
	rm -f $(PREFIX)/man/man1/sshp.1
