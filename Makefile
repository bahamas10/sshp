CC := cc
CFLAGS := -Wall -Werror -Wextra -Wpedantic -O2
PREFIX ?= /usr/local

sshp: src/sshp.c
	$(CC) -o $@ $(CFLAGS) $^

.PHONY: test
test: sshp
	./test

.PHONY: man
man: man/sshp.1
man/sshp.1: man/sshp.md
	md2man-roff $^ > $@

.PHONY: install
install: sshp man/sshp.1
	cp man/sshp.1 $(PREFIX)/man/man1
	cp sshp $(PREFIX)/bin

.PHONY: clean
clean:
	rm -f sshp
	rm -f man/sshp.1

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/sshp
	rm -f $(PREFIX)/man/man1/sshp.1
