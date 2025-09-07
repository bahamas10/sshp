CC ?= cc
CFLAGS ?= -Wall -Werror -Wextra -Wpedantic -O2
PREFIX ?= /usr/local
UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
	USE_KQUEUE ?= 1
else ifeq ($(UNAME),FreeBSD)
	USE_KQUEUE ?= 1
else
	# epoll is default
	USE_KQUEUE ?= 0
endif

# build targets
sshp: src/sshp.c src/fdwatcher.o
	$(CC) -o $@ $(CFLAGS) $^

src/fdwatcher.o: src/fdwatcher.c src/fdwatcher.h
	$(CC) -o $@ -c -D USE_KQUEUE=$(USE_KQUEUE) $(CFLAGS) $<

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
	rm -f src/*.o

.PHONY: clean-man
clean-man:
	rm -f man/sshp.1

.PHONY: clean-all
clean-all: clean clean-man

# test targets
.PHONY: test
test: sshp
	cd test && ./runtest test_*

.PHONY: check
check:
	./tools/check src/*.h src/*.c test/* man/*.md

# install/uninstall targets
.PHONY: install
install: sshp
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/man/man1
	cp man/sshp.1 $(PREFIX)/man/man1
	cp sshp $(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/sshp
	rm -f $(PREFIX)/man/man1/sshp.1
