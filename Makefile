CC := cc
CFLAGS := -Wall -Werror -Wextra -Wpedantic -O2 -lpthread

sshp: src/sshp.c
	$(CC) -o $@ $(CFLAGS) $^

.PHONY: clean
clean:
	rm -f sshp
