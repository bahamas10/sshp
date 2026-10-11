/*
 * Attempt to read a char from stdin
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	char c;
	ssize_t bytes;

	do {
		bytes = read(STDIN_FILENO, &c, 1);
	} while (bytes == -1 && errno == EINTR);

	if (bytes == -1) {
		printf("read error: %s\n", strerror(errno));
		return 1;
	}

	if (bytes == 1) {
		printf("read data: <%c>\n", c);
		return 1;
	}

	printf("eof\n");
	return 0;
}
