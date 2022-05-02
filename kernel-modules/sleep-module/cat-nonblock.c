/*
 * cat-nonblock.c - open a file and display its content, but exit
 * rather than wait for input.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_BYTES 1024 * 4

int main(int argc, char *argv[])
{
	int fd, i;
	size_t bytes;
	char buf[MAX_BYTES];

	if (argc != 2) {
		printf("Usage: %s <filename>.\n", argv[0]);
		return -1;
	}

	fd = open(argv[1], O_RDONLY | O_NONBLOCK);

	if (fd == -1) {
		puts(errno == EAGAIN ? "open would() block." : "open() failed.");
		return -1;
	}

	do {
		bytes = read(fd, buf, MAX_BYTES);

		if (bytes == -1) {
			if (errno == EAGAIN)
				puts("Normally I'd block, but you told me not to.");
			else
				perror("read()");
				
			return -1;
		}

		for (i = 0; i < bytes; ++i)
			putchar(buf[i]);
	} while (bytes > 0);

	return 0;
}
