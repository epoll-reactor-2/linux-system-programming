/*
 * util.c - Syscall analyzer utility.
 */
#include <stdio.h>

#include "syscall-analyzer.h"

// Example program, that shows design of this utility.
int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: ./syscall_analyzer <executable> <args...>");
		return 1;
	}

	char buf[8192];
	void *handle = analyzer_init();
	int bytes_read;
	char *out_file = "/tmp/syscall_out_buf";

	analyzer_setopt(handle, ANALYZER_OPT_ARGC, (void *) (long) argc);
	analyzer_setopt(handle, ANALYZER_OPT_ARGV, argv);
	analyzer_setopt(handle, ANALYZER_OPT_OUT_FILE, out_file);

	printf("%s returned:\n", argv[1]);

	analyzer_perform(handle);
	analyzer_destroy(handle);

	puts("\n");
	
	FILE *fd = fopen(out_file, "r");
	while ((bytes_read = fread(buf, 1, sizeof(buf), fd)) > 0) {
		if (printf("%.*s", bytes_read, buf) != bytes_read) {
			perror("printf");
			goto exit;
		}
	}

exit:
	if (fclose(fd) == EOF) {
		perror("fclose");
		return -1;
	}

	if (remove(out_file) == -1) {
		perror("remove");
		return -1;
	}

	return 0;
}
