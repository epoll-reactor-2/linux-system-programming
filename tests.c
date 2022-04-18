#include <stdio.h>

#include "syscall_analyzer.h"

int main() {
    char out_buffer[65536];
    void *handle = analyzer_init();

    printf("Showing `ls` command syscalls...\n");

    analyzer_setopt(handle, ANALYZER_OPT_EXECUTABLE, "/bin/ls");
    analyzer_setopt(handle, ANALYZER_OPT_OUT_BUFFER_SIZE, sizeof(out_buffer));
    analyzer_setopt(handle, ANALYZER_OPT_OUT_BUFFER, out_buffer);

    analyzer_perform(handle);
    analyzer_destroy(handle);

    printf("\n%s\n", out_buffer);
}
