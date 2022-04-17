#ifndef SYSCALL_ANALYZER_SYSCALL_ANALYZER_H
#define SYSCALL_ANALYZER_SYSCALL_ANALYZER_H

/* Syscall analyzer.
   Goals:
   * run given executable and show syscalls it performs.

   The analyzer should only show syscalls, but don't
   show output of program (so because all output actually
   contained in `write` calls).
 */

typedef enum {
    ANALYZER_OPT_OUT_FILE,
    ANALYZER_OPT_OUT_BUFFER,
    ANALYZER_OPT_OUT_BUFFER_SIZE,
    ANALYZER_OPT_EXECUTABLE
} analyzer_opt_t;

void *analyzer_init();

void analyzer_destroy(void *handle);

void analyzer_setopt(void *handle, analyzer_opt_t opt, void *param);

int analyzer_perform(void *handle);

#endif //SYSCALL_ANALYZER_SYSCALL_ANALYZER_H
