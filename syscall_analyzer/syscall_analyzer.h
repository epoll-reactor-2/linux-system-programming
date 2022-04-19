#ifndef SYSCALL_ANALYZER_SYSCALL_ANALYZER_H
#define SYSCALL_ANALYZER_SYSCALL_ANALYZER_H

typedef enum {
    ANALYZER_OPT_ARGC,
    ANALYZER_OPT_ARGV,
    ANALYZER_OPT_OUT_FILE,
    ANALYZER_OPT_OUT_BUFFER,
    ANALYZER_OPT_OUT_BUFFER_SIZE
} analyzer_opt_t;

void *analyzer_init();

void analyzer_destroy(void *handle);

void analyzer_setopt(void *handle, analyzer_opt_t opt, void *param);

int analyzer_perform(void *handle);

#endif //SYSCALL_ANALYZER_SYSCALL_ANALYZER_H
