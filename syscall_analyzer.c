#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscall_analyzer.h"

typedef struct analyzer_handle_t {
    void  *output_file_path;
    void  *output_buffer;
    void  *output_buffer_size;
    void  *executable_path;
    FILE  *output_fd;
    size_t bytes_been_written;
} analyzer_handle_t;

void *analyzer_init() {
    analyzer_handle_t *analyzer = (analyzer_handle_t *)malloc(sizeof(analyzer_handle_t));
    analyzer->output_file_path = NULL;
    analyzer->output_buffer = NULL;
    analyzer->output_buffer_size = NULL;
    analyzer->executable_path = NULL;
    analyzer->output_fd = NULL;
    analyzer->bytes_been_written = 0;
    return analyzer;
}

void analyzer_destroy(void *handle) {
    analyzer_handle_t *analyzer = (analyzer_handle_t *)handle;
    free(analyzer);
}

void analyzer_setopt(void *handle, analyzer_opt_t opt, void *param) {
    analyzer_handle_t *analyzer = (analyzer_handle_t *)handle;

    switch (opt) {
    case ANALYZER_OPT_OUT_BUFFER:
        analyzer->output_buffer = param;
        break;

    case ANALYZER_OPT_OUT_BUFFER_SIZE:
        analyzer->output_buffer_size = param;
        break;

    case ANALYZER_OPT_EXECUTABLE:
        analyzer->executable_path = param;
        break;

    case ANALYZER_OPT_OUT_FILE:
        analyzer->output_file_path = param;
        break;

    default:
        break;
    }
}

static void analyzer_ensure_buffers_are_set(analyzer_handle_t *analyzer) {
    if (analyzer->output_buffer && analyzer->output_file_path) {
        fprintf(stderr, "Only one output buffer expected.");
        abort();
    }

    if (analyzer->output_buffer) {
        if (!analyzer->output_buffer_size) {
            fprintf(stderr, "Buffer size required.");
            abort();
        }
        return;
    }

    if (analyzer->output_file_path)
        return;

    analyzer->output_file_path = "/dev/stdout";
}

static void analyzer_configure_buffer(analyzer_handle_t *analyzer) {
    if (analyzer->output_buffer)
        return;

    analyzer->output_fd = fopen(analyzer->output_file_path, "w");
}

__attribute__((format(printf, 2, 3)))
static void analyzer_write(analyzer_handle_t *analyzer, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    if (analyzer->output_fd) {
        analyzer->bytes_been_written += vfprintf(analyzer->output_fd, fmt, args);
    } else {
        analyzer->bytes_been_written += vsprintf(analyzer->output_buffer + analyzer->bytes_been_written, fmt, args);
    }

    va_end(args);

    if (analyzer->output_buffer_size) {
        size_t buffer_size = (size_t)analyzer->output_buffer_size;
        if (analyzer->bytes_been_written >= buffer_size) {
            fprintf(stderr, "Buffer overflow.");
            abort();
        }
    }
}

__attribute__((noreturn, format(printf, 1, 2)))
static void analyzer_fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, fmt, args);

    va_end(args);

    abort();
}

static const char *syscall_to_string(long syscall);
static void syscall_regs_to_string(analyzer_handle_t *analyzer, long syscall, struct user_regs_struct regs);

static void analyzer_run_executable(analyzer_handle_t *analyzer) {
    pid_t pid = fork();
    switch (pid) {
        case -1:
            analyzer_fatal("Error: %s\n", strerror(errno));
        case 0: {
            ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
            char *cmd = analyzer->executable_path;
            char *argv[2];
            argv[0] = cmd;
            argv[1] = NULL;
            execvp(cmd, argv);
            analyzer_fatal("Error: %s\n", strerror(errno));
        }
    }

    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0))
            analyzer_fatal("Error: %s\n", strerror(errno));

        if (waitpid(pid, 0, 0) == -1)
            analyzer_fatal("Error: %s\n", strerror(errno));

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            analyzer_fatal("Error: %s\n", strerror(errno));

        long syscall = regs.orig_rax;

        syscall_regs_to_string(analyzer, syscall, regs);

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            analyzer_fatal("Error: %s\n", strerror(errno));

        if (waitpid(pid, 0, 0) == -1)
            analyzer_fatal("Error: %s\n", strerror(errno));

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            analyzer_write(analyzer, " = ?\n");
            if (errno == ESRCH)
                break;
        }

        analyzer_write(analyzer, " = %lld\n", regs.rax);
    }
}

int analyzer_perform(void *handle) {
    analyzer_handle_t *analyzer = (analyzer_handle_t *)handle;

    analyzer_ensure_buffers_are_set(analyzer);
    analyzer_configure_buffer(analyzer);
    analyzer_run_executable(analyzer);

    return 0;
}

static const char *syscall_to_string(long syscall) {
    static const char *syscall_map[] = {
        "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access",
        "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup",
        "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect",
        "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
        "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4",
        "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl",
        "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
        "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown",
        "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog",
        "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid",
        "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid",
        "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs",
        "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall",
        "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
        "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname",
        "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid",
        "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
        "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex",
        "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents",
        "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
        "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop",
        "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete",
        "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl",
        "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink",
        "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key",
        "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
        "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
        "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare",
        "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
        "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
        "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1",
        "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark",
        "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns",
        "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module",
    };
    return syscall_map[syscall];
}

static void syscall_regs_to_string(analyzer_handle_t *analyzer, long syscall, struct user_regs_struct regs) {
    analyzer_write(analyzer, "%s(", syscall_to_string(syscall));

    switch (syscall) {
//        case /*read*/0: {
//            analyzer_write(analyzer, "%lld, %lld, %lld", regs.rdi, regs.rsi, regs.rdx);
//            break;
//        }

        default:
            analyzer_write(analyzer,
                "rdi = %lld, rsi = %lld, rdx = %lld, r10 = %lld, r8 = %lld, r9 = %lld ",
                regs.rdi, regs.rsi, regs.rdx,
                regs.r10, regs.r8,  regs.r9
            );
            break;
    }

    analyzer_write(analyzer, ")");
}
