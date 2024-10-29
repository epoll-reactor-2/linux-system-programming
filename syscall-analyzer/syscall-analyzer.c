/*
 * syscall-analyzer.c - Library to be able see executed by program syscalls.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <syscall.h>

#include "syscall-analyzer.h"

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))

/* Internal context. */
struct analyzer_context {
	void    *output_file_path;
	void    *output_buffer;
	void    *output_buffer_size;
	FILE    *output_fd;
	void    *argc;
	char   **argv;
	size_t   bytes_been_written;
};

void *analyzer_init()
{
	 struct analyzer_context *analyzer =
	(struct analyzer_context *) malloc(sizeof (struct analyzer_context));

	if (!analyzer) {
		perror("malloc");
		exit(-1);
	}
	analyzer->output_file_path = NULL;
	analyzer->output_buffer = NULL;
	analyzer->output_buffer_size = NULL;
	analyzer->output_fd = NULL;
	analyzer->argc = 0;
	analyzer->argv = NULL;
	analyzer->bytes_been_written = 0;
	return analyzer;
}

void analyzer_destroy(void *handle)
{
	struct analyzer_context *analyzer = (struct analyzer_context *)handle;

	if (analyzer->output_fd) {
		if (fclose(analyzer->output_fd) == EOF) {
			perror("fclose");
			exit(-1);
		}
	}

	free(analyzer);
}

__attribute__((noreturn, format(printf, 1, 2)))
static void analyzer_fatal()
{
	printf("Error: %s\n", strerror(errno));

	abort();
}

/* Setup analyzer option. Can be called multiple times.
   Analyzer holds only last passed parameter. */
void analyzer_setopt(void *handle, int opt, void *param)
{
	struct analyzer_context *analyzer = (struct analyzer_context *) handle;

	switch (opt) {
	case ANALYZER_OPT_OUT_BUFFER:
		analyzer->output_buffer = param;
		break;

	case ANALYZER_OPT_OUT_BUFFER_SIZE:
		analyzer->output_buffer_size = param;
		break;

	case ANALYZER_OPT_OUT_FILE:
		analyzer->output_file_path = param;
		break;

	case ANALYZER_OPT_ARGC:
		analyzer->argc = param;
		break;

	case ANALYZER_OPT_ARGV:
		analyzer->argv = param;
		break;

	default:
		break;
	}
}

static void analyzer_ensure_buffers_are_set(struct analyzer_context *analyzer)
{
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

static void analyzer_configure_buffer(struct analyzer_context *analyzer)
{
	if (analyzer->output_buffer)
	return;

	analyzer->output_fd = fopen(analyzer->output_file_path, "w");

	if (!analyzer->output_fd) {
		perror("fopen");
		exit(-1);
	}
}

/* Run given executable and collect data about performed syscalls. */
static void analyzer_inspect_executable(struct analyzer_context *analyzer);

int analyzer_perform(void *handle)
{
	struct analyzer_context *analyzer = (struct analyzer_context *)handle;

	analyzer_ensure_buffers_are_set(analyzer);
	analyzer_configure_buffer(analyzer);
	analyzer_inspect_executable(analyzer);

	return 0;
}

/* Write to specified in handle file or buffer. */
__attribute__((format(printf, 2, 3)))
static void analyzer_write(struct analyzer_context *analyzer, const char *fmt, ...)
{
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

/* Translate syscall code to readable string. */
static const char *syscall_to_string(long syscall)
{
	static const char *syscall_map[] = {
		"read",               "write",              "open",                   "close",                  "stat",                  "fstat",
		"lstat",              "poll",               "lseek",                  "mmap",                   "mprotect",              "munmap",
		"brk",                "rt_sigaction",       "rt_sigprocmask",         "rt_sigreturn",           "ioctl",                 "pread64",
		"pwrite64",           "readv",              "writev",                 "access",                 "pipe",                  "select",
		"sched_yield",        "mremap",             "msync",                  "mincore",                "madvise",               "shmget",
		"shmat",              "shmctl",             "dup",                    "dup2",                   "pause",                 "nanosleep",
		"getitimer",          "alarm",              "setitimer",              "getpid",                 "sendfile",              "socket",
		"connect",            "accept",             "sendto",                 "recvfrom",               "sendmsg",               "recvmsg",
		"shutdown",           "bind",               "listen",                 "getsockname",            "getpeername",           "socketpair",
		"setsockopt",         "getsockopt",         "clone",                  "fork",                   "vfork",                 "execve",
		"exit",               "wait4",              "kill",                   "uname",                  "semget",                "semop",
		"semctl",             "shmdt",              "msgget",                 "msgsnd",                 "msgrcv",                "msgctl",
		"fcntl",              "flock",              "fsync",                  "fdatasync",              "truncate",              "ftruncate",
		"getdents",           "getcwd",             "chdir",                  "fchdir",                 "rename",                "mkdir",
		"rmdir",              "creat",              "link",                   "unlink",                 "symlink",               "readlink",
		"chmod",              "fchmod",             "chown",                  "fchown",                 "lchown",                "umask",
		"gettimeofday",       "getrlimit",          "getrusage",              "sysinfo",                "times",                 "ptrace",
		"getuid",             "syslog",             "getgid",                 "setuid",                 "setgid",                "geteuid",
		"getegid",            "setpgid",            "getppid",                "getpgrp",                "setsid",                "setreuid",
		"setregid",           "getgroups",          "setgroups",              "setresuid",              "getresuid",             "setresgid",
		"getresgid",          "getpgid",            "setfsuid",               "setfsgid",               "getsid",                "capget",
		"capset",             "rt_sigpending",      "rt_sigtimedwait",        "rt_sigqueueinfo",        "rt_sigsuspend",         "sigaltstack",
		"utime",              "mknod",              "uselib",                 "personality",            "ustat",                 "statfs",
		"fstatfs",            "sysfs",              "getpriority",            "setpriority",            "sched_setparam",        "sched_getparam",
		"sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock",
		"munlock",            "mlockall",           "munlockall",             "vhangup",                "modify_ldt",            "pivot_root",
		"_sysctl",            "prctl",              "arch_prctl",             "adjtimex",               "setrlimit",             "chroot",
		"sync",               "acct",               "settimeofday",           "mount",                  "umount2",               "swapon",
		"swapoff",            "reboot",             "sethostname",            "setdomainname",          "iopl",                  "ioperm",
		"create_module",      "init_module",        "delete_module",          "get_kernel_syms",        "query_module",          "quotactl",
		"nfsservctl",         "getpmsg",            "putpmsg",                "afs_syscall",            "tuxcall",               "security",
		"gettid",             "readahead",          "setxattr",               "lsetxattr",              "fsetxattr",             "getxattr",
		"lgetxattr",          "fgetxattr",          "listxattr",              "llistxattr",             "flistxattr",            "removexattr",
		"lremovexattr",       "fremovexattr",       "tkill",                  "time",                   "futex",                 "sched_setaffinity",
		"sched_getaffinity",  "set_thread_area",    "io_setup",               "io_destroy",             "io_getevents",          "io_submit",
		"io_cancel",          "get_thread_area",    "lookup_dcookie",         "epoll_create",           "epoll_ctl_old",         "epoll_wait_old",
		"remap_file_pages",   "getdents64",         "set_tid_address",        "restart_syscall",        "semtimedop",            "fadvise64",
		"timer_create",       "timer_settime",      "timer_gettime",          "timer_getoverrun",       "timer_delete",          "clock_settime",
		"clock_gettime",      "clock_getres",       "clock_nanosleep",        "exit_group",             "epoll_wait",            "epoll_ctl",
		"tgkill",             "utimes",             "vserver",                "mbind",                  "set_mempolicy",         "get_mempolicy",
		"mq_open",            "mq_unlink",          "mq_timedsend",           "mq_timedreceive",        "mq_notify",             "mq_getsetattr",
		"kexec_load",         "waitid",             "add_key",                "request_key",            "keyctl",                "ioprio_set",
		"ioprio_get",         "inotify_init",       "inotify_add_watch",      "inotify_rm_watch",       "migrate_pages",         "openat",
		"mkdirat",            "mknodat",            "fchownat",               "futimesat",              "newfstatat",            "unlinkat",
		"renameat",           "linkat",             "symlinkat",              "readlinkat",             "fchmodat",              "faccessat",
		"pselect6",           "ppoll",              "unshare",                "set_robust_list",        "get_robust_list",       "splice",
		"tee",                "sync_file_range",    "vmsplice",               "move_pages",             "utimensat",             "epoll_pwait",
		"signalfd",           "timerfd_create",     "eventfd",                "fallocate",              "timerfd_settime",       "timerfd_gettime",
		"accept4",            "signalfd4",          "eventfd2",               "epoll_create1",          "dup3",                  "pipe2",
		"inotify_init1",      "preadv",             "pwritev",                "rt_tgsigqueueinfo",      "perf_event_open",       "recvmmsg",
		"fanotify_init",      "fanotify_mark",      "prlimit64",              "name_to_handle_at",      "open_by_handle_at",     "clock_adjtime",
		"syncfs",             "sendmmsg",           "setns",                  "getcpu",                 "process_vm_readv",      "process_vm_writev",
		"kcmp",               "finit_module",       "sched_setattr",          "sched_getattr",          "renameat2",             "seccomp",
		"getrandom",          "memfd_create",       "kexec_file_load",        "bpf",                    "execveat",              "userfaultfd",
		"membarrier",         "mlock2",             "copy_file_range",        "preadv2",                "pwritev2",              "pkey_mprotect",
		"pkey_alloc",         "pkey_free",          "statx"
	};

	if (syscall < 0 || syscall >= ARRAY_SIZE(syscall_map))
		return "unknown_syscall";

	return syscall_map[syscall];
}

/* Read len bytes from address to buf. */
static ssize_t remote_process_read_address(pid_t pid, void *address, char *buf, long buf_size)
{
	struct iovec local[1] = {0};
	struct iovec remote[1] = {0};
	ssize_t was_read;

	local[0].iov_base = (void *)buf;
	local[0].iov_len = buf_size;

	remote[0].iov_base = address;
	remote[0].iov_len = buf_size;

	was_read = process_vm_readv(pid, local, 1, remote, 1, 0);

	if (was_read < 0)
		analyzer_fatal();

	return was_read;
}

static void remote_process_read_string(pid_t pid, void *address, char *buf, long buf_size)
{
	ssize_t was_read = remote_process_read_address(pid, address, buf, buf_size);
	buf[was_read] = '\0';
}

#define __append_on_match(x) \
	if (parameter & x) \
		flags_written += sprintf(buf + flags_written, #x "|");

static void fmt_oflags(unsigned long long parameter, char *buf)
{
	long flags_written = 0;

	if (!(parameter & O_RDONLY) /* O_RDONLY == 0 */)
		flags_written += sprintf(buf + flags_written, "O_RDONLY|");

	__append_on_match(O_WRONLY)
	__append_on_match(O_RDWR)
	__append_on_match(O_CREAT)
	__append_on_match(O_EXCL)
	__append_on_match(O_NOCTTY)
	__append_on_match(O_TRUNC)
	__append_on_match(O_ASYNC)
	__append_on_match(O_FSYNC)
	__append_on_match(O_NONBLOCK)
	__append_on_match(O_CLOEXEC)

	if (buf[flags_written - 1] == '|')
		buf[flags_written - 1] = '\0';
}

// I guess, access() allowed to be called with F_OK... OR
// with any combination of R_OK, W_OK, X_OK.
static void fmt_access_flags(unsigned long long parameter, char *buf)
{
	long flags_written = 0;

	if (parameter == F_OK) {
		flags_written += sprintf(buf + flags_written, "F_OK");
		return;
	}

	__append_on_match(R_OK)
	__append_on_match(W_OK)
	__append_on_match(X_OK)

	if (buf[flags_written - 1] == '|')
		buf[flags_written - 1] = '\0';
}

static void fmt_mmap_prot_flags(unsigned long long parameter, char *buf)
{
	long flags_written = 0;

	if (parameter == PROT_NONE) {
		flags_written += sprintf(buf + flags_written, "PROT_NONE");
		return;
	}

	__append_on_match(PROT_READ)
	__append_on_match(PROT_WRITE)
	__append_on_match(PROT_EXEC)
	__append_on_match(PROT_GROWSDOWN)
	__append_on_match(PROT_GROWSUP)

	if (buf[flags_written - 1] == '|')
		buf[flags_written - 1] = '\0';
}

unsigned long long fmt_mmap_map_flags(unsigned long long parameter, char *buf)
{
	long flags_written = 0;

	__append_on_match(MAP_SHARED)
	__append_on_match(MAP_PRIVATE)
	__append_on_match(MAP_TYPE)
	__append_on_match(MAP_FIXED)
	__append_on_match(MAP_ANON)
#ifdef __USE_MISC
	__append_on_match(MAP_SHARED_VALIDATE)
	__append_on_match(MAP_GROWSDOWN)
	__append_on_match(MAP_DENYWRITE)
	__append_on_match(MAP_EXECUTABLE)
	__append_on_match(MAP_LOCKED)
	__append_on_match(MAP_NORESERVE)
	__append_on_match(MAP_POPULATE)
	__append_on_match(MAP_NONBLOCK)
	__append_on_match(MAP_STACK)
	__append_on_match(MAP_HUGETLB)
	__append_on_match(MAP_SYNC)
	__append_on_match(MAP_FIXED_NOREPLACE)
#endif /* __USE_MISC */

	if (buf[flags_written - 1] == '|')
		buf[flags_written - 1] = '\0';
}

// A few examples of syscall parameters resolving with the help of
// https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md.
// Other syscalls pretty prints can be done the same way.
static void syscall_write_format(struct analyzer_context *analyzer, pid_t pid, struct user_regs_struct regs)
{
	char buf[64];
	unsigned i;

	remote_process_read_string(pid, /* char *buf */(void *) regs.rsi, buf, sizeof (buf));

	for (i = 0; i < sizeof(buf); ++i)
		if (buf[i] == '\n')
			buf[i] = ' ';

	analyzer_write(analyzer,
		"fd = %lld, buf = \"%s\", count = %lld",
		regs.rdi, buf, regs.rdx
	);
}

static void syscall_access_format(struct analyzer_context *analyzer, pid_t pid, struct user_regs_struct regs)
{
	char buf[128];
	char flags[128];
	unsigned i;

	remote_process_read_string(pid, /* char *buf */ (void *) regs.rdi, buf, sizeof (buf));
	fmt_access_flags(/* int flags */ regs.rsi, flags);

	for (i = 0; i < sizeof(buf); ++i)
		if (buf[i] == '\n')
			buf[i] = ' ';

	analyzer_write(analyzer,
		"filename = \"%s\", mode = %s",
		buf, flags);
}

static void syscall_mmap_format(struct analyzer_context *analyzer, struct user_regs_struct regs)
{
	char prot_flags[128];
	char map_flags[128];

	fmt_mmap_prot_flags(regs.rdx, prot_flags);
	fmt_mmap_map_flags(regs.r10, map_flags);

	analyzer_write(analyzer,
		"addr = 0x%llx, length = 0x%llx, prot = %s, flags = %s, fd = %llx, offset = 0x%llx",
		regs.rdi, regs.rsi, prot_flags, map_flags, regs.r8, regs.r9);
}


static void syscall_openat_format(struct analyzer_context *analyzer, pid_t pid, struct user_regs_struct regs)
{
	char filename[128];
	char oflags[128];

	remote_process_read_string(pid, /* char *buf */(void *)regs.rsi, filename, sizeof(filename));
	fmt_oflags(/* int flags */regs.rdx, oflags);

	analyzer_write(analyzer,
		"dfd = %lld, filename = \"%s\", flags = %s",
		regs.rdi, filename, oflags
	);
}

/* Append syscall with its parameters to handle buffer. */
static void syscall_format(struct analyzer_context *analyzer, pid_t pid, long syscall, struct user_regs_struct regs)
{
	analyzer_write(analyzer, "%s(", syscall_to_string(syscall));

	switch (syscall) {
	case __NR_write:
		syscall_write_format(analyzer, pid, regs);
		break;

	case __NR_access:
		syscall_access_format(analyzer, pid, regs);
		break;

	case __NR_mmap:
		syscall_mmap_format(analyzer, regs);
		break;

	case __NR_openat:
		syscall_openat_format(analyzer, pid, regs);
		break;

	default:
		analyzer_write(analyzer,
			"rdi = %lld, rsi = %lld, rdx = %lld, r10 = %lld, r8 = %lld, r9 = %lld ",
			regs.rdi, regs.rsi, regs.rdx,
			regs.r10, regs.r8,  regs.r9);
		break;
	}

	analyzer_write(analyzer, ")");
}

static void run_syscall(pid_t pid)
{
	// Run syscall and stop on exit.
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
		analyzer_fatal();

	if (waitpid(pid, 0, 0) == -1)
		analyzer_fatal();
}

static struct user_regs_struct get_syscall_regs(pid_t pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
		analyzer_fatal();

	return regs;
}

static void analyzer_inspect_executable(struct analyzer_context *analyzer)
{
	pid_t pid = fork();

	if (pid == 0) {
		ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
		char  *arg  =  analyzer->argv[1];
		char **args = &analyzer->argv[1];
		execvp(arg, args);
	} else if (pid == -1) {
		analyzer_fatal();
	}

	waitpid(pid, 0, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

	while (1) {
		run_syscall(pid);

		struct user_regs_struct regs = get_syscall_regs(pid);
		long syscall = regs.orig_rax;
		syscall_format(analyzer, pid, syscall, regs);

		run_syscall(pid);

		// Get syscall result.
		if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
			analyzer_write(analyzer, " = ?\n");
			// No process or process group can be found corresponding to that specified by pid.
			if (errno == ESRCH)
				break;
		}

		// Print syscall exit code.
		analyzer_write(analyzer, " = %lld\n", regs.rax);
	}
}

#undef ARRAY_SIZE
