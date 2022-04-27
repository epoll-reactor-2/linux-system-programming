/*
 * syscall-spy.c - System call "stealing" sample.
 *
 * Disables page protection at a processor level by changing the 16th
 * bit in the cr0 register (could be Intel specific).
 *
 * Based on example by Peter Jay Salzman and
 * https://bbs.archlinux.org/viewtopic.php?id=139406.
 */
#include <linux/delay.h>       // msleep()
#include <linux/kernel.h>      // pr_info()
#include <linux/module.h>      // __init, __exit
#include <linux/moduleparam.h> // module_param
#include <linux/version.h>     // LINUX_VERSION_CODE, KERNEL_VERSION

// For the current process structure, we need this to know
// who the current user is.
#include <linux/sched.h>
#include <linux/uaccess.h>

/* The way we access sys_call_table varies as kernel internal changes.
 * - Prior to v5.4 : manual symbol lookup,
 * - v5.5 to v.5.6 : use kallsyms_lookup_name(),
 * - v5.7+         : Kprobes or specific kernel module parameter.
 */

// The in-kernel calls to the ksys_close() syscall were removed in Linux v5.11+.
#if (LINUX_VERSION_CODE <  KERNEL_VERSION(5, 7, 0))
# if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 0))
#  define HAVE_KSYS_CLOSE 1
#  include <linux/syscalls.h> // ksys_close()
# else
#  include <linux/kallsyms.h> // kallsyms_lookup_name
# endif
#else
#if defined (CONFIG_KPROBES)
# define HAVE_KPROBES 1
# include <linux/kprobes.h>
#else
# define HAVE_PARAM 1
# include <linux/kallsyms.h> // sprint_symbol()
  // The address of sys_call_table.
  static unsigned long sym = 0;
  module_param(sym, ulong, 0644);
#endif // CONFIG_KPROBES
#endif // Version < 5.7.0

static unsigned long **sys_call_table;

// UID we want to spy on.
static int uid;
module_param(uid, int, 0644);

// A pointer to the original system call.
static asmlinkage int (*original_call)(const char *, int, int);

// The function we will replace sys_open.
static asmlinkage int funny_sys_open(const char *filename, int flags, int mode)
{
	int i = 0;
	char ch;

	pr_info("syscall_spy: Opened file by %d: ", uid);
	do {
		get_user(ch, (char __user *)filename + i);
		++i;
		pr_info("%c", ch);
	} while (ch != '\0');
	pr_info("\n");
	return original_call(filename, flags, mode);
}

static unsigned long **aquire_sys_call_table(void)
{
#ifdef HAVE_KSYS_CLOSE
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *)ksys_close)
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
#endif

#ifdef HAVE_PARAM
	const char sct_name[] = "sys_call_table";
	char symbol[40] = {0};

	if (sym == 0) {
		pr_alert("For Linux v5.7+, Kprobes is the preferable way to get "
		         "symbol.\n");
         	pr_info("If Kprobes is absent, you have to specify the address of "
        	        "sys_call_table symbol.\n");
		pr_info("by /boot/System.map or /proc/kallsyms, which contains all the"
		        "symbol addresses, into sym parameter.\n");
	        return NULL;
	}
	sprint_symbol(symbol, sym);
	if (!strncmp(sct_name, symbol, sizeof(sct_name) - 1))
		return (unsigned long **)sym;

	return NULL;
#endif

#ifdef HAVE_KPROBES
	unsigned long (*kallsyms_lookup_name)(const char *);
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	if (register_kprobe(&kp) < 0)
		return NULL;

	kallsyms_lookup_name = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);
#endif
	return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
 static inline void __write_cr0(unsigned long cr0)
 {
	asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
 }
#else
# define __write_cr0 write_cr0
#endif

static void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	__write_cr0(cr0);
}

static void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	__write_cr0(cr0);
}

static int __init spy_syscall_init(void)
{
	if (!(sys_call_table = aquire_sys_call_table()))
		return -1;

	disable_write_protection();

	// Keep track of the original open function.
	original_call = (void *)sys_call_table[__NR_open];

	// Use funny syscall.
	sys_call_table[__NR_open] = (unsigned long *)funny_sys_open;

	enable_write_protection();

	pr_info("Spying on UID = %d.\n", uid);

	return 0;
}

static void __exit spy_syscall_exit(void)
{
	if (!sys_call_table)
		return;

	// Return the system call back to normal.
	if (sys_call_table[__NR_open] != (unsigned long *)funny_sys_open) {
		pr_alert("Somebody else also played with the open syscall\n"
		         "The system may be left in unstable state.\n");
	}

	disable_write_protection();
	sys_call_table[__NR_open] = (unsigned long *)original_call;
	enable_write_protection();

	msleep(2000);
}

module_init(spy_syscall_init);
module_exit(spy_syscall_exit);

MODULE_LICENSE("GPL");
