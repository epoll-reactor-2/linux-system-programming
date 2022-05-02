/*
 * sleep.c - /proc file with property that if several processes
 * try to open it at the same time, this will put all but one to sleep.
 */
#include <linux/kernel.h>  // pr_info()
#include <linux/module.h>  // __init, __exit
#include <linux/proc_fs.h> // procfs API
#include <linux/sched.h>   // putting processes to sleep and waking them up
#include <linux/uaccess.h> // get_user(), put_user()
#include <linux/version.h> // version macros

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
# define HAVE_PROC_OPS
#endif

// To keep last received message.
#define MESSAGE_LENGTH 80
static char message[MESSAGE_LENGTH];

static struct proc_dir_entry *proc_file;
#define PROC_ENTRY_FILENAME "sleep"

// Read function.
static ssize_t module_output(struct file *file,
			     char __user *buf, // Bufer to put data to.
			     size_t       len,
			     loff_t      * /* unused */)
{
	static int finished = 0;
	int i;
	char output_msg[MESSAGE_LENGTH + 30];

	if (finished) {
		finished = 0;
		return 0;
	}

	sprintf(output_msg, "Last input: %s\n", message);
	for (i = 0; i < len && output_msg[i]; ++i)
		put_user(output_msg[i], buf + i);

	finished = 1;

	// Bytes was read.
	return i;
}

// Write function
static ssize_t module_input(struct file       *file,
			    const char __user *buf, // The buffer with input.
			    size_t             len,
			    loff_t            * /* unused */)
{
	int i;

	for (i = 0; i < MESSAGE_LENGTH - 1 && i < len; ++i)
		get_user(message[i], buf + i);

	message[i] = '\0';

	// Number of character used.
	return i;
}

// 1 if the file is open, 0 otherwise.
static atomic_t already_open = ATOMIC_INIT(0);

// Queue of processes who want file.
static DECLARE_WAIT_QUEUE_HEAD(waitq);

// Called on /proc file open.
static int module_open(struct inode * /* unused */, struct file *file)
{
	// If file's flags include O_NONBLOCK, it means the process don't want to
	// wait for the file.
	if (file->f_flags & O_NONBLOCK && atomic_read(&already_open))
		return -EAGAIN;

	try_module_get(THIS_MODULE);

	while (atomic_cmpxchg(&already_open, 0, 1)) {
		int i, is_sig = 0;

		// This puts the current process to sleep. Execution will be resumed
		// right after the wake_up(&waitq) (only module_close does that, when
		// the file is closed) or on signal.
		wait_event_interruptible(waitq, !atomic_read(&already_open));

		// If we're woke up on signal, return -EINTR. This allows processes to be
		// killed or stopped.
		for (i = 0; i < _NSIG_WORDS && !is_sig; ++i)
			is_sig = current->pending.signal.sig[i] & ~current->blocked.sig[i];

		if (is_sig) {
			// It is important to place module_put here because for processes
			// where the open is interrupted by signal, there will never be
			// corresponding close. If we're do not decrement module usage here,
			// it will be permanently enabled.
			module_put(THIS_MODULE);
			return -EINTR;
		}
	}

	return 0;
}

// Called on /proc file close.
static int module_close(struct inode * /* unused */, struct file *file)
{
	atomic_set(&already_open, 0);

	wake_up(&waitq);

	module_put(THIS_MODULE);

	return 0;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops fops = {
	.proc_read = module_output,
	.proc_write = module_input,
	.proc_open = module_open,
	.proc_release = module_close
};
#else
static const struct file_operations fops = {
	.read = module_output,
	.write = module_input,
	.open = module_open,
	.release = module_close
};
#endif

static int __init sleep_init(void)
{
	proc_file = proc_create(PROC_ENTRY_FILENAME, 0644, NULL, &fops);
	if (proc_file == NULL) {
		remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
		pr_debug("sleep: could not initialize %s.\n", PROC_ENTRY_FILENAME);
		return -ENOMEM;
	}
	proc_set_size(proc_file, 80);
	proc_set_user(proc_file, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID);

	pr_info("/proc/%s created.\n", PROC_ENTRY_FILENAME);

	return 0;
}

static void __exit sleep_exit(void)
{
	remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	
	pr_info("/proc/%s removed.\n", PROC_ENTRY_FILENAME);
}

MODULE_LICENSE("GPL");

module_init(sleep_init);
module_exit(sleep_exit);
