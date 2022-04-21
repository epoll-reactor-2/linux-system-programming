/*
 * chardev.c - Creates a read-only char device that says how many
 * times you read from the dev file.
 */
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/poll.h>

MODULE_LICENSE("GPL");

static int device_open   (struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read (struct file *,       char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

#define DEVICE_NAME "chardev" // Dev name as it apperas in /proc/devices.
#define BUF_LEN     1         // Max length of the message from the device.

static int major; // Major number assigned to device driver.

enum {
	CDEV_NOT_USED       = 0,
	CDEV_EXCLUSIVE_OPEN = 1
};

// Is device open? Used to prevent multiple access to device.
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char msg[BUF_LEN]; // The message the device will give when asked.

// High-level abstraction of device. Classes allow userspace to work with
// devices based on what they do, rather than how they are connected or
// how they work.
static struct class *device;

static struct file_operations chardev_fops = {
	.owner   = THIS_MODULE,
	.read    = device_read,
	.write   = device_write,
	.open    = device_open,
	.release = device_release 
};

static int __init chardev_init(void)
{
	major = register_chrdev(0, DEVICE_NAME, &chardev_fops);

	if (major < 0) {
		pr_alert("Registering char device failed with %d\n", major);
		return major;
	}

	pr_info("Major number %d was assigned to device", major);

	device = class_create(THIS_MODULE, DEVICE_NAME);
	
	if (device) {
		pr_info("Device /dev/%s already exists.", DEVICE_NAME);
		return 0;
	}

	device_create(device, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

	pr_info("Device created on /dev/%s\n", DEVICE_NAME);

	return 0;
}

static void __exit chardev_exit(void)
{
	device_destroy(device, MKDEV(major, 0));
	class_destroy(device);

	unregister_chrdev(major, DEVICE_NAME); // Unregister our device.

	pr_info("Device deleted on /dev/%s\n", DEVICE_NAME);
}

// Called when a process tries to open the device file, like "sudo cat /dev/chardev".
static int device_open(struct inode *inode, struct file *file)
{
	static int counter = 0;

	if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
		return -EBUSY;

	sprintf(msg, "/dev/%s was accessed %d times\n", DEVICE_NAME, counter++);
	pr_info("%s", msg);
	
	try_module_get(THIS_MODULE);

	return 0;
}

// Called when a process closes the device file.
static int device_release(struct inode *inode, struct file *file)
{
	// We're now ready for our next caller.
	atomic_set(&already_open, CDEV_NOT_USED);

	// Decrement the usage count, or else once you opened the file, you
	// will get rid of the module.
	module_put(THIS_MODULE);

	pr_info("/dev/%s was released\n", DEVICE_NAME);

	return 0;
}

// Called when a process, which already opened the dev file, attempts to read from it.
static ssize_t device_read(
	struct file *filp,
	char __user *buffer,
	size_t       length,
	loff_t      *offset)
{
	// Number of bytes actually written to the buffer.
	int bytes_read = 0;
	const char *msg_ptr = msg;

	if (!*(msg_ptr + *offset)) { // We are at the end of message.
		*offset = 0; // Reset the offset.
		return 0; // Signify end of file.
	}

	msg_ptr += *offset;

	// Actually put the data into the buffer.
	while (length && *msg_ptr) {
		// The buffer is in the user data segment, not the kernel
		// segment so "*" assignment won't work. We have to use put_user
		// which copies data from the kernel data segment to the user
		// data segment.
		put_user(*(msg_ptr++), buffer++);
		length--;
		bytes_read++;
	}

	*offset += bytes_read;

	// Most read functions return the number of bytes put into the buffer.
	return bytes_read;
}

// Called when a process writes to dev file: echo "Hi" > /dev/chardev.
static ssize_t device_write(
	struct file       *filp,
	const char __user *buffer,
	size_t             len,
	loff_t            *off)
{
	pr_alert("Sorry, write operation is not supported.\n");

	return -EINVAL;
}

module_init(chardev_init);
module_exit(chardev_exit);
