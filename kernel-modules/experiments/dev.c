/* This is an template ready-to-use character device driver.

   You can embed some interaction with hardware via ioctl() or
   other syscalls. Once I will get some board for educational
   purposes, it make sense to code something with
   I2C, UART, SPI buses. */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>

static const char    name[] = "template_device";
struct cdev          cdev;
static struct class *cl;
static dev_t         dev;

static int dev_open(struct inode * /* unused */, struct file * /* unused */)
{
	return 0;
}

static int dev_release(struct inode * /* unused */, struct file * /* unused */)
{
	return 0;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case 0xFFAB:
		pr_info("ioctl_device: %d, %s\n", task_pid_nr(current), current->comm);
		break;

	case 0xFFAC:
		if (arg == 8) {
			pr_info("ioctl_device: argument = %ld.\n", arg);
		} else {
			pr_warn("ioctl_device: wrong argument.\n");
			return -EINVAL;
		}
		break;
	}
	return 0;
}

static struct file_operations fops = {
	.open		= dev_open,
	.release	= dev_release,
	.unlocked_ioctl	= dev_ioctl
};

static int __init dev_init(void)
{
	int ret;
	struct device *dev_ret;

	ret = alloc_chrdev_region(&dev, 0, 1, name);
	if (ret < 0)
		return ret;

	// /sys/class/template_device
	cl = class_create(name);
	if (IS_ERR(cl)) {
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(cl);
	}

	// Create device for sysfs.
	dev_ret = device_create(cl, NULL, dev, NULL, name);
	if (IS_ERR(dev_ret)) {
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(dev_ret);
	}

	// Create character device.
	cdev_init(&cdev, &fops);
	ret = cdev_add(&cdev, dev, 1);
	if (ret < 0) {
		device_destroy(cl, dev);
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		return ret;
	}

	pr_info("dev: initialized\n");
	return 0;
}

static void __exit dev_exit(void)
{
	device_destroy(cl, dev);
	class_destroy(cl);
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);
	pr_info("dev: exited");
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");