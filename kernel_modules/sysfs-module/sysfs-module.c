/*
 * sysfs-module.c - Sysfs example.
 */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>

MODULE_LICENSE("GPL");

static struct kobject *sysfs_object;

// The variable we want to be able to change.
static int sysfs_value = 0;

static ssize_t sysfs_value_show(
	struct kobject        * /* unused */,
	struct kobj_attribute * /* unused */,
	char                  *buf)
{
	return sprintf(buf, "%d\n", sysfs_value);
}

static ssize_t sysfs_value_store(
	struct kobject        * /* unused */,
	struct kobj_attribute * /* unused */,
	char                  *buf,
	size_t                 count)
{
	sscanf(buf, "%du", &sysfs_value);
	return count;
}

// I prefer explicit initialization instead of vile __ATTR macros.
static struct kobj_attribute sysfs_value_attribute = {
	.attr  = {
		.name = "sysfs_value",
		.mode = 0660
	},
	.show  =         sysfs_value_show,
	.store = (void *)sysfs_value_store
};

static int __init sysfs_module_init(void)
{
	int error = 0;

	pr_info("sysfs_module: unitialized\n");

	// Note: name "sysfs_object" causes error while creation.
	sysfs_object = kobject_create_and_add("__sysfs_object", kernel_kobj);
	if (!sysfs_object)
		return -ENOMEM;

	error = sysfs_create_file(sysfs_object, &sysfs_value_attribute.attr);
	if (error)
		pr_info("sysfs_module: failed to create /sys/sysfs_object\n");

	return error;
}

static void __exit sysfs_module_exit(void)
{
	pr_info("sysfs_module: exit success\n");
	kobject_put(sysfs_object);
}

module_init(sysfs_module_init);
module_exit(sysfs_module_exit);
