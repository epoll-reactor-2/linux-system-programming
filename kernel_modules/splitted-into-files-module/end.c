/*
 * end.c - Illustration of multi-filed modules.
 */
#include <linux/init.h>   // __exit
#include <linux/kernel.h> // pr_info()
#include <linux/module.h> // module API

MODULE_LICENSE("GPL");

static void __exit splitted_into_files_exit(void)
{
	pr_info("Goodbye from splitted to files module\n");
}

module_exit(splitted_into_files_exit);
