/*
 * begin.c - Illustration of multi-filed modules.
 */
#include <linux/init.h>   // __init macros
#include <linux/kernel.h> // pr_info()
#include <linux/module.h> // module API

MODULE_LICENSE("GPL");

static int __init splitted_into_files_init(void)
{
	pr_info("Hello from splitted to files module\n");
	return 0;
}

module_init(splitted_into_files_init);
