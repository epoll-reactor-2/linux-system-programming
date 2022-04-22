/*
 * initdata-variable-module.c - Illustrating the __init,
 * __initdata and __exit macros.
 */
#include <linux/init.h>   // __init, __exit
#include <linux/kernel.h> // pr_info()
#include <linux/module.h> // module API

MODULE_LICENSE("GPL");

static int data __initdata = 187;

static int __init initdata_variable_init(void)
{
	pr_info("initdata_variable module started with arg %d\n", data);
	return 0;
}

static void __exit initdata_variable_exit(void)
{
	pr_info("initdata_variable module terminated\n");
}

module_init(initdata_variable_init);
module_exit(initdata_variable_exit);
