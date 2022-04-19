#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("epoll-reactor");
MODULE_DESCRIPTION("Hello-world kernel module");
MODULE_VERSION("0.1");

static int __init custom_module_init(void) {
    int i;

    printk(KERN_INFO "Initialize epoll-reactor module...");
    for (i = 0; i < 10; ++i)
        printk(KERN_INFO "Ping message %d\n", i);

    return 0;
}

static void __exit custom_module_exit(void) {
    printk(KERN_INFO "Deinitialize epoll-reactor module...");
}

module_init(custom_module_init);
module_exit(custom_module_exit);
