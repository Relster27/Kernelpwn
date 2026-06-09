#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/sched.h>

static DEFINE_MUTEX(ioMutex);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xdc9");

static int     stageone_release(struct inode *, struct file *);
static ssize_t stageone_read(struct file *, char *, size_t, loff_t *);
static ssize_t stageone_write(struct file *, const char *, size_t, loff_t *);
int iterate = 0;
static unsigned long* temp;

static int stageone_open(struct inode *inode, struct file *filp) {
    if(!mutex_trylock(&ioMutex)) {
        pr_alert("no racing\n");
        return -EBUSY;
    }
    else{
       printk(KERN_ALERT "driver opened 0x%llx\n", current);
       printk("The process is \"%s\" (pid %i)\n",current->comm, current->pid);
       return 0;
    }
}

static int stageone_release(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "driver closed.\n");
    mutex_unlock(&ioMutex);
    return 0;
}

static ssize_t stageone_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  printk(KERN_ALERT "no write (w)\n");
  return -EFAULT;

}


static ssize_t stageone_read(struct file *filp, char *buffer, size_t length, loff_t *offset) {
  printk(KERN_ALERT "no write (w)\n");
  return -EFAULT;

}

static long stageone_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param){
	if(ioctl_num == 0x1001){
		printk(KERN_INFO "set \n");
		temp = (unsigned long*)ioctl_param;
	}

	else if(ioctl_num == 0x1002){
		printk(KERN_INFO "set \n");
		*temp = ioctl_param;

	}
	return 0;
}

static struct file_operations fops = {
    .read = stageone_read,
    .write = stageone_write,
    .open = stageone_open,
    .unlocked_ioctl = stageone_ioctl,
    .release = stageone_release
};


struct proc_dir_entry *proc_entry = NULL;

int init_module(void){
    proc_entry = proc_create("stageone", 0666, NULL, &fops);
    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) proc_remove(proc_entry);
    mutex_destroy(&ioMutex);
}
