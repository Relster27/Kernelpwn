#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mutex.h>


MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("0xdc9");


static int major_number;
int itor = 40;
char msg[2048];
static int stagetwo_open(struct inode *inode, struct file *filp){
       printk(KERN_INFO "driver opened.\n");
       return 0;
}

static int stagetwo_release(struct inode *inode, struct file *filp){
    printk(KERN_INFO "driver closed.\n");
    return 0;
}

static ssize_t stagetwo_read(struct file *filp, char *buffer, size_t length, loff_t *offset) {
	char temp[64] = "aaaaaaaa \n";
   	memcpy(msg, temp, itor);
   	check_object_size(msg, length, 1);
   	return strlen(msg) - copy_to_user(buffer, msg, length);

}

void(*blanks)(void);
static long stagetwo_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param){

	// itor
	if(ioctl_num == 0x1336){
		itor = (int) ioctl_param;
	}

	// write & exec
	else if(ioctl_num == 0x1337){
		blanks = ioctl_param;
		blanks();

	}
	return 0;
}

static struct file_operations fops = {
  	.open = stagetwo_open,
  	.read = stagetwo_read,
  	.unlocked_ioctl = stagetwo_ioctl,
  	.release = stagetwo_release

};

int init_module(void){
  	major_number = register_chrdev(0, "stagetwo", &fops);
  	if (major_number < 0) {
    		printk(KERN_INFO "Registering stagetwo failed: %d\n", major_number);
    		return major_number;
  	}
  	printk(KERN_INFO "inserted and number is %d.\n", major_number);
  	return 0;

}

void cleanup_module(void){
  	unregister_chrdev(major_number, "stagetwo");
}
