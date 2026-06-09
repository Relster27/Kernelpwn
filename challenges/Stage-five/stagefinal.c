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

struct param{
    size_t idx;
    size_t size;
    char *buf;
};

struct migrate_idx{
	size_t idx_src;
	size_t idx_dst;
	size_t size_to_set;
};

static DEFINE_MUTEX(ioMutex);
static int major_number;

struct param heap[5];
static int stagefinal_open(struct inode *inode, struct file *filp){
    if(!mutex_trylock(&ioMutex)) {
        printk(KERN_ALERT "no racing\n");
        return -EBUSY;
    }
    else{
       printk(KERN_INFO "driver opened.\n");
       printk(KERN_INFO "heap is at 0x%llx\n", heap);
       return 0;
    }
}


static int stagefinal_release(struct inode *inode, struct file *filp){
    printk(KERN_INFO "driver closed.\n");
    mutex_unlock(&ioMutex);
    return 0;
}




static long stagefinal_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param){

	// copy to kernel struct
	struct param req;
	struct migrate_idx req2;

	if (copy_from_user((void *)&req, (void *)ioctl_param, sizeof(req))){
        	printk(KERN_ALERT "COPYING HEAP STRUCT ERROR!\n");
    	}

	else if (copy_from_user((void *)&req2, (void *)ioctl_param, sizeof(req2))){
		printk(KERN_ALERT "COPYING HEAP EDIT ERROR!\n");
	}

    	else if(ioctl_num == 0x1774){
		memcpy(heap[req2.idx_dst].buf, heap[req2.idx_src].buf + req2.size_to_set, req2.size_to_set);
		printk(KERN_INFO "migrate to heap 0x%llx\n", ioctl_param);
		printk(KERN_INFO "copy to heap %d from heap %d\n", req2.idx_dst, req2.idx_src);
		
	} // migrates

	else if(ioctl_num == 0x1775){
		memcpy(heap[req2.idx_dst].buf+ req2.size_to_set, heap[req2.idx_src].buf, req2.size_to_set);
		printk(KERN_INFO "migrate to heap 0x%llx\n", ioctl_param);
		printk(KERN_INFO "copy to heap %d from heap %d\n", req2.idx_dst, req2.idx_src);
			
	} // migrates


	else{
			printk(KERN_INFO "Copied 0x%llx\n", ioctl_param);
			printk(KERN_INFO "idx %d\n", req.idx);
			
			if(!(req.idx >= 0 && req.idx <= 4)){
				printk(KERN_INFO"only 5 to 0 index pls\n");
				return -EFAULT;
			}

			if(ioctl_num == 0x1770){

				if(req.size < 0xa8){
					printk(KERN_INFO"size must be more than 0xa8\n");
					return -EFAULT;
				}

				else if (req.size > 0x260){
					printk(KERN_INFO"size must be less than 0x260\n");
					return -EFAULT;
				}

				else{
					heap[req.idx].size = req.size;
					heap[req.idx].buf = (char *)kmalloc(heap[req.idx].size, GFP_KERNEL);
					printk(KERN_INFO "SUCCESFULLY COPIED TO HEAP!\n");
					printk(KERN_INFO "KMALLOCED index %d\n", req.idx);
					printk(KERN_INFO "KMALLOCED data %s\n", heap[req.idx].buf);
					printk(KERN_INFO "KMALLOCED size 0x%lx\n", heap[req.idx].size);
					printk(KERN_INFO "KMALLOCED ptr 0x%lx\n", heap[req.idx].buf);
					
				}
			
			} // kmalloc

			else if(ioctl_num == 0x1771){
				printk(KERN_INFO "KFREEING index %d\n", req.idx);
				printk(KERN_INFO "KFREEING ptr 0x%lx\n", heap[req.idx].buf);
				memset(heap[req.idx].buf, 0, heap[req.idx].size); // insane difficulty
				kfree(heap[req.idx].buf);
				heap[req.idx].size = 0;
				heap[req.idx].buf = 0; // insane difficulty
			} // kfree

			else if(ioctl_num == 0x1772){
				if (copy_to_user(req.buf, heap[req.idx].buf, heap[req.idx].size)){
		        		printk(KERN_ALERT "COPY TO USER ERROR!\n");
		    		}
				else{
					printk(KERN_INFO "Copied to user 0x%llx\n", ioctl_param);
					printk(KERN_INFO "Copied to user index %d\n", req.idx);
					printk(KERN_INFO "Copied to user size 0x%lx\n", heap[req.idx].size);
					printk(KERN_INFO "Copied data to user %s\n", heap[req.idx].buf);
				}
			} // read (secure)


			else if(ioctl_num == 0x1773){
				if(copy_from_user(heap[req.idx].buf, req.buf, heap[req.idx].size)){
						printk(KERN_ALERT "WRITING TO HEAP ERROR\n");
					}
				else{
					printk(KERN_INFO "write to heap 0x%llx\n", ioctl_param);
					printk(KERN_INFO "write to heap index %d\n", req.idx);
					printk(KERN_INFO "write to heap size 0x%lx\n", heap[req.idx].size);
					printk(KERN_INFO "write data to heap %s\n", heap[req.idx].buf);
				}

			} // write (secure)

	} // else after struct req

	// end of copy to kernel struct req heap


	return 0;
}

static struct file_operations fops = {
  	.open = stagefinal_open,
  	.unlocked_ioctl = stagefinal_ioctl,
  	.release = stagefinal_release

};

int init_module(void){
  	major_number = register_chrdev(0, "stagefinal", &fops);

  	if (major_number < 0) {
    		printk(KERN_INFO "Registering stagefinal failed: %d\n", major_number);
    		return major_number;
  	}

  printk(KERN_INFO "number %d.\n", major_number);
  	return 0;
}

void cleanup_module(void)
{
  	unregister_chrdev(major_number, "stagefinal");
}
