#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>

/*
    Linux (none) 6.13.0 #1 SMP PREEMPT_DYNAMIC Tue Mar 25 12:25:20 JST 2025 x86_64 GNU/Linux
*/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rui");

#define MAXSIZE 0x400
#define R _IOR('A', 0, uint32_t)
#define W _IOW('A', 1, uint32_t)

typedef struct data_t {
    char buffer[MAXSIZE];
} data_t;

typedef struct request_t {
    size_t size;
    void *data;
} request_t;

static data_t *data;
static DEFINE_MUTEX(lock_data);

static long write_only_ioctl(struct file *filp, unsigned int cmd, unsigned long args){
    request_t req;

    if (copy_from_user(&req, (request_t *)args, sizeof(request_t)) != 0) return -EINVAL;
    
    mutex_lock(&lock_data);

    switch (cmd){
        case R: // currently not available
        case W: {
            if (!data) 
                if (!(data = kzalloc(sizeof(data_t), GFP_KERNEL))) // write_only_ioctl+218
                    return -ENOMEM;
            if (req.size > MAXSIZE) 
                return -EINVAL;
            if (copy_from_user(data->buffer, req.data, req.size) != 0)  // write_only_ioctl+136
                return -EFAULT;
            data->buffer[req.size] = '\0';
            break;
        }
        default: return -EINVAL;
    }

    mutex_unlock(&lock_data);
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = write_only_ioctl,
};

static int __init init_mod(void) {
    int ret = register_chrdev(0, "writeonly", &fops);
    if (ret < 0) return ret;
    return 0;
}

static void __exit clean_mod(void) {
    unregister_chrdev(0, "writeonly");
    mutex_destroy(&lock_data);
}

module_init(init_mod);
module_exit(clean_mod);