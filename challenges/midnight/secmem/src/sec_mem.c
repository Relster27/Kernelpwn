#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>

#define DEVICE_NAME "sec_mem"
#define BUFFER_SIZE 1024
#define MAX_FUNC_NAME 64

typedef ssize_t (*buffer_op_fn)(void *buffer, const void *data, size_t len, int64_t offset);

struct sec_mem_buffer {
    char buffer[BUFFER_SIZE];
    buffer_op_fn ops[3]; 
};

static struct sec_mem_buffer device_global_struct;

struct sec_mem_ioctl_data {
    size_t length;
    uint64_t op_index; 
    char buffer[BUFFER_SIZE];
    int64_t offset;
};

static int major_number;
static struct class *sec_mem_class = NULL;
static struct cdev sec_mem_cdev;

static struct mutex mutex;


struct sec_mem_ioctl_data data;

static int sec_mem_release(struct inode *inode, struct file *file) {
    mutex_unlock(&mutex);
    pr_info("sec_mem_dev: Device closed\n");
    return 0;
}

ssize_t buffer_copy_from_user(void *buffer, const void *data, size_t len, int64_t offset) {
    if (len > sizeof(struct sec_mem_buffer)) {
        return -EINVAL;
    }
    memcpy(buffer, data, len);
    return len;
}

ssize_t buffer_copy_to_user(void *buffer, const void *data, size_t len, int64_t offset) {
    if (len > sizeof(struct sec_mem_buffer)) {
        return -EINVAL;
    }
    memcpy(data, buffer + offset, len);
    return len;
}

ssize_t buffer_clear(void *buffer, const void *data, size_t len, int64_t offset) {
    memset(buffer, 0, BUFFER_SIZE);  
    return BUFFER_SIZE;  
}

#define sec_mem_IOC_MAGIC 'k'
#define sec_mem_IOC_SET_OPERATION _IOW(sec_mem_IOC_MAGIC, 3, unsigned int)

static void *paciza(void *ptr) {
    __asm__ volatile (
        "paciza %0" 
	: "+r" (ptr)    
    );
    return ptr;
}


static void *autiza(void *ptr) {
    __asm__ volatile (
        "autiza %0"  
	: "+r" (ptr)    
    );
    return ptr;  
}

static void sec_mem_init_ops(void) {
    device_global_struct.ops[0] = buffer_copy_from_user;
    device_global_struct.ops[1] = buffer_copy_to_user; 
    device_global_struct.ops[2] = buffer_clear;

    for (int i = 0; i < 3; i++) {
        device_global_struct.ops[i] = paciza(device_global_struct.ops[i]);
    }
}

static int sec_mem_open(struct inode *inode, struct file *file) {
    if (!mutex_trylock(&mutex)) {
        pr_err("Device is already open!\n");
        return -EBUSY;
    }

    sec_mem_init_ops();
    return 0;
}

static long sec_mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    if (cmd == sec_mem_IOC_SET_OPERATION) {
        if (copy_from_user(&data, (struct sec_mem_ioctl_data *)arg, sizeof(data))) {
            return -EFAULT;
        }

        if (data.op_index >= 3) { 
            return -EINVAL;
        }

	void *auth_ptr = autiza(device_global_struct.ops[data.op_index]);

        if (!auth_ptr) {
            return -EACCES; 
        }

        buffer_op_fn op = (buffer_op_fn)auth_ptr;
        ssize_t result = op(device_global_struct.buffer, &data.buffer, data.length, data.offset);
        if (result < 0) {
            return result;
        }

        if (copy_to_user(arg, &data, sizeof(data))){
            return -EFAULT;
        }

        return 0;
    }

    return -EINVAL;
}

static char *sec_mem_devnode(const struct device *dev, umode_t *mode) {
    if (mode)
        *mode = 0666;
    return NULL;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = sec_mem_open,
    .release = sec_mem_release,
    .unlocked_ioctl = sec_mem_ioctl,  
};


static int __init sec_mem_init(void) {
    mutex_init(&mutex);
    
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("sec_mem_dev: Failed to register a major number\n");
        return major_number;
    }

    sec_mem_class = class_create("sec_mem_class");
    if (IS_ERR(sec_mem_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        pr_err("sec_mem_dev: Failed to register device class\n");
        return PTR_ERR(sec_mem_class);
    }
    sec_mem_class->devnode = sec_mem_devnode;

    device_create(sec_mem_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    cdev_init(&sec_mem_cdev, &fops);
    cdev_add(&sec_mem_cdev, MKDEV(major_number, 0), 1);
    
    return 0;
}

static void sec_mem_exit(void) {
    device_destroy(sec_mem_class, MKDEV(major_number, 0));  
    cdev_del(&sec_mem_cdev);  
    class_destroy(sec_mem_class);  
    unregister_chrdev(major_number, DEVICE_NAME);  
}


module_init(sec_mem_init);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Itarow");
MODULE_DESCRIPTION("secure memory driver");

