#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("A vulnerable driver for a CTF");

#define CMD_ALLOC   0x0268
#define CMD_INC     0x0298
#define CMD_SEL     0x01c1
#define CMD_DELETE  0x0831

#define MAX_OBJ_NUM 0x100
#define PAD_SIZE    0x7f8

struct obj {
  char buf[PAD_SIZE];
  size_t cnt;
};

static struct kmem_cache *obj_cachep;
static DEFINE_MUTEX(module_lock);

unsigned char inc_used = 0;
struct obj *selected = 0;
struct obj *obj_array[MAX_OBJ_NUM] = { NULL };

static long module_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  long ret = -EINVAL;
  mutex_lock(&module_lock);

  if (arg >= MAX_OBJ_NUM)
    goto out;

  switch (cmd) {
    case CMD_ALLOC: // alloc
      obj_array[arg] = kmem_cache_zalloc(obj_cachep, GFP_KERNEL);
      ret = 0;
      break;

    case CMD_SEL: // select
      if (!obj_array[arg])
        goto out;
      selected = obj_array[arg];
      ret = 0;
      break;

    case CMD_INC: // increment
      if (inc_used++ > 1)
        goto out;
      selected->cnt++;
      ret = 0;
      break;

    case CMD_DELETE:  // free
      if (!obj_array[arg])
        goto out;
      kmem_cache_free(obj_cachep, obj_array[arg]);
      obj_array[arg] = NULL;
      ret = 0;
      break;
  }

 out:
  mutex_unlock(&module_lock);
  return ret;
}

static struct file_operations module_fops = {
  .owner          = THIS_MODULE,
  .unlocked_ioctl = module_ioctl,
};

static struct miscdevice vuln_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "vuln",
  .fops = &module_fops
};

static int __init module_initialize(void) {
  if (misc_register(&vuln_dev) != 0)
    return -EBUSY;

  obj_cachep = KMEM_CACHE(obj, 0);
  if (!obj_cachep) {
    misc_deregister(&vuln_dev);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void) {
  misc_deregister(&vuln_dev);
  mutex_destroy(&module_lock);
}

module_init(module_initialize);
module_exit(module_cleanup);
