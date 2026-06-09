#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("A vulnerable driver for a CTF");

#define CMD_READ  0x1337
#define CMD_WRITE 0x1338

struct req_t {
	char* buf;
	uint64_t size;
};

char g_msg[0x100] = "Welcome to Black Hat MEA 2025 Finals!";
char g_flag[0x100] = "The flag will be written here on the remote server.";

static long module_ioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{
	struct req_t req;
	switch (cmd) {
	case CMD_READ:
		if (copy_from_user(&req, (struct req_t __user*)arg, sizeof(req)))
			return -EFAULT;
		if (_copy_to_user((char __user*)req.buf, g_msg, req.size))
			return -EFAULT;
		break;

	case CMD_WRITE:
		if (copy_from_user(&req, (struct req_t __user*)arg, sizeof(req)))
			return -EFAULT;
		if (_copy_from_user(g_msg, (char __user*)req.buf, req.size))
			return -EFAULT;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static ssize_t module_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
  if (copy_from_user(g_flag, buf, count < 0x100 ? count : 0x100))
    return -EFAULT;

  return count;
}

static struct file_operations module_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = module_ioctl,
  .write = module_write,
};

static struct miscdevice vuln_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vuln",
	.fops = &module_fops
};

static int __init module_initialize(void)
{
	if (misc_register(&vuln_dev) != 0)
		return -EBUSY;
	return 0;
}

static void __exit module_cleanup(void)
{
	misc_deregister(&vuln_dev);
}

module_init(module_initialize);
module_exit(module_cleanup);
