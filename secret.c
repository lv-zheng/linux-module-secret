#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#undef pr_fmt
#define pr_fmt(fmt) "secret: " fmt


static int devcount = 5;
static unsigned long deftimeout_ms = 5000;

struct secret_dev;

struct secret_entry {
	unsigned char *text;
	unsigned long len;
	int cancelled; /* protected by spinlock of device */
	struct timer_list timer;
	struct list_head list;
	struct secret_dev *dev;
};

static struct secret_dev {
	struct device *device;
	unsigned long timeout_ms;
	struct cdev cdev;
	struct completion comp;
	spinlock_t lock;
	struct list_head secrets; /* protected by lock */
} *secret_devices;

struct secret_file_pdata_read {
	struct secret_dev *dev;
	struct mutex mtx;
	unsigned char *buffer;
	unsigned long len;
	unsigned long pos;
};

struct secret_file_pdata_write {
	struct secret_dev *dev;
	struct mutex mtx;
	unsigned char *buffer;
	unsigned long len;
	struct secret_entry *entry;
};

static struct class *secret_class;
static dev_t major;


static inline unsigned long secret_text_size(void)
{
	return PAGE_SIZE;
}

static inline void *secret_text_alloc(void)
{
	return (void *) get_zeroed_page(GFP_KERNEL);
}

static inline void secret_text_free(void *p)
{
	free_page((unsigned long) p);
}


/* Timer function (atomic context) */
static void secret_on_timer(unsigned long entry_ul)
{
	struct secret_entry *entry = (void *) entry_ul;
	struct secret_dev *dev = entry->dev;

	/* read function extracts entry from the list head */
	spin_lock(&dev->lock);
	if (entry->cancelled) {
		spin_unlock(&dev->lock);
		return;
	}
	list_move(&entry->list, &dev->secrets);
	spin_unlock(&dev->lock);

	complete(&dev->comp);
}


/* fops for O_RDONLY file */

static ssize_t secret_r_read(struct file *filp, char __user *buf,
			size_t count, loff_t *pos)
{
	struct secret_file_pdata_read *pdata = filp->private_data;
	struct secret_dev *dev = pdata->dev;
	ssize_t retval = 0;

	if (mutex_lock_interruptible(&pdata->mtx))
		return -ERESTARTSYS;

	/* Wait for data on first read */
	if (!pdata->buffer) {
		struct secret_entry *entry;
		struct list_head *entry_list;

		if (wait_for_completion_interruptible(&dev->comp)) {
			retval = -ERESTARTSYS;
			goto out;
		}

		/* The timer function holds the spinlock too, use _bh */
		spin_lock_bh(&dev->lock);

		/* Extract data and free the entry */
		entry_list = dev->secrets.next;
		BUG_ON(entry_list == &dev->secrets);
		entry = list_entry(entry_list, struct secret_entry, list);
		list_del(entry_list);

		spin_unlock_bh(&dev->lock);

		pdata->buffer = entry->text;
		pdata->len = entry->len;
		pdata->pos = 0;

		kfree(entry);
	}

	if (pdata->pos > pdata->len)
		pdata->pos = pdata->len;

	if (count > pdata->len - pdata->pos)
		count = pdata->len - pdata->pos;

	if (copy_to_user(buf, pdata->buffer + pdata->pos, count)) {
		retval = -EFAULT;
		goto out;
	}

	pdata->pos += count;
	retval = count;

out:
	mutex_unlock(&pdata->mtx);
	return retval;
}

static int secret_r_release(struct inode *inode, struct file *filp)
{
	struct secret_file_pdata_read *pdata = filp->private_data;

	secret_text_free(pdata->buffer);
	kfree(pdata);

	return 0;
}

static const struct file_operations secret_r_fops = {
	.read		= secret_r_read,
	.release	= secret_r_release,
};


/* fops for O_WRONLY file */

static ssize_t secret_w_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *pos)
{
	struct secret_file_pdata_read *pdata = filp->private_data;
	ssize_t retval = 0;

	if (mutex_lock_interruptible(&pdata->mtx))
		return -ERESTARTSYS;

	if (pdata->len == secret_text_size()) {
		retval = -ENOSPC;
		goto out;
	}

	if (pdata->len + count > secret_text_size())
		count = secret_text_size() - pdata->len;

	if (copy_from_user(pdata->buffer + pdata->len, buf, count)) {
		retval = -EFAULT;
		goto out;
	}

	pdata->len += count;
	retval = count;

out:
	mutex_unlock(&pdata->mtx);
	return retval;
}

static int secret_w_release(struct inode *inode, struct file *filp)
{
	struct secret_file_pdata_write *pdata = filp->private_data;
	struct secret_dev *dev = pdata->dev;
	struct secret_entry *entry = pdata->entry;
	struct timer_list *timer = &entry->timer;

	entry->text = pdata->buffer;
	entry->len = pdata->len;
	entry->cancelled = 0;
	INIT_LIST_HEAD(&entry->list);
	entry->dev = dev;

	/* The timer function holds the spinlock too, use _bh */
	spin_lock_bh(&dev->lock);
	list_add_tail(&entry->list, &dev->secrets);
	spin_unlock_bh(&dev->lock);

	init_timer(timer);
	timer->expires = jiffies + dev->timeout_ms * HZ / 1000;
	timer->function = secret_on_timer;
	timer->data = (unsigned long) entry;
	add_timer(timer);

	return 0;
}

static const struct file_operations secret_w_fops = {
	.write		= secret_w_write,
	.release	= secret_w_release,
};


/* open functions */

static int secret_r_open(struct inode *inode, struct file *filp)
{
	struct secret_file_pdata_read *pdata;

	pdata = kmalloc(sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	pdata->buffer = NULL; /* text is fetched on first read */

	pdata->dev = container_of(inode->i_cdev, struct secret_dev, cdev);
	mutex_init(&pdata->mtx);

	filp->private_data = pdata;
	filp->f_op = &secret_r_fops;
	nonseekable_open(inode, filp);
	return 0;
}

static int secret_w_open(struct inode *inode, struct file *filp)
{
	struct secret_file_pdata_write *pdata;

	pdata = kmalloc(sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	pdata->buffer = secret_text_alloc();
	pdata->entry = kmalloc(sizeof(*pdata->entry), GFP_KERNEL);
	if (!pdata->buffer || !pdata->entry) {
		secret_text_free(pdata->buffer);
		kfree(pdata->entry);
		kfree(pdata);
		return -ENOMEM;
	}

	pdata->dev = container_of(inode->i_cdev, struct secret_dev, cdev);
	mutex_init(&pdata->mtx);
	pdata->len = 0;

	filp->private_data = pdata;
	filp->f_op = &secret_w_fops;
	nonseekable_open(inode, filp);
	return 0;
}

static int secret_open(struct inode *inode, struct file *filp)
{
	switch (filp->f_flags & O_ACCMODE) {
	case O_RDONLY:
		return secret_r_open(inode, filp);
	case O_WRONLY:
		return secret_w_open(inode, filp);
	default:
		/* R+W is not supported */
		return -EINVAL;
	}
}


static const struct file_operations secret_fops = {
	.open		= secret_open,
};


/* init and cleanup */

static void secret_device_init(struct secret_dev *dev, dev_t minor)
{
	int err;
	struct cdev *cdev = &dev->cdev;
	dev_t devno = MKDEV(major, minor);

	dev->timeout_ms = deftimeout_ms;
	init_completion(&dev->comp);
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->secrets);

	dev->device = device_create(secret_class, NULL, devno, NULL,
			"secret%d", (int) minor);
	if (IS_ERR(dev->device)) {
		pr_notice("Error %d create /dev/secret%d\n",
			(int) PTR_ERR(dev->device), (int) minor);
		dev->device = NULL;
	}

	cdev_init(cdev, &secret_fops);
	cdev->owner = THIS_MODULE;
	err = cdev_add(cdev, devno, 1);

	if (err) {
		pr_notice("Error %d adding secret%d\n", err, (int) minor);
		return;
	}
}

static void secret_device_cleanup(struct secret_dev *dev, dev_t minor)
{
	struct list_head *curr;
	struct secret_entry *entry;
	int cnt = 0;

	cdev_del(&dev->cdev);

	/*
	 * At this point, all the opened files have been released, so we can
	 * just delete the timers and entries one by one.
	 */

	while (1) {
		spin_lock_bh(&dev->lock);

		curr = dev->secrets.next;
		if (curr == &dev->secrets) {
			spin_unlock_bh(&dev->lock);
			break;
		}

		entry = list_entry(curr, struct secret_entry, list);
		entry->cancelled = 1;
		list_del(curr);

		/* Spinlocks must be released before del_timer_sync */
		spin_unlock_bh(&dev->lock);

		del_timer_sync(&entry->timer);

		secret_text_free(entry->text);
		kfree(entry);
		++cnt;
	}

	if (cnt)
		dev_dbg(dev->device, "cleared out %d pending secrets\n", cnt);

	device_destroy(secret_class, MKDEV(major, minor));
}

static void secret_module_cleanup(void)
{
	dev_t minor;

	if (secret_devices) {
		for (minor = 0; minor < devcount; ++minor)
			secret_device_cleanup(&secret_devices[minor], minor);
		kfree(secret_devices);
	}

	if (major)
		unregister_chrdev_region(MKDEV(major, 0), devcount);

	class_destroy(secret_class);
}

static int __init secret_init(void)
{
	int err = 0, minor;
	dev_t dev;

	secret_class = class_create(THIS_MODULE, "secret");
	if (IS_ERR(secret_class)) {
		err = PTR_ERR(secret_class);
		goto error;
	}

	/* Allocate device numbers */
	err = alloc_chrdev_region(&dev, 0, devcount, "hello");
	if (err)
		goto error;

	major = MAJOR(dev);

	/* Initialize devices */
	secret_devices = kmalloc_array(devcount, sizeof(*secret_devices),
				GFP_KERNEL);
	if (!secret_devices) {
		err = -ENOMEM;
		goto error;
	}

	for (minor = 0; minor < devcount; ++minor)
		secret_device_init(&secret_devices[minor], minor);

	pr_info("module initialized\n");
	return 0;

error:
	secret_module_cleanup();
	pr_info("module failed to initialize\n");
	return err;
}

static void __exit secret_exit(void)
{
	secret_module_cleanup();

	pr_info("module exited\n");
}

module_init(secret_init);
module_exit(secret_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zheng Lv");
