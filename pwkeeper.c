/* Name: Sarah Lively
 * Email: slively1@umbc.edu
 * Description: Password manager that stores and generates passwords using kernel linked lists. 
 * Special Note: Extra credit was done.
 *
 * Resources: Andrew Henry (ahenry3@umbc.edu), https://stackoverflow.com/questions/9207850/why-do-we-need-list-for-each-safe-in-for-deleting-nodes-in-kernel-linked-list
*/

/*
 * This file uses kernel-doc style comments, which is similar to
 * Javadoc and Doxygen-style comments. See
 * ~/linux/Documentation/doc-guide/kernel-doc.rst for details.
 */

/*
 * Getting compilation warnings? The Linux kernel is written against
 * C89, which means:
 *  - No // comments, and
 *  - All variables must be declared at the top of functions.
 * Read ~/linux/Documentation/process/coding-style.rst to ensure your
 * project compiles without warnings.
 */

#define pr_fmt(fmt) "pwkeeper: " fmt

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid_namespace.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <crypto/hash.h>

#include "xt_cs421net.h"

#define MASTERPW_LEN 32
#define ACCOUNTNAME_LEN 16
#define ACCOUNTPW_LEN 16

struct master {

	uid_t uid;
	char password[32];
	struct list_head list;

};

struct accounts {

	uid_t uid;
	char name[16];
	char pw[32];
	char salt[16];
	struct list_head list;

};

static LIST_HEAD(master_head);
static LIST_HEAD(acc_head);
static DEFINE_SPINLOCK(m_lock);
static DEFINE_SPINLOCK(a_lock);

static void kdf(const char *salt, const char *master_pw, const char *acc_name,
		char *ubuf);

/**
 * sha3_digest() - calculate the SHA-3 digest for an arbitrary input buffer
 * @input: input data buffer
 * @input_len: number of bytes in @input
 * @digest: destination pointer to store digest
 * @digest_len: size of digest buffer (in/out parameter)
 *
 * Hash the input buffer pointed to by @input, up to @input_len
 * bytes. Store the resulting digest at @digest. Afterwards, update
 * the value pointed to by @digest_len by the size of the stored
 * digest.
 *
 * <strong>You do not need to modify this function.</strong>
 *
 * Return: 0 on success, negative on error
 */
static int sha3_digest(const void *input, size_t input_len, u8 * digest,
		       size_t * digest_len)
{
	struct crypto_shash *sha3_tfm;
	struct shash_desc *sha3_desc;
	unsigned int digestsize;
	size_t i;
	int retval;

	sha3_tfm = crypto_alloc_shash("sha3-512", 0, 0);
	if (IS_ERR_OR_NULL(sha3_tfm)) {
		pr_err("Could not allocate hash tfm: %ld\n", PTR_ERR(sha3_tfm));
		return PTR_ERR(sha3_tfm);
	}

	digestsize = crypto_shash_digestsize(sha3_tfm);
	if (*digest_len < digestsize) {
		pr_err("Digest buffer too small, need at least %u bytes\n",
		       digestsize);
		retval = -EINVAL;
		goto out;
	}

	sha3_desc =
	    kzalloc(sizeof(*sha3_desc) + crypto_shash_descsize(sha3_tfm),
		    GFP_KERNEL);
	if (!sha3_desc) {
		pr_err("Could not allocate hash desc\n");
		retval = -ENOMEM;
		goto out;
	}
	sha3_desc->tfm = sha3_tfm;
	sha3_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	retval = crypto_shash_digest(sha3_desc, input, input_len, digest);
	*digest_len = digestsize;
	pr_info("Hashed %zu bytes, digest = ", input_len);
	for (i = 0; i < digestsize; i++)
		pr_cont("%02x", digest[i]);
	pr_info("\n");
	kfree(sha3_desc);
out:
	crypto_free_shash(sha3_tfm);
	return retval;
}

/**
 * pwkeeper_master_write() - callback invoked when a process writes to
 * /dev/pwkeeper_master
 * @filp: process's file object that is writing to this device (ignored)
 * @ubuf: source buffer from user
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * If *@ppos does not point to zero, do nothing and return -EINVAL.
 *
 * Copy the contents of @ubuf to the master password for the user, the
 * lesser of @count and MASTERPW_LEN. Then increment the value pointed
 * to by @ppos by the number of bytes copied.
 *
 * When replacing an existing master password, recalculate all account
 * passwords.
 *
 * <em>Caution: @ubuf is not a string; it is not null-terminated.</em>
 *
 * Return: number of bytes copied from @ubuf, or negative on error
 */
static ssize_t pwkeeper_master_write(struct file *filp,
				     const char __user * ubuf, size_t count,
				     loff_t * ppos)
{
	struct master *entry;
	size_t bytes_to_copy;
	unsigned long ret;
	unsigned long flags;

	if (*ppos != 0)
		return -EINVAL;

	spin_lock_irqsave(&m_lock, flags);
	list_for_each_entry(entry, &master_head, list) {

		if (entry->uid == get_current_user()->uid.val) {

			bytes_to_copy =
			    (count < MASTERPW_LEN ? count : MASTERPW_LEN);
			*ppos += bytes_to_copy;
			if (bytes_to_copy < MASTERPW_LEN)
				memset(entry->password + bytes_to_copy, '\0',
				       MASTERPW_LEN - bytes_to_copy);

			ret =
			    copy_from_user(entry->password, ubuf,
					   bytes_to_copy);

			if (ret != 0)
				return -EFAULT;

			return bytes_to_copy;

		}

	}

	entry = kmalloc(sizeof(struct master), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	bytes_to_copy = (count < MASTERPW_LEN ? count : MASTERPW_LEN);
	*ppos += bytes_to_copy;
	if (bytes_to_copy < MASTERPW_LEN)
		memset(entry->password + bytes_to_copy, '\0',
		       MASTERPW_LEN - bytes_to_copy);
	ret = copy_from_user(entry->password, ubuf, bytes_to_copy);
	if (ret != 0)
		return -EFAULT;

	entry->uid = get_current_user()->uid.val;
	list_add_tail(&entry->list, &master_head);
	spin_unlock_irqrestore(&m_lock, flags);
	return bytes_to_copy;

}

/**
 * pwkeeper_account_read() - callback invoked when a process reads
 * from /dev/pwkeeper_account
 * @filp: process's file object that is reading from this device (ignored)
 * @ubuf: destination to store account password
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * Write to @ubuf the password generated for the most recently written
 * account name for the current UID, offset by @ppos. Copy the lesser
 * of @count and (ACCOUNTPW_LEN - *@ppos). Then increment the value
 * pointed to by @ppos by the number of bytes written. If @ppos is
 * greater than or equal to ACCOUNTPW_LEN, then write
 * nothing.
 *
 * If no account name was set (via previous successful invocation of
 * pwkeeper_account_write()), do nothing and return -ENOKEY.
 *
 * Return: number of bytes written to @ubuf, 0 on end of file, or
 * negative on error
 */
static ssize_t pwkeeper_account_read(struct file *filp, char __user * ubuf,
				     size_t count, loff_t * ppos)
{
	unsigned long ret;
	size_t bytes_to_copy;
	struct accounts *a;
	struct accounts *mostRecent;
	int names = 0;
	unsigned long flags;

	/*ASK ABOUT RETURN VALUE */
	if (*ppos >= ACCOUNTPW_LEN)
		return -EINVAL;

	spin_lock_irqsave(&a_lock, flags);

	bytes_to_copy =
	    ((count <
	      (ACCOUNTPW_LEN - *ppos)) ? count : (ACCOUNTPW_LEN - *ppos));

	list_for_each_entry(a, &acc_head, list) {

		if (a->uid == get_current_user()->uid.val) {

			mostRecent = a;
			names += 1;

		}
	}

	if (names != 0) {
		ret =
		    copy_to_user(ubuf, mostRecent->pw + *ppos + 16,
				 bytes_to_copy);
		*ppos += bytes_to_copy;
	}

	spin_unlock_irqrestore(&a_lock, flags);

	if (names == 0)
		return -ENOKEY;

	if (ret != 0)
		return -EFAULT;

	return bytes_to_copy;

}

/**
 * pwkeeper_account_write() - callback invoked when a process writes
 * to /dev/pwkeeper_account
 * @filp: process's file object that is writing to this device (ignored)
 * @ubuf: source buffer from user
 * @count: number of bytes in @ubuf
 * @ppos: file offset (in/out parameter)
 *
 * If *@ppos does not point to zero, do nothing and return -EINVAL.
 *
 * If the current user has not set a master password, do nothing and
 * return -ENOKEY.
 *
 * Otherwise check if @ubuf is already in the accounts list associated
 * with the current user. If it is already there, do nothing and
 * return @count.
 *
 * Otherwise, create a new node in the accounts list associated with
 * the current user. Copy the contents of @ubuf to that node, the
 * lesser of @count and ACCOUNTNAME_LEN. Increment the value pointed
 * to by @ppos by the number of bytes copied. Finally, perform the key
 * derivation function as specified in the project description, to
 * determine the account's password.
 *
 * <em>Caution: @ubuf is not a string; it is not null-terminated.</em>
 *
 * Return: @count, or negative on error
 */
static ssize_t pwkeeper_account_write(struct file *filp,
				      const char __user * ubuf, size_t count,
				      loff_t * ppos)
{
	struct accounts *entry;
	struct master *m;
	struct master *found;
	size_t bytes_to_copy;
	unsigned long ret;
	unsigned long flags;
	int pw_set = 0;

	if (*ppos != 0)
		return -EINVAL;

	spin_lock_irqsave(&a_lock, flags);
	spin_lock_irqsave(&m_lock, flags);

	list_for_each_entry(m, &master_head, list) {

		if (m->uid == get_current_user()->uid.val) {
			found = m;
			pw_set = 1;

		}
	}

	if (pw_set == 0)
		return -ENOKEY;

	list_for_each_entry(entry, &acc_head, list) {

		if (entry->uid == get_current_user()->uid.val)
			if (memcmp
			    (entry->name, ubuf,
			     ACCOUNTNAME_LEN * sizeof(char)) == 0)
				return count;

	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	bytes_to_copy = (count < ACCOUNTNAME_LEN ? count : ACCOUNTNAME_LEN);
	*ppos += bytes_to_copy;
	if (bytes_to_copy < ACCOUNTNAME_LEN)
		memset(entry->name + bytes_to_copy, '\0',
		       ACCOUNTNAME_LEN - bytes_to_copy);

	ret = copy_from_user(entry->name, ubuf, bytes_to_copy);
	if (ret != 0)
		return -EFAULT;

	entry->uid = get_current_user()->uid.val;
	get_random_bytes(entry->salt, sizeof(char) * 16);
	/*  printk(KERN_INFO "Calling kdf santa");
	   printk(KERN_INFO "Entry name here: %s", entry->name);
	   printk(KERN_INFO "Entry password %s", entry->pw); */

	kdf(entry->salt, found->password, entry->name, entry->pw);
	/*printk(KERN_INFO "Found password santa: %s", found->password); */
	list_add_tail(&entry->list, &acc_head);

	spin_unlock_irqrestore(&a_lock, flags);
	spin_unlock_irqrestore(&m_lock, flags);

	return bytes_to_copy;

}

/* Automatically generates a password using the key derivation formula
 * outlined in the project description.
 */
static void kdf(const char *salt, const char *master_pw, const char *acc_name,
		char *ubuf)
{

	char temp[64];
	char digest[64];
	size_t length = 64;
	unsigned ret;
	int i;
	int tmp;

	memcpy(temp, salt, 16);
	memcpy(temp + 16, master_pw, MASTERPW_LEN);
	memcpy(temp + 16 + MASTERPW_LEN, acc_name, ACCOUNTNAME_LEN);
	ret = sha3_digest(temp, 64, digest, &length);

	for (i = 0; i < 16; i++) {

		tmp = digest[i] & 63;
		tmp += 48;
		ubuf[i] = tmp;

	}

}

static const struct file_operations pwkeeper_master_fops = {
	.write = pwkeeper_master_write,
};

static struct miscdevice pwkeeper_master_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pwkeeper_master",
	.fops = &pwkeeper_master_fops,
	.mode = 0666
};

static const struct file_operations pwkeeper_account_fops = {
	.read = pwkeeper_account_read,
	.write = pwkeeper_account_write,
};

static struct miscdevice pwkeeper_account_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pwkeeper_account",
	.fops = &pwkeeper_account_fops,
	.mode = 0666
};

/**
 * pwkeeper_accounts_show() - callback invoked when a process reads from
 * /sys/devices/platform/pwkeeper/accounts
 *
 * @dev: device driver data for sysfs entry (ignored)
 * @attr: sysfs entry context (ignored)
 * @buf: destination to store current user's accounts
 *
 * Write to @buf, up to PAGE_SIZE characters, a human-readable message
 * that lists all accounts registered for the current UID, and the
 * associated account passwords. Note that @buf is a normal character
 * buffer, not a __user buffer. Use scnprintf() in this function.
 *
 * @return Number of bytes written to @buf, or negative on error.
 */
static ssize_t pwkeeper_accounts_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct accounts *entry;
	int pos = 0;
	int n = 0;

	pos = scnprintf(buf, PAGE_SIZE, "Account  Password\n");
	n = scnprintf(buf + pos % PAGE_SIZE, PAGE_SIZE - pos % PAGE_SIZE,
		      "-------  ---------\n");

	list_for_each_entry(entry, &acc_head, list) {

		if (entry->uid == get_current_user()->uid.val) {
			pos += n;
			n = scnprintf(buf + pos % PAGE_SIZE,
				      PAGE_SIZE - pos % PAGE_SIZE, "%s %s\n",
				      entry->name, entry->pw);

		}
	}

	return pos + n;
}

/**
 * pwkeeper_master_show() - callback invoked when a process reads from
 * /sys/devices/platform/pwkeeper/masters
 *
 * @dev: device driver data for sysfs entry (ignored)
 * @attr: sysfs entry context (ignored)
 * @buf: destination to store login statistics
 *
 * Check if the calling process has CAP_SYS_ADMIN. If not, return
 * -EPERM.
 *
 * Otherwise, write to @buf, up to PAGE_SIZE characters, a
 * human-readable message that lists all users IDs that have
 * registered master passwords. Note that @buf is a normal character
 * buffer, not a __user buffer. Use scnprintf() in this function.
 *
 * @return Number of bytes written to @buf, or negative on error.
 */
static ssize_t pwkeeper_masters_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	struct master *m;
	int pos = 0;
	int n = 0;

	if (!ns_capable(pid_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	else {

		pos = scnprintf(buf, PAGE_SIZE, "Registered UIDs\n");
		n = scnprintf(buf + pos % PAGE_SIZE,
			      PAGE_SIZE - pos % PAGE_SIZE,
			      "----------------\n");
		list_for_each_entry(m, &master_head, list) {

			pos += n;
			n = scnprintf(buf + pos % PAGE_SIZE,
				      PAGE_SIZE - pos % PAGE_SIZE, "%u\n",
				      m->uid);

		}
	}

	return pos + n;
}

static DEVICE_ATTR(accounts, S_IRUGO, pwkeeper_accounts_show, NULL);
static DEVICE_ATTR(masters, S_IRUGO, pwkeeper_masters_show, NULL);

/**
 * cs421net_top() - top-half of CS421Net ISR
 * @irq: IRQ that was invoked (ignored)
 * @cookie: Pointer to data that was passed into
 * request_threaded_irq() (ignored)
 *
 * If @irq is CS421NET_IRQ, then wake up the bottom-half. Otherwise,
 * return IRQ_NONE.
 */
static irqreturn_t cs421net_top(int irq, void *cookie)
{
	if (irq == CS421NET_IRQ)
		return IRQ_WAKE_THREAD;
	else
		return IRQ_NONE;
}

/**
 * cs421net_bottom() - bottom-half to CS421Net ISR
 * @irq: IRQ that was invoked (ignore)
 * @cookie: Pointer that was passed into request_threaded_irq()
 * (ignored)
 *
 * Fetch the incoming packet, via cs421net_get_data(). Treat the input
 * as a 32-BIT LITTLE ENDIAN BINARY VALUE representing a UID. Search
 * through the master list and accounts list, deleting all nodes with
 * that UID. If the UID is exactly zero, then delete ALL nodes in the
 * master and accounts lists.
 *
 * If the packet length is not exactly 4 bytes, or if the provided
 * value does not match a registered UID in the master list, then do
 * nothing.
 *
 * Remember to add appropriate spin lock calls in this function.
 *
 * <em>Caution: The incoming payload is not a string; it is not null-terminated.</em>
 * You can NOT use strcpy() or strlen() on it.
 *
 * Return: always IRQ_HANDLED
 */
static irqreturn_t cs421net_bottom(int irq, void *cookie)
{
	size_t len = 0;
	uint8_t *data = cs421net_get_data(&len);
	unsigned long payload = 0;
	struct master *m;
	struct list_head *pos, *q;
	struct accounts *a;
	int i;

	if (len != 4) {

		printk(KERN_INFO "Length is not 4");
		kfree(data);
		return IRQ_HANDLED;

	}

	spin_lock(&a_lock);
	spin_lock(&m_lock);

	for (i = 0; i < len; i++) {

		payload += data[i] << (8 * i);

	}

	printk(KERN_INFO "New payload is: %lu", payload);
	list_for_each_safe(pos, q, &master_head) {

		if (payload == 0) {

			m = list_entry(pos, struct master, list);
			list_del(pos);
			kfree(m);

		}

		else if (payload == list_entry(pos, struct master, list)->uid) {

			m = list_entry(pos, struct master, list);
			list_del(pos);
			kfree(m);

		}

	}
	list_for_each_safe(pos, q, &acc_head) {

		if (payload == 0) {

			a = list_entry(pos, struct accounts, list);
			list_del(pos);
			kfree(pos);

		}

		else if (payload == list_entry(pos, struct accounts, list)->uid) {

			a = list_entry(pos, struct accounts, list);
			list_del(pos);
			kfree(a);

		}

	}

	spin_unlock(&m_lock);
	spin_unlock(&a_lock);
	return IRQ_HANDLED;

}

/**
 * pwkeeper_probe() - callback invoked when this driver is probed
 * @pdev platform device driver data (ignored)
 *
 * Return: 0 on successful probing, negative on error
 */
static int pwkeeper_probe(struct platform_device *pdev)
{
	int retval;
	unsigned long flags = 0;
	retval = misc_register(&pwkeeper_master_dev);
	if (retval) {
		pr_err("Could not register master device\n");
		goto err;
	}

	retval = misc_register(&pwkeeper_account_dev);
	if (retval) {
		pr_err("Could not register account device\n");
		goto err_deregister_master;
	}

	retval = device_create_file(&pdev->dev, &dev_attr_accounts);
	if (retval) {
		pr_err("Could not create sysfs entry\n");
		goto err_deregister_account;
	}

	retval = device_create_file(&pdev->dev, &dev_attr_masters);
	if (retval) {
		pr_err("Could not create sysfs entry\n");
		goto err_remove_sysfs_accounts;
	}

	/*
	 * In part 5, register the ISR and enable network
	 * integration. Make sure you clean up upon error.
	 */
	retval =
	    request_threaded_irq(CS421NET_IRQ, cs421net_top, cs421net_bottom,
				 flags, "cs421net", NULL);
	cs421net_enable();
	if (retval) {
		pr_err("Couldn't create int handler\n");
		goto err_remove_sysfs_masters;

	}

	pr_info("Probe successful\n");
	return 0;

err_remove_sysfs_masters:
	device_remove_file(&pdev->dev, &dev_attr_masters);
err_remove_sysfs_accounts:
	device_remove_file(&pdev->dev, &dev_attr_accounts);
err_deregister_account:
	misc_deregister(&pwkeeper_account_dev);
err_deregister_master:
	misc_deregister(&pwkeeper_master_dev);
err:
	pr_err("Probe failed, error %d\n", retval);
	return retval;

}

/**
 * pwkeeper_remove() - callback when this driver is removed
 * @pdev platform device driver data (ignored)
 *
 * Return: Always 0
 */
static int pwkeeper_remove(struct platform_device *pdev)
{
	struct accounts *a;
	struct list_head *p, *n;
	struct list_head *l = &acc_head;
	struct master *tmp;
	struct list_head *pos, *next;
	struct list_head *mylist = &master_head;

	pr_info("Removing\n");

	/*
	 * In part 5, disable network integration and remove the ISR.
	 */
	cs421net_disable();
	free_irq(CS421NET_IRQ, NULL);

	/*
	 * In part 3, free all memory associated with accounts list.
	 */

	list_for_each_safe(p, n, l) {
		a = list_entry(p, struct accounts, list);
		list_del(p);
		kfree(a);
	}

	/*
	 * In part 2, free all memory associated with master password
	 * list.
	 */

	list_for_each_safe(pos, next, mylist) {
		tmp = list_entry(pos, struct master, list);
		list_del(pos);
		kfree(tmp);
	}

	device_remove_file(&pdev->dev, &dev_attr_masters);
	device_remove_file(&pdev->dev, &dev_attr_accounts);
	misc_deregister(&pwkeeper_account_dev);
	misc_deregister(&pwkeeper_master_dev);
	return 0;
}

static struct platform_driver cs421_driver = {
	.driver = {
		   .name = "pwkeeper",
		   },
	.probe = pwkeeper_probe,
	.remove = pwkeeper_remove,
};

static struct platform_device *pdev;

/**
 * cs421_init() -  create the platform driver
 * This is needed so that the device gains a sysfs group.
 *
 * <strong>You do not need to modify this function.</strong>
 */
static int __init cs421_init(void)
{
	pdev = platform_device_register_simple("pwkeeper", -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);
	return platform_driver_register(&cs421_driver);
}

/**
 * cs421_exit() - remove the platform driver
 * Unregister the driver from the platform bus.
 *
 * <strong>You do not need to modify this function.</strong>
 */
static void __exit cs421_exit(void)
{
	platform_driver_unregister(&cs421_driver);
	platform_device_unregister(pdev);
}

module_init(cs421_init);
module_exit(cs421_exit);

MODULE_DESCRIPTION("CS421 Password Keeper - project 2");
MODULE_LICENSE("GPL");
