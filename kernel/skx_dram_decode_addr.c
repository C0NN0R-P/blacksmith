// kernel/skx_dram_decode_addr.c
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Connor Pfreundschuh");
MODULE_DESCRIPTION("Decode arbitrary physical address using skx_edac (with ioctl)");

// ------------ original decoded struct (kept, used by skx_decode) -------------
struct skx_dev;

struct decoded_addr {
	struct skx_dev *dev;
	u64 addr;
	int socket;
	int imc;
	int channel;
	u64 chan_addr;
	int sktways;
	int chanways;
	int dimm;
	int rank;
	int channel_rank;
	u64 rank_address;
	int row;
	int column;
	int bank_address;
	int bank_group;
};

// module parameter still present for one-off tests
static u64 phys_addr = 0;
module_param(phys_addr, ullong, 0644);
MODULE_PARM_DESC(phys_addr, "Physical address to decode (optional)");

typedef bool (*skx_decode_t)(struct decoded_addr *);
static skx_decode_t real_skx_decode = NULL;

static struct kprobe kp = {
	.symbol_name = "skx_decode",
};

// ----------------- UAPI struct for ioctl (must match userspace) --------------
struct skx_decode_req {
	u64 phys_addr;   /* in */
	int32_t channel; /* out */
	int32_t rank;    /* out */
	int32_t bank_group; /* out */
	int32_t bank;    /* out */
	int64_t row;     /* out */
	int64_t col;     /* out */
};

/* ioctl number: keep this value in sync with userspace _IOWR('k', 1, ...). */
#define SKX_IOCTL_DECODE _IOWR('k', 1, struct skx_decode_req)

static long skx_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct skx_decode_req req;
	struct decoded_addr res;
	bool ok;

	if (cmd != SKX_IOCTL_DECODE)
		return -ENOTTY;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	memset(&res, 0, sizeof(res));
	res.addr = req.phys_addr;

	if (!real_skx_decode) {
		pr_err("[skx_decode] real_skx_decode not resolved\n");
		return -ENOSYS;
	}

	ok = real_skx_decode(&res);
	if (!ok) {
		pr_err("[skx_decode] skx_decode failed for phys 0x%llx\n",
		       (unsigned long long)res.addr);
		return -EIO;
	}

	/* fill outputs */
	req.channel = res.channel;
	req.rank    = res.rank;
	req.bank_group = res.bank_group;
	req.bank    = res.bank_address;
	req.row     = res.row;
	req.col     = res.column;

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}

static const struct file_operations skx_misc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = skx_misc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = skx_misc_ioctl,
#endif
};

static struct miscdevice skx_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "skx_dram_decode",
	.fops = &skx_misc_fops,
};

// ----------------- init / exit ------------------------------------------------
static int __init skx_decode_init(void) {
	struct decoded_addr res;
	int ret;

	pr_info("[skx_decode] Loading skx_dram_decode_addr module (ioctl-enabled)...\n");

	/* find real skx_decode via kprobe */
	if (register_kprobe(&kp)) {
		pr_err("[skx_decode] Failed to register kprobe on skx_decode\n");
		return -ENOSYS;
	}
	real_skx_decode = (skx_decode_t)kp.addr;
	unregister_kprobe(&kp);
	if (!real_skx_decode) {
		pr_err("[skx_decode] Failed to resolve skx_decode address\n");
		return -ENOSYS;
	}

	/* register misc device */
	ret = misc_register(&skx_misc_dev);
	if (ret) {
		pr_err("[skx_decode] misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info("[skx_decode] misc device registered as /dev/%s\n", skx_misc_dev.name);

	/* legacy behavior: if phys_addr module param provided, decode and print */
	if (phys_addr != 0) {
		memset(&res, 0, sizeof(res));
		res.addr = phys_addr;
		if (real_skx_decode(&res)) {
			pr_info("[skx_decode] phys = 0x%llx => socket=%d imc=%d channel=%d dimm=%d rank=%d row=0x%x col=0x%x bank=%d bg=%d chan_addr=0x%llx sktways=%d chanways=%d channel_rank=%d rank_addr=0x%llx\n",
				(unsigned long long)res.addr,
				res.socket, res.imc, res.channel,
				res.dimm, res.rank, res.row, res.column,
				res.bank_address, res.bank_group,
				(unsigned long long)res.chan_addr,
				res.sktways, res.chanways, res.channel_rank,
				(unsigned long long)res.rank_address);
		} else {
			pr_err("[skx_decode] Failed to decode physical address 0x%llx\n",
			       (unsigned long long)phys_addr);
		}
	}

	return 0;
}

static void __exit skx_decode_exit(void) {
	misc_deregister(&skx_misc_dev);
	pr_info("[skx_decode] skx_dram_decode_addr module unloaded.\n");
}

module_init(skx_decode_init);
module_exit(skx_decode_exit);
