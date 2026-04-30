// SPDX-License-Identifier: GPL-2.0
/*
 * sprdwl_rx_kprobe.c
 *
 * Out-of-tree diagnostic + mitigation for the SM-X205 LineageOS port.
 *
 * Probes the vendor sprdwl_ng.ko's `sprdwl_free_data(void *ptr, int is_page)`
 * at entry. Two complementary detection strategies flag double-frees:
 *
 * 1. Hash-table: records recently freed ptrs; a repeat within window_ms
 *    is a candidate double-free.
 * 2. Refcount: for is_page=1 (page-frag) frees, reads the backing page's
 *    actual _refcount via virt_to_head_page + page_count.  refcount <= 0
 *    means the page was already freed — definitive double-free.
 *
 * With mitigate=1 (default), a confirmed double-free is neutralized by
 * zeroing x0 and x1 so the function executes `kfree(NULL)` (a no-op).
 *
 * v2 (2026-04-17): fast-path optimisation — the ring buffer, strscpy,
 * and pr_info are only touched on dup/refcount_bad events.  The common
 * no-dup path does only: NULL check, refcount read, hash lookup + update
 * under spinlock, and an atomic counter bump.  This cuts per-call
 * overhead from ~200 cycles to ~50 to reduce SDIO latency pressure on
 * the CM4 watchdog.
 *
 * Load after sprdwl_ng.ko.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
#include <linux/mm.h>
#include <linux/page_ref.h>
#include <linux/atomic.h>

#define TARGET_SYM    "sprdwl_free_data"
#define SLOT_BITS     12
#define SLOT_COUNT    (1u << SLOT_BITS)
#define SLOT_MASK     (SLOT_COUNT - 1u)
#define RING_SIZE     512u
#define RING_MASK     (RING_SIZE - 1u)

static unsigned int window_ms = 15000;
module_param(window_ms, uint, 0644);
MODULE_PARM_DESC(window_ms, "Hash-table repeat-detection window in ms (default 15000)");

static bool verbose;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Log every probed call via pr_info (noisy)");

static bool mitigate = true;
module_param(mitigate, bool, 0644);
MODULE_PARM_DESC(mitigate, "Neutralize detected double-frees (default true)");

struct slot {
	void		*ptr;
	unsigned long	ts;
	unsigned long	lr;
	u32		cpu;
	u32		is_page;
};

struct event {
	void		*ptr;
	unsigned long	ts;
	unsigned long	lr;
	unsigned long	prev_lr;
	u32		cpu;
	u32		prev_cpu;
	u32		is_page;
	u32		pid;
	u32		dup;
	u32		blocked;
	int		refcount;
	char		comm[TASK_COMM_LEN];
};

static struct slot	slots[SLOT_COUNT];
static struct event	ring[RING_SIZE];
static u32		ring_head;
static atomic64_t	total_calls = ATOMIC64_INIT(0);
static u64		total_dups;
static u64		total_blocked;
static DEFINE_SPINLOCK(lock);
static struct dentry	*dbg_dir;

static inline u32 slot_idx(void *p)
{
	return hash_long((unsigned long)p >> 4, SLOT_BITS) & SLOT_MASK;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	void *ptr        = (void *)regs->regs[0];
	u32   is_page    = (u32)regs->regs[1];
	unsigned long lr = regs->regs[30];
	unsigned long now = jiffies;
	unsigned long window = msecs_to_jiffies(window_ms);
	struct slot  *s;
	unsigned long flags;
	u32 idx;
	bool hash_hit = false;
	bool refcount_bad = false;
	int  rc = 0;

	if (!ptr)
		return 0;

	/*
	 * Refcount check for page-frag frees: if the head page's refcount
	 * is already <= 0, the page was freed — this free is definitely bogus.
	 * Do this outside the spinlock (atomic read, no locking needed).
	 */
	if (is_page) {
		struct page *head = virt_to_head_page(ptr);
		rc = page_count(head);
		if (rc <= 0)
			refcount_bad = true;
	}

	idx = slot_idx(ptr);
	s = &slots[idx];

	spin_lock_irqsave(&lock, flags);

	atomic64_inc(&total_calls);

	/* Hash-table repeat check */
	if (s->ptr == ptr && time_before_eq(now, s->ts + window))
		hash_hit = true;

	if (refcount_bad || hash_hit) {
		/*
		 * Slow path: record the event in the ring buffer.
		 * Only taken on actual or candidate double-frees.
		 */
		struct event *e = &ring[ring_head & RING_MASK];

		ring_head++;
		e->ptr      = ptr;
		e->ts       = now;
		e->lr       = lr;
		e->cpu      = smp_processor_id();
		e->is_page  = is_page;
		e->pid      = current->pid;
		e->refcount = rc;
		e->blocked  = 0;
		strscpy(e->comm, current->comm, TASK_COMM_LEN);
		e->dup = 1;

		if (hash_hit) {
			e->prev_cpu = s->cpu;
			e->prev_lr  = s->lr;
		} else {
			e->prev_cpu = 0;
			e->prev_lr  = 0;
		}
		total_dups++;

		if (mitigate && refcount_bad) {
			regs->regs[0] = 0;
			regs->regs[1] = 0;
			e->blocked = 1;
			total_blocked++;
		}

		spin_unlock_irqrestore(&lock, flags);

		pr_warn_ratelimited(
			"sprdwl_rx_kprobe: DOUBLE FREE %s ptr=%px is_page=%u "
			"refcount=%d cpu=%u lr=0x%lx pid=%u comm=%s%s\n",
			refcount_bad && mitigate ? "[BLOCKED]" : "[LOGGED]",
			ptr, is_page, rc,
			smp_processor_id(), lr, current->pid, current->comm,
			refcount_bad ? " (page already freed)" :
			hash_hit     ? " (hash repeat)" : "");
		return 0;
	}

	/*
	 * Fast path: no dup detected.  Update the hash slot and return.
	 * No ring buffer write, no strscpy, no pr_info (unless verbose).
	 */
	s->ptr     = ptr;
	s->ts      = now;
	s->lr      = lr;
	s->cpu     = smp_processor_id();
	s->is_page = is_page;

	spin_unlock_irqrestore(&lock, flags);

	if (unlikely(verbose))
		pr_info("sprdwl_rx_kprobe: ptr=%px is_page=%u rc=%d cpu=%u lr=0x%lx\n",
			ptr, is_page, rc, smp_processor_id(), lr);

	return 0;
}

static struct kprobe kp = {
	.symbol_name = TARGET_SYM,
	.pre_handler = handler_pre,
};

static int events_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	u32 i, start, span;
	u64 calls, dups, blocked;

	spin_lock_irqsave(&lock, flags);
	calls   = atomic64_read(&total_calls);
	dups    = total_dups;
	blocked = total_blocked;
	span    = ring_head < RING_SIZE ? ring_head : RING_SIZE;
	start   = ring_head < RING_SIZE ? 0 : ring_head;
	spin_unlock_irqrestore(&lock, flags);

	seq_printf(m,
		   "total_calls=%llu total_dups=%llu total_blocked=%llu "
		   "window_ms=%u mitigate=%u ring=%u/%u\n",
		   calls, dups, blocked, window_ms, mitigate, span, RING_SIZE);
	seq_puts(m, "# idx ts_j dup blk cpu pid rc lr              ptr              is_page prev_cpu prev_lr         comm\n");

	for (i = 0; i < span; i++) {
		u32 idx = (start + i) & RING_MASK;
		struct event e;

		spin_lock_irqsave(&lock, flags);
		e = ring[idx];
		spin_unlock_irqrestore(&lock, flags);

		if (!e.ts)
			continue;
		seq_printf(m,
			   "%4u %lu %u %u %u %u %d 0x%016lx %px %u %u 0x%016lx %s\n",
			   i, e.ts, e.dup, e.blocked, e.cpu, e.pid,
			   e.refcount, e.lr, e.ptr, e.is_page,
			   e.prev_cpu, e.prev_lr, e.comm);
	}
	return 0;
}

static int events_open(struct inode *inode, struct file *f)
{
	return single_open(f, events_show, NULL);
}

static const struct file_operations events_fops = {
	.owner   = THIS_MODULE,
	.open    = events_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static ssize_t reset_write(struct file *f, const char __user *ubuf,
			   size_t len, loff_t *ppos)
{
	unsigned long flags;

	spin_lock_irqsave(&lock, flags);
	memset(slots, 0, sizeof(slots));
	memset(ring,  0, sizeof(ring));
	ring_head     = 0;
	atomic64_set(&total_calls, 0);
	total_dups    = 0;
	total_blocked = 0;
	spin_unlock_irqrestore(&lock, flags);
	return len;
}

static const struct file_operations reset_fops = {
	.owner = THIS_MODULE,
	.write = reset_write,
	.open  = simple_open,
	.llseek = noop_llseek,
};

static int __init krxp_init(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("sprdwl_rx_kprobe: register_kprobe(%s) failed: %d (is sprdwl_ng loaded?)\n",
		       TARGET_SYM, ret);
		return ret;
	}

	dbg_dir = debugfs_create_dir("sprdwl_rx_kprobe", NULL);
	if (!IS_ERR_OR_NULL(dbg_dir)) {
		debugfs_create_file("events", 0444, dbg_dir, NULL, &events_fops);
		debugfs_create_file("reset",  0200, dbg_dir, NULL, &reset_fops);
		debugfs_create_u64("total_calls",   0444, dbg_dir,
				   (u64 *)&total_calls);
		debugfs_create_u64("total_dups",    0444, dbg_dir, &total_dups);
		debugfs_create_u64("total_blocked", 0444, dbg_dir, &total_blocked);
		debugfs_create_u32("window_ms",     0644, dbg_dir, &window_ms);
	}

	pr_info("sprdwl_rx_kprobe: armed at %s@%px (window=%ums mitigate=%u)\n",
		TARGET_SYM, kp.addr, window_ms, mitigate);
	return 0;
}

static void __exit krxp_exit(void)
{
	unregister_kprobe(&kp);
	debugfs_remove_recursive(dbg_dir);
	pr_info("sprdwl_rx_kprobe: disarmed (calls=%llu dups=%llu blocked=%llu)\n",
		atomic64_read(&total_calls), total_dups, total_blocked);
}

module_init(krxp_init);
module_exit(krxp_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LineageOS SM-X205 port");
MODULE_DESCRIPTION("Kprobe on sprdwl_free_data: detect and neutralize RX-path double-frees");
