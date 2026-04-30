// SPDX-License-Identifier: GPL-2.0
/*
 * sprdwl_holdtime.c
 *
 * Diagnostic kretprobe wrapper around the major sprdwl_ng entry
 * points.  Records, per CPU, "which sprdwl_ng function is currently
 * executing and for how long".  Logs every call whose duration
 * exceeds threshold_ms (default 50) into a debugfs ring.
 *
 * Built to test the hypothesis that the unmitigated post-association
 * silent reset is caused by sprdwl_ng holding a CPU long enough that
 * userspace watchdogd misses a kick.  The companion
 * CONFIG_SOFTLOCKUP_DETECTOR + CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC
 * convert any >22s hold into a panic with a stack — this module gives
 * us live read-out of shorter-but-still-suspect holds before any
 * threshold fires.
 *
 * Logging only.  No mitigation.
 *
 * Targets are best-effort: a missing symbol logs a warning and is
 * skipped.  Use `cat /proc/kallsyms | grep sprdwl` after boot to
 * extend or trim the target list.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

static unsigned int threshold_ms = 50;
module_param(threshold_ms, uint, 0644);
MODULE_PARM_DESC(threshold_ms, "Log calls whose duration >= threshold_ms (default 50)");

static unsigned int panic_ms;
module_param(panic_ms, uint, 0644);
MODULE_PARM_DESC(panic_ms, "If >0 and a call exceeds panic_ms, panic() to flush pstore (default 0=off)");

#define HD_RING_SIZE	256u
#define HD_RING_MASK	(HD_RING_SIZE - 1u)

struct hd_slot {
	u64		enter_ns;
	const char	*fn;
	unsigned long	arg0;
	unsigned long	arg1;
	pid_t		pid;
	char		comm[TASK_COMM_LEN];
};

struct hd_event {
	u64		enter_ns;
	u64		exit_ns;
	const char	*fn;
	unsigned long	arg0;
	unsigned long	arg1;
	pid_t		pid;
	u32		cpu;
	char		comm[TASK_COMM_LEN];
};

struct hd_inst {
	u64 enter_ns;
};

struct hd_target {
	struct kretprobe rp;
	const char	*name;
	atomic64_t	enters;
	atomic64_t	exits;
	atomic64_t	slow;
	u64		max_ns;
	bool		registered;
};

static DEFINE_PER_CPU(struct hd_slot, hd_slots);

static struct hd_event	hd_ring[HD_RING_SIZE];
static u32		hd_ring_head;
static DEFINE_SPINLOCK(hd_ring_lock);
static u64		hd_global_max_ns;

static struct dentry	*dbg_dir;

#define MAX_TARGETS 16
static struct hd_target hd_targets[MAX_TARGETS];
static unsigned int	n_targets;

/*
 * Best-effort target list.  Each name is tried with register_kretprobe;
 * symbols not found in the running kernel/sprdwl_ng are silently
 * dropped from the active set.
 */
static const char *const target_names[] = {
	"sprdwl_rx_work_queue",
	"mm_mh_data_process",
	"sprdwl_send_data",
	"sprdwl_xmit",
	"sprdwl_tx_data",
	"sprdwl_send_cmd_recv_rsp",
	"sprdwl_cfg80211_scan",
	"sprdwl_cfg80211_connect",
	"sprdwl_cfg80211_disconnect",
	"sprdwl_init",
	"sprdwl_cmd_lock",
	"sprdwl_intf_set_sdio_clk",
	NULL,
};

static int hd_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hd_target *t = container_of(ri->rp, struct hd_target, rp);
	struct hd_inst *d = (struct hd_inst *)ri->data;
	struct hd_slot *s;
	u64 now = local_clock();

	d->enter_ns = now;

	s = this_cpu_ptr(&hd_slots);
	s->enter_ns = now;
	s->fn       = t->name;
	s->arg0     = regs->regs[0];
	s->arg1     = regs->regs[1];
	s->pid      = current->pid;
	memcpy(s->comm, current->comm, TASK_COMM_LEN);

	atomic64_inc(&t->enters);
	return 0;
}

static int hd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hd_target *t = container_of(ri->rp, struct hd_target, rp);
	struct hd_inst *d = (struct hd_inst *)ri->data;
	struct hd_slot *s;
	u64 now = local_clock();
	u64 elapsed = now - d->enter_ns;
	u64 threshold_ns = (u64)threshold_ms * NSEC_PER_MSEC;
	u64 panic_ns = (u64)panic_ms * NSEC_PER_MSEC;

	atomic64_inc(&t->exits);

	s = this_cpu_ptr(&hd_slots);
	if (s->fn == t->name)
		s->fn = NULL;

	if (elapsed >= threshold_ns) {
		struct hd_event *e;
		unsigned long flags;

		atomic64_inc(&t->slow);

		spin_lock_irqsave(&hd_ring_lock, flags);
		e = &hd_ring[hd_ring_head & HD_RING_MASK];
		hd_ring_head++;
		e->enter_ns = d->enter_ns;
		e->exit_ns  = now;
		e->fn       = t->name;
		e->arg0     = regs->regs[0];
		e->arg1     = 0;
		e->pid      = current->pid;
		e->cpu      = smp_processor_id();
		memcpy(e->comm, current->comm, TASK_COMM_LEN);

		if (elapsed > t->max_ns)
			t->max_ns = elapsed;
		if (elapsed > hd_global_max_ns)
			hd_global_max_ns = elapsed;
		spin_unlock_irqrestore(&hd_ring_lock, flags);

		pr_warn_ratelimited(
			"sprdwl_holdtime: %s held cpu%u for %llu ms (pid=%u comm=%s)\n",
			t->name, smp_processor_id(),
			elapsed / NSEC_PER_MSEC, current->pid, current->comm);
	}

	if (panic_ns && elapsed >= panic_ns) {
		panic("sprdwl_holdtime: %s held cpu%u for %llu ms >= panic_ms=%u",
		      t->name, smp_processor_id(),
		      elapsed / NSEC_PER_MSEC, panic_ms);
	}

	return 0;
}

static int current_show(struct seq_file *m, void *v)
{
	int cpu;
	u64 now = local_clock();

	seq_puts(m, "# cpu  elapsed_ms   pid  comm             fn\n");
	for_each_possible_cpu(cpu) {
		struct hd_slot s;
		u64 elapsed;

		s = *per_cpu_ptr(&hd_slots, cpu);
		if (!s.fn)
			continue;
		elapsed = now - s.enter_ns;
		seq_printf(m, "%5d  %10llu  %5u  %-16s %s  arg0=0x%lx arg1=0x%lx\n",
			   cpu, elapsed / NSEC_PER_MSEC,
			   s.pid, s.comm, s.fn, s.arg0, s.arg1);
	}
	return 0;
}

static int events_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	u32 i, span, start;

	spin_lock_irqsave(&hd_ring_lock, flags);
	span  = hd_ring_head < HD_RING_SIZE ? hd_ring_head : HD_RING_SIZE;
	start = hd_ring_head < HD_RING_SIZE ? 0 : hd_ring_head;
	spin_unlock_irqrestore(&hd_ring_lock, flags);

	seq_printf(m, "# global_max_ms=%llu  ring=%u/%u\n",
		   hd_global_max_ns / NSEC_PER_MSEC, span, HD_RING_SIZE);
	seq_puts(m, "# cpu  enter_ns         dur_ms   pid  comm             fn  arg0\n");

	for (i = 0; i < span; i++) {
		u32 idx = (start + i) & HD_RING_MASK;
		struct hd_event e;

		spin_lock_irqsave(&hd_ring_lock, flags);
		e = hd_ring[idx];
		spin_unlock_irqrestore(&hd_ring_lock, flags);

		if (!e.fn)
			continue;
		seq_printf(m, "%5u  %16llu  %7llu  %5u  %-16s %s  0x%lx\n",
			   e.cpu, e.enter_ns,
			   (e.exit_ns - e.enter_ns) / NSEC_PER_MSEC,
			   e.pid, e.comm, e.fn, e.arg0);
	}
	return 0;
}

static int stats_show(struct seq_file *m, void *v)
{
	unsigned int i;

	seq_printf(m, "threshold_ms=%u  panic_ms=%u  registered=%u/%u\n",
		   threshold_ms, panic_ms, n_targets, MAX_TARGETS);
	seq_puts(m, "# enters         exits          slow           max_ms     name\n");
	for (i = 0; i < MAX_TARGETS; i++) {
		struct hd_target *t = &hd_targets[i];

		if (!t->registered)
			continue;
		seq_printf(m, "  %-12llu   %-12llu   %-12llu   %-8llu   %s\n",
			   (u64)atomic64_read(&t->enters),
			   (u64)atomic64_read(&t->exits),
			   (u64)atomic64_read(&t->slow),
			   t->max_ns / NSEC_PER_MSEC,
			   t->name);
	}
	return 0;
}

#define DEFINE_SHOW_FOPS(NAME)						\
static int NAME##_open(struct inode *inode, struct file *f)		\
{ return single_open(f, NAME##_show, NULL); }				\
static const struct file_operations NAME##_fops = {			\
	.owner = THIS_MODULE, .open = NAME##_open,			\
	.read = seq_read, .llseek = seq_lseek, .release = single_release \
}

DEFINE_SHOW_FOPS(current);
DEFINE_SHOW_FOPS(events);
DEFINE_SHOW_FOPS(stats);

static ssize_t reset_write(struct file *f, const char __user *ubuf,
			   size_t len, loff_t *ppos)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&hd_ring_lock, flags);
	memset(hd_ring, 0, sizeof(hd_ring));
	hd_ring_head = 0;
	hd_global_max_ns = 0;
	for (i = 0; i < MAX_TARGETS; i++) {
		atomic64_set(&hd_targets[i].enters, 0);
		atomic64_set(&hd_targets[i].exits, 0);
		atomic64_set(&hd_targets[i].slow, 0);
		hd_targets[i].max_ns = 0;
	}
	spin_unlock_irqrestore(&hd_ring_lock, flags);
	return len;
}

static const struct file_operations reset_fops = {
	.owner = THIS_MODULE, .write = reset_write,
	.open = simple_open, .llseek = noop_llseek,
};

static int __init hd_init(void)
{
	const char *const *p;
	unsigned int i = 0;
	int ret;

	for (p = target_names; *p; p++) {
		struct hd_target *t;

		if (i >= MAX_TARGETS) {
			pr_warn("sprdwl_holdtime: target table full, dropping %s\n", *p);
			continue;
		}
		t = &hd_targets[i];
		t->name = *p;
		t->rp.kp.symbol_name = *p;
		t->rp.handler        = hd_ret;
		t->rp.entry_handler  = hd_entry;
		t->rp.data_size      = sizeof(struct hd_inst);
		t->rp.maxactive      = 0;  /* default = NR_CPUS */
		atomic64_set(&t->enters, 0);
		atomic64_set(&t->exits, 0);
		atomic64_set(&t->slow, 0);

		ret = register_kretprobe(&t->rp);
		if (ret) {
			pr_warn("sprdwl_holdtime: skip %s (%d)\n", *p, ret);
			t->name = NULL;
			continue;
		}
		t->registered = true;
		i++;
	}
	n_targets = i;
	if (!n_targets) {
		pr_err("sprdwl_holdtime: no targets armed; bailing\n");
		return -ENODEV;
	}

	dbg_dir = debugfs_create_dir("sprdwl_holdtime", NULL);
	if (!IS_ERR_OR_NULL(dbg_dir)) {
		debugfs_create_file("current", 0444, dbg_dir, NULL, &current_fops);
		debugfs_create_file("events",  0444, dbg_dir, NULL, &events_fops);
		debugfs_create_file("stats",   0444, dbg_dir, NULL, &stats_fops);
		debugfs_create_file("reset",   0200, dbg_dir, NULL, &reset_fops);
		debugfs_create_u32("threshold_ms", 0644, dbg_dir, &threshold_ms);
		debugfs_create_u32("panic_ms",     0644, dbg_dir, &panic_ms);
	}

	pr_info("sprdwl_holdtime: armed %u targets (threshold=%ums)\n",
		n_targets, threshold_ms);
	return 0;
}

static void __exit hd_exit(void)
{
	unsigned int i;

	for (i = 0; i < MAX_TARGETS; i++) {
		if (hd_targets[i].registered)
			unregister_kretprobe(&hd_targets[i].rp);
	}
	debugfs_remove_recursive(dbg_dir);
	pr_info("sprdwl_holdtime: disarmed (max=%llums)\n",
		hd_global_max_ns / NSEC_PER_MSEC);
}

module_init(hd_init);
module_exit(hd_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LineageOS SM-X205 port");
MODULE_DESCRIPTION("Per-CPU sprdwl_ng entry-point hold-time tracker");
