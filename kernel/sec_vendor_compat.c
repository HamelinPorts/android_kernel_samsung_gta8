// SPDX-License-Identifier: GPL-2.0
/*
 * sec_vendor_compat.c - Symbol shims for Samsung X205XXS6DYG6 vendor .ko files
 *
 * Several kernel symbols imported by Samsung's precompiled vendor modules
 * (mali_gondul.ko, sprd_vdsp.ko, ...) were either renamed or replaced with
 * CPP macros between the X205XXS6DYG6 stock kernel and the LineageOS rebuild.
 * The CRC-based vermagic fallback in kernel/module.c can paper over CRC drift
 * but cannot resurrect a symbol that no longer exists. This file provides the
 * minimum set of EXPORT_SYMBOL'd wrappers to keep those vendor modules
 * loadable.
 *
 * Each shim is a tiny adapter to the modern in-tree implementation. The
 * vendor's CRCs for these symbols are already in kernel/sec_vendor_crcs.h, so
 * once the symbols exist again, check_version() will fall through to the
 * X205XXS6DYG6 whitelist and accept them.
 */

#include <linux/export.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/time64.h>
#include <linux/idr.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/build_bug.h>
#include <linux/stddef.h>

/* ------------------------------------------------------------------------- */
/* Vendor-binary ABI offset asserts                                          */
/*                                                                           */
/* Samsung's precompiled vendor .ko files have stock 4.14.199 struct offsets */
/* hard-compiled. Where a later 4.14.y LTS backport moved a field the blob   */
/* directly reads or writes, we re-pad / reshape the kernel definition to    */
/* restore the stock offset.                                                 */
/*                                                                           */
/* These BUILD_BUG_ON assertions fail the build if any future change shifts  */
/* a guarded field, so the blob incompatibility cannot regress silently.    */
/* See maliissue-analysis.md for the full analysis.                          */
/* ------------------------------------------------------------------------- */

static void __maybe_unused sec_vendor_abi_offset_asserts(void)
{
	/* mm_struct.mmap_sem @ 0x70 — consumed by mali_gondul.ko's
	 * kbase_jd_submit / kbase_mem_import / kbase_os_mem_map_lock /
	 * kbase_mem_commit / kbase_mem_flags_change paths, all of which
	 * have `add x0, x8, #0x70` hard-compiled for &current->mm->mmap_sem.
	 * Restored by the pad field in struct mm_struct.             */
	BUILD_BUG_ON(offsetof(struct mm_struct, mmap_sem) != 0x70);
}

/* ------------------------------------------------------------------------- */
/* ns_to_timespec                                                            */
/*                                                                           */
/* Stock X205 kernel exported ns_to_timespec() unconditionally.              */
/* LineageOS gates the function inside #if __BITS_PER_LONG == 32 in          */
/* kernel/time/time.c, and include/linux/time32.h CPP-substitutes            */
/* "ns_to_timespec" with "ns_to_timespec64" for all in-tree callers.         */
/* Vendor modules built before that change still import the symbol by name,  */
/* so we provide a real exported function here.                              */
/* ------------------------------------------------------------------------- */
#undef ns_to_timespec
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec64 ts64 = ns_to_timespec64(nsec);
	struct timespec ts;

	ts.tv_sec  = (time_t)ts64.tv_sec;
	ts.tv_nsec = ts64.tv_nsec;
	return ts;
}
EXPORT_SYMBOL(ns_to_timespec);

/* ------------------------------------------------------------------------- */
/* set_normalized_timespec                                                   */
/*                                                                           */
/* Same gating story as ns_to_timespec: the implementation in                */
/* kernel/time/time.c is inside #if __BITS_PER_LONG == 32, and time32.h has  */
/* a "set_normalized_timespec -> set_normalized_timespec64" CPP define for   */
/* in-tree callers. sprd_camera.ko was built before that and imports the     */
/* legacy name.                                                              */
/* ------------------------------------------------------------------------- */
#undef set_normalized_timespec
void set_normalized_timespec(struct timespec *ts, time_t sec, s64 nsec)
{
	struct timespec64 ts64 = { .tv_sec = sec, .tv_nsec = 0 };

	set_normalized_timespec64(&ts64, sec, nsec);
	ts->tv_sec  = (time_t)ts64.tv_sec;
	ts->tv_nsec = ts64.tv_nsec;
}
EXPORT_SYMBOL(set_normalized_timespec);

/* ------------------------------------------------------------------------- */
/* ida_simple_get / ida_simple_remove                                        */
/*                                                                           */
/* LineageOS replaced these with CPP macros around ida_alloc_range() and     */
/* ida_free() in include/linux/idr.h, but that is the easy half of the       */
/* problem. The harder half is that LineageOS also rewrote                   */
/* struct radix_tree_root (the only field of struct ida) and inserted a      */
/* spinlock_t xa_lock at offset 0:                                           */
/*                                                                           */
/*     stock:    { gfp_t gfp_mask; struct radix_tree_node *rnode; }    16 B  */
/*     lineage:  { spinlock_t xa_lock; gfp_t gfp_mask;                       */
/*                 struct radix_tree_node *rnode; }                    24 B  */
/*                                                                           */
/* Vendor .ko files (sprd_vdsp etc.) statically allocate their struct ida    */
/* objects with the 16-byte stock layout. If we let LineageOS's              */
/* ida_alloc_range() touch those objects directly it reads the vendor's     */
/* gfp_mask (= IDR_RT_MARKER | GFP_NOWAIT = 0x800) as if it were the         */
/* embedded spinlock and spins forever waiting for it to "unlock", which     */
/* trips the hardware watchdog inside ~20 s. Verified empirically against    */
/* the X205 socko.d/sprd_vdsp.ko.                                            */
/*                                                                           */
/* The shim has to translate every vendor struct-ida pointer into a fresh    */
/* LineageOS-format struct ida that LineageOS can poke at safely. We use     */
/* the vendor pointer as an opaque cookie and keep a hash table of           */
/* (vendor_ptr, real_ida) pairs. As long as the vendor module always passes  */
/* the same pointer for the same logical IDA, the IDs returned to it stay   */
/* consistent.                                                               */
/* ------------------------------------------------------------------------- */
#undef ida_simple_get
#undef ida_simple_remove

struct sec_compat_ida {
	void			*vendor_ptr;
	struct ida		real_ida;
	struct hlist_node	node;
};

static DEFINE_HASHTABLE(sec_compat_ida_map, 6);
static DEFINE_SPINLOCK(sec_compat_ida_map_lock);

static struct ida *sec_get_compat_ida(void *vendor_ida)
{
	struct sec_compat_ida *e, *new_entry;
	unsigned long flags;
	unsigned long key = (unsigned long)vendor_ida;

	spin_lock_irqsave(&sec_compat_ida_map_lock, flags);
	hash_for_each_possible(sec_compat_ida_map, e, node, key) {
		if (e->vendor_ptr == vendor_ida) {
			spin_unlock_irqrestore(&sec_compat_ida_map_lock, flags);
			return &e->real_ida;
		}
	}
	spin_unlock_irqrestore(&sec_compat_ida_map_lock, flags);

	/* First time we see this vendor pointer -- allocate a real IDA. */
	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry)
		return NULL;
	new_entry->vendor_ptr = vendor_ida;
	ida_init(&new_entry->real_ida);

	spin_lock_irqsave(&sec_compat_ida_map_lock, flags);
	/* Re-check for a racing inserter */
	hash_for_each_possible(sec_compat_ida_map, e, node, key) {
		if (e->vendor_ptr == vendor_ida) {
			spin_unlock_irqrestore(&sec_compat_ida_map_lock, flags);
			ida_destroy(&new_entry->real_ida);
			kfree(new_entry);
			return &e->real_ida;
		}
	}
	hash_add(sec_compat_ida_map, &new_entry->node, key);
	spin_unlock_irqrestore(&sec_compat_ida_map_lock, flags);
	pr_info_once("sec_vendor_compat: bridging vendor struct ida @ %px to a LineageOS-format ida\n",
		     vendor_ida);
	return &new_entry->real_ida;
}

int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask)
{
	struct ida *real = sec_get_compat_ida(ida);

	if (!real)
		return -ENOMEM;
	return ida_alloc_range(real, start, end ? end - 1 : ~0u, gfp_mask);
}
EXPORT_SYMBOL(ida_simple_get);

void ida_simple_remove(struct ida *ida, unsigned int id)
{
	struct ida *real = sec_get_compat_ida(ida);

	if (real)
		ida_free(real, id);
}
EXPORT_SYMBOL(ida_simple_remove);

/* ------------------------------------------------------------------------- */
/* __ll_sc___cmpxchg_case_mb_4                                               */
/*                                                                           */
/* The arm64 LL/SC cmpxchg helpers used to be named with the operand size    */
/* in bytes (..._1 / _2 / _4 / _8). LineageOS renamed them to bit widths     */
/* (..._8 / _16 / _32 / _64) so the only "_4" exporter is gone. mali_gondul  */
/* still imports __ll_sc___cmpxchg_case_mb_4, which is the same operation    */
/* as __ll_sc___cmpxchg_case_mb_32 (4 bytes == 32 bits). Provide an alias.   */
/* ------------------------------------------------------------------------- */
#ifdef CONFIG_ARM64
extern u32 __ll_sc___cmpxchg_case_mb_32(volatile void *ptr, unsigned long old,
					u32 new);

u32 __ll_sc___cmpxchg_case_mb_4(volatile void *ptr, unsigned long old, u32 new)
{
	return __ll_sc___cmpxchg_case_mb_32(ptr, old, new);
}
EXPORT_SYMBOL(__ll_sc___cmpxchg_case_mb_4);
#endif
