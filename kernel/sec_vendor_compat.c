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
/* ida_simple_get / ida_simple_remove                                        */
/*                                                                           */
/* LineageOS replaced these with CPP macros around ida_alloc_range() and     */
/* ida_free() in include/linux/idr.h, so the legacy function symbols are     */
/* gone from vmlinux. Vendor modules (sprd_vdsp.ko etc.) still want them.    */
/* ------------------------------------------------------------------------- */
#undef ida_simple_get
#undef ida_simple_remove

int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask)
{
	return ida_alloc_range(ida, start, end ? end - 1 : ~0u, gfp_mask);
}
EXPORT_SYMBOL(ida_simple_get);

void ida_simple_remove(struct ida *ida, unsigned int id)
{
	ida_free(ida, id);
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
