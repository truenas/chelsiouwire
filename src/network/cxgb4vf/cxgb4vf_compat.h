/*
 * This file is part of the Chelsio T4/T5/T6 Virtual Function (VF) Ethernet
 * driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4VF_COMPAT_H__
#define __CXGB4VF_COMPAT_H__

#include <linux/version.h>
#include "distro_compat.h"

#include <linux/if_vlan.h>

#if defined(ARCH_HAS_IOREMAP_WC)
#define wc_flush() wmb()
#define writel_wc(__v, __a) \
	do { \
		wmb(); /* memory store, WC MMIO store ordering */ \
		__raw_writel((__force u32)cpu_to_le32(__v), __a); \
		wc_flush(); \
	} while (0)
#else
#define wc_flush() do {} while(0)
#define writel_wc(__v, __a) writel(__v, __a)
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()  smp_mb()
#endif

#ifndef dma_rmb
#define dma_rmb()	rmb()
#endif

#endif /* __CXGB4VF_COMPAT_H__ */
