/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file is used to allow the driver to be compiled under multiple
 * versions of Linux with as few obtrusive in-line #ifdef's as possible.
 */

#ifndef __CXGB4_COMPAT_H
#define __CXGB4_COMPAT_H

#include <linux/version.h>
#include <net/inet6_hashtables.h>
#include "common.h"
#include "distro_compat.h"
#include <linux/pci.h>
#if defined(CONFIG_NET_RX_BUSY_POLL)
#include <net/busy_poll.h>
#endif
#ifndef _HAVE_ARCH_IPV6_CSUM
#include <net/ip6_checksum.h>
#endif

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef PORT_DA
#define PORT_DA 0x05
#endif
#ifndef PORT_OTHER
#define PORT_OTHER 0xff
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK		0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT		13
#endif

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
#endif  /* !__CXGB4_COMPAT_H */
