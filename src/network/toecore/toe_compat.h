/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOE_COMPAT_H
#define __TOE_COMPAT_H

#include <linux/version.h>
#include "distro_compat.h"

/* semaphore.h is under include/linux for 2.6.27 */
#ifdef LINUX_SEMAPHORE_H
#include <linux/semaphore.h>
#else
#include <asm/semaphore.h>
#endif

#include <linux/version.h>

#define T3_IP_INC_STATS_BH(net, field) IP_INC_STATS_BH(net, field)

#if defined(KALLSYMS_LOOKUP_NAME)
#include <linux/kallsyms.h>
#endif /* KALLSYMS_LOOKUP_NAME */

#ifdef CONFIG_IA64
static inline int change_page_attr(struct page *page, int numpages,
				   pgprot_t prot)
{
	return 0;
}

static inline void global_flush_tlb(void)
{}

/* Unused dummy value */
#define PAGE_KERNEL_RO	__pgprot(0)
#endif

#ifdef LOOPBACK
static inline int ipv4_is_loopback(__be32 addr)
{
	return LOOPBACK(addr);
}
#endif

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
/* prevent collision with (struct mac_addr) definition in bond_3ad.h */
#define mac_addr __br_mac_addr
#include <net/bridge/br_private.h>
#undef mac_addr

#if defined(NETIF_F_TCPIP_OFFLOAD)
static inline void br_set_offload_mask(struct net_bridge *br)
{
	br->feature_mask |= NETIF_F_TCPIP_OFFLOAD;

}
#endif
#endif

/*
 * In Linux 3.1 dst->neighbour was removed and we now need to use the function
 * dst_neigh_lookup() which takes a reference on the neighbour.  These
 * compatibility routines encode that dependency.
 */
static inline struct neighbour *t4_dst_neigh_lookup(const struct dst_entry *dst,
                                                    const void *daddr)
{
        return dst_neigh_lookup(dst, daddr);
}

static inline void t4_dst_neigh_release(struct neighbour *neigh)
{
        neigh_release(neigh);
}

static inline int t4_get_sysctl_tcp_timestamps(struct net *net)
{
	return net->ipv4.sysctl_tcp_timestamps;
}

static inline int t4_get_sysctl_tcp_sack(struct net *net)
{
	return net->ipv4.sysctl_tcp_sack;
}

static inline int t4_get_sysctl_tcp_ecn(struct net *net)
{
	return net->ipv4.sysctl_tcp_ecn;
}

static inline int t4_get_sysctl_tcp_win_scaling(struct net *net)
{
	return net->ipv4.sysctl_tcp_window_scaling;
}

#if !defined(for_each_netdev)
#define for_each_netdev(d) \
	for (d = dev_base; d; d = d->next)
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}
#endif

#if !defined(TRANSPORT_HEADER)
#define transport_header h.raw
#define network_header nh.raw
#endif

#if !defined(SEC_INET_CONN_ESTABLISHED)
static inline void security_inet_conn_established(struct sock *sk,
						  struct sk_buff *skb)
{}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#define INET_PROC_DIR init_net.proc_net

#if !defined(VLAN_DEV_API)
#include <linux/if_vlan.h>
#if defined(VLAN_DEV_INFO)
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev);
}
#endif

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
#else /* VLAN_DEV_API */

#if defined(RHEL_RELEASE_5_7)
#include <linux/if_vlan.h>
static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->vlan_id;
}
#endif /* RHEL_RELEASE */
#endif /* VLAN_DEV_API */

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_id id
#endif

#if !defined(INIT_RCU_HEAD)
#define INIT_RCU_HEAD(ptr)
#endif

#if defined(RHEL_RELEASE_6_2)
#include <net/secure_seq.h>
#endif /* RHEL_RELEASE */

typedef struct list_head * bond_list_iter;

#define bond_for_each_slave_compat(__bond, __pos, __iter) \
	bond_for_each_slave(__bond, __pos, __iter)

#define bond_first_slave_compat(__bond) \
	bond_first_slave_rcu(__bond)

#define inet6_sk_saddr(__sk)	inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	(__sk)->sk_v6_rcv_saddr
#define inet6_sk_daddr(__sk)	(__sk)->sk_v6_daddr

#define net_random()		prandom_u32()

/*
 * A little complicated here.  The Bond Slave AD Information used to be an
 * embedded structure within the (struct slave) and is now a pointer to
 * a separately allocated structure.  So SLAVE_AD_INFO() used to be a
 * reference to that embedded structure and we'd see uses of code like
 *
 *     SLAVE_AD_INFO(slave).port
 *
 * but these now need to be
 *
 *     SLAVE_AD_INFO(slave)->port
 *
 * So we give ourselves a compatibility definition which work more like the
 * new one.
 */
#define SLAVE_AD_INFO_COMPAT(__slave) \
	SLAVE_AD_INFO(__slave)

#define bond_read_lock_compat(__bond)	rcu_read_lock();
#define bond_read_unlock_compat(__bond)	rcu_read_unlock();

#define tcp_rcv_established_compat(__sk, __skb, __hdr) \
		tcp_rcv_established(__sk, __skb)
#endif /* __TOE_COMPAT_H */
