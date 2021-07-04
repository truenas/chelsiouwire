/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2019 Chelsio Communications.  All rights reserved.
 * See the corresponding files in the Linux tree for copyrights of the
 * original Linux code a lot of this file is based on.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* The following tags are used by the out-of-kernel Makefile to identify
 * supported kernel versions if a module_support-<kver> file is not found.
 * Do not remove these tags.
 * $SUPPORTED KERNEL 5.0$
 * $SUPPORTED KERNEL 5.1$
 * $SUPPORTED KERNEL 5.2$
 * $SUPPORTED KERNEL 5.4$
 * $SUPPORTED KERNEL 5.6$
 * $SUPPORTED KERNEL 5.10$
 */

#include <net/tcp.h>
#include <linux/pkt_sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "defs.h"
#include <asm/tlbflush.h>
#include <linux/hash.h>

static unsigned long (*kallsyms_lookup_name_p)(const char *name);

#if defined(CONFIG_PPC64)
static void (*hpte_need_flush_p)(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep, unsigned long pte, int huge);
static struct page *(*pmd_page_p)(pmd_t pmd);

#if defined(CONFIG_PPC_BOOK3S)
static void (*radix__flush_tlb_pte_p9_dd1_p)(unsigned long old_pte,
					     struct mm_struct *mm,
					     unsigned long address);
void radix__flush_tlb_pte_p9_dd1_offload(unsigned long old_pte,
					 struct mm_struct *mm,
					 unsigned long address)
{
	if (radix__flush_tlb_pte_p9_dd1_p)
		radix__flush_tlb_pte_p9_dd1_p(old_pte, mm, address);
}
#endif

void hpte_need_flush(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep, unsigned long pte, int huge)
{
	if (hpte_need_flush_p)
		hpte_need_flush_p(mm, addr, ptep, pte, huge);
}

struct page *pmd_page_offload(pmd_t pmd)
{
	struct page *page = NULL;
	if (pmd_page_p)
		page = pmd_page_p(pmd);
	return page;
}
#endif

static void (*tcp_update_metrics_p)(struct sock *sk);
static __u32 (*secure_tcp_seq_p)(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport);
void (*tcp_xmit_timers_init_p)(struct sock *);
void (*sk_stream_write_space_p)(struct sock *);

#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if !defined(CONFIG_ARM64)
static void (*flush_tlb_mm_range_p)(struct mm_struct *mm,
           unsigned long start, unsigned long end, unsigned long vmflag);
#endif
#if defined(CONFIG_PPC64)
static void (*flush_tlb_page_p)(struct vm_area_struct *vma,
				unsigned long va);
#endif
#endif
void flush_tlb_mm_offload(struct mm_struct *mm);
#endif

#ifdef CONFIG_UDPV6_OFFLOAD
void (*ipv6_local_rxpmtu_p)(struct sock *sk, struct flowi6 *fl6, u32 mtu);
void (*ipv6_local_error_p)(struct sock *sk, int err, struct flowi6 *fl6,
			   u32 info);
void (*ipv6_push_nfrag_opts_p)(struct sk_buff *skb, struct ipv6_txoptions *opt,
			      u8 *proto,
				struct in6_addr **daddr, struct in6_addr *saddr);
struct proto *udpv6_prot_p;
#endif /* CONFIG_UDPV6_OFFLOAD */

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
struct proto * tcpv6_prot_p;
void (*ip6_route_input_p)(struct sk_buff *skb);
#endif

struct tcp_congestion_ops *tcp_reno_p;
void (*sk_filter_charge_p)(struct sock *, struct sk_filter *);
void (*sk_filter_uncharge_p)(struct sock *, struct sk_filter *);

void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_PPC64)
	flush_tlb_page_p(vma, addr);
#endif
#endif
#endif
}

int sysctl_tcp_window_scaling __read_mostly = 1;

static bool addr_same(const struct inetpeer_addr *a,
                      const struct inetpeer_addr *b)
{
        return inetpeer_addr_cmp(a, b) == 0;
}

struct tcpm_hash_bucket {
	struct tcp_metrics_block __rcu  *chain;
};

enum tcp_metric_index {
	TCP_METRIC_RTT,
	TCP_METRIC_RTTVAR,
	TCP_METRIC_SSTHRESH,
	TCP_METRIC_CWND,
	TCP_METRIC_REORDERING,

	TCP_METRIC_RTT_US,	/* in usec units */
	TCP_METRIC_RTTVAR_US,	/* in usec units */

	/* Always last.  */
	__TCP_METRIC_MAX,
};

#define TCP_METRIC_MAX	(__TCP_METRIC_MAX - 1)

/* TCP_METRIC_MAX includes 2 extra fields for userspace compatibility
 * Kernel only stores RTT and RTTVAR in usec resolution
 */
#define TCP_METRIC_MAX_KERNEL (TCP_METRIC_MAX - 2)

struct tcp_fastopen_metrics {
	u16	mss;
	u16	syn_loss:10,		/* Recurring Fast Open SYN losses */
		try_exp:2;		/* Request w/ exp. option (once) */
	unsigned long	last_syn_loss;	/* Last Fast Open SYN loss */
	struct	tcp_fastopen_cookie	cookie;
};

struct tcp_metrics_block {
	struct tcp_metrics_block __rcu	*tcpm_next;
	possible_net_t                  tcpm_net;
	struct inetpeer_addr		tcpm_saddr;
	struct inetpeer_addr		tcpm_daddr;
	unsigned long			tcpm_stamp;
	u32				tcpm_ts;
	u32				tcpm_ts_stamp;
	u32				tcpm_lock;
	u32				tcpm_vals[TCP_METRIC_MAX_KERNEL + 1];
	struct tcp_fastopen_metrics	tcpm_fastopen;

	struct rcu_head			rcu_head;
};

#define TCP_METRICS_RECLAIM_DEPTH	5
#define TCP_METRICS_RECLAIM_PTR		(struct tcp_metrics_block *) 0x1UL

#define deref_locked(p) \
        rcu_dereference_protected(p, lockdep_is_held(&tcp_metrics_lock))

static inline struct net *tm_net(struct tcp_metrics_block *tm)
{
	return read_pnet(&tm->tcpm_net);
}

static struct tcp_metrics_block *tcp_get_encode(struct tcp_metrics_block *tm, int depth)
{
	if (tm)
		return tm;
	if (depth > TCP_METRICS_RECLAIM_DEPTH)
		return TCP_METRICS_RECLAIM_PTR;
	return NULL;
}

static struct tcpm_hash_bucket  *tcp_metrics_hash __read_mostly;
static unsigned int             tcp_metrics_hash_log __read_mostly;

static struct tcp_metrics_block *__tcp_get_metrics(const struct inetpeer_addr *saddr,
						   const struct inetpeer_addr *daddr,
						   struct net *net, unsigned int hash)
{
	struct tcp_metrics_block *tm;
	int depth = 0;

	for (tm = rcu_dereference(tcp_metrics_hash[hash].chain); tm;
	     tm = rcu_dereference(tm->tcpm_next)) {
		if (addr_same(&tm->tcpm_saddr, saddr) &&
		    addr_same(&tm->tcpm_daddr, daddr) &&
		    net_eq(tm_net(tm), net))
			break;
		depth++;
	}
	return tcp_get_encode(tm, depth);
}

static DEFINE_SPINLOCK(tcp_metrics_lock);

static void tcpm_suck_dst(struct tcp_metrics_block *tm,
			  const struct dst_entry *dst,
			  bool fastopen_clear)
{
	u32 msval;
	u32 val;

	tm->tcpm_stamp = jiffies;

	val = 0;
	if (dst_metric_locked(dst, RTAX_RTT))
		val |= 1 << TCP_METRIC_RTT;
	if (dst_metric_locked(dst, RTAX_RTTVAR))
		val |= 1 << TCP_METRIC_RTTVAR;
	if (dst_metric_locked(dst, RTAX_SSTHRESH))
		val |= 1 << TCP_METRIC_SSTHRESH;
	if (dst_metric_locked(dst, RTAX_CWND))
		val |= 1 << TCP_METRIC_CWND;
	if (dst_metric_locked(dst, RTAX_REORDERING))
		val |= 1 << TCP_METRIC_REORDERING;
	tm->tcpm_lock = val;

	msval = dst_metric_raw(dst, RTAX_RTT);
	tm->tcpm_vals[TCP_METRIC_RTT] = msval * USEC_PER_MSEC;

	msval = dst_metric_raw(dst, RTAX_RTTVAR);
	tm->tcpm_vals[TCP_METRIC_RTTVAR] = msval * USEC_PER_MSEC;
	tm->tcpm_vals[TCP_METRIC_SSTHRESH] = dst_metric_raw(dst, RTAX_SSTHRESH);
	tm->tcpm_vals[TCP_METRIC_CWND] = dst_metric_raw(dst, RTAX_CWND);
	tm->tcpm_vals[TCP_METRIC_REORDERING] = dst_metric_raw(dst, RTAX_REORDERING);
	tm->tcpm_ts = 0;
	tm->tcpm_ts_stamp = 0;
	if (fastopen_clear) {
		tm->tcpm_fastopen.mss = 0;
		tm->tcpm_fastopen.syn_loss = 0;
		tm->tcpm_fastopen.try_exp = 0;
		tm->tcpm_fastopen.cookie.exp = false;
		tm->tcpm_fastopen.cookie.len = 0;
	}
}

#define TCP_METRICS_TIMEOUT             (60 * 60 * HZ)

static void tcpm_check_stamp(struct tcp_metrics_block *tm, struct dst_entry *dst)
{
	if (tm && unlikely(time_after(jiffies, tm->tcpm_stamp + TCP_METRICS_TIMEOUT)))
		tcpm_suck_dst(tm, dst, false);
}

static struct tcp_metrics_block *tcpm_new(struct dst_entry *dst,
					  struct inetpeer_addr *saddr,
					  struct inetpeer_addr *daddr,
					  unsigned int hash)
{
	struct tcp_metrics_block *tm;
	struct net *net;
	bool reclaim = false;

	spin_lock_bh(&tcp_metrics_lock);
	net = dev_net(dst->dev);

	/* While waiting for the spin-lock the cache might have been populated
	 * with this entry and so we have to check again.
	 */
	tm = __tcp_get_metrics(saddr, daddr, net, hash);
	if (tm == TCP_METRICS_RECLAIM_PTR) {
		reclaim = true;
		tm = NULL;
	}
	if (tm) {
		tcpm_check_stamp(tm, dst);
		goto out_unlock;
	}

	if (unlikely(reclaim)) {
		struct tcp_metrics_block *oldest;

		oldest = deref_locked(tcp_metrics_hash[hash].chain);
		for (tm = deref_locked(oldest->tcpm_next); tm;
			tm = deref_locked(tm->tcpm_next)) {
				if (time_before(tm->tcpm_stamp, oldest->tcpm_stamp))
					oldest = tm;
		}
		tm = oldest;
	} else {
		tm = kmalloc(sizeof(*tm), GFP_ATOMIC);
		if (!tm)
			goto out_unlock;
	}
	write_pnet(&tm->tcpm_net, net);
	tm->tcpm_saddr = *saddr;
	tm->tcpm_daddr = *daddr;

	tcpm_suck_dst(tm, dst, true);

	if (likely(!reclaim)) {
		tm->tcpm_next = tcp_metrics_hash[hash].chain;
		rcu_assign_pointer(tcp_metrics_hash[hash].chain, tm);
	}

out_unlock:
	spin_unlock_bh(&tcp_metrics_lock);
	return tm;
}

static struct tcp_metrics_block *tcp_get_metrics(struct sock *sk,
						 struct dst_entry *dst,
						 bool create)
{
	struct tcp_metrics_block *tm;
	struct inetpeer_addr saddr, daddr;
	unsigned int hash;
	struct net *net;

	if (sk->sk_family == AF_INET) {
		inetpeer_set_addr_v4(&saddr, inet_sk(sk)->inet_saddr);
		inetpeer_set_addr_v4(&daddr, inet_sk(sk)->inet_daddr);
		hash = ipv4_addr_hash(inet_sk(sk)->inet_daddr);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6) {
		if (ipv6_addr_v4mapped(&sk->sk_v6_daddr)) {
			inetpeer_set_addr_v4(&saddr, inet_sk(sk)->inet_saddr);
			inetpeer_set_addr_v4(&daddr, inet_sk(sk)->inet_daddr);
			hash = ipv4_addr_hash(inet_sk(sk)->inet_daddr);
		} else {
			inetpeer_set_addr_v6(&saddr, &sk->sk_v6_rcv_saddr);
			inetpeer_set_addr_v6(&daddr, &sk->sk_v6_daddr);
			hash = ipv6_addr_hash(&sk->sk_v6_daddr);
		}
	}
#endif
	else
		return NULL;

	net = dev_net(dst->dev);
	hash ^= net_hash_mix(net);
	hash = hash_32(hash, tcp_metrics_hash_log);

	tm = __tcp_get_metrics(&saddr, &daddr, net, hash);
	if (tm == TCP_METRICS_RECLAIM_PTR)
                tm = NULL;
	if (!tm && create)
		tm = tcpm_new(dst, &saddr, &daddr, hash);
	else
		tcpm_check_stamp(tm, dst);
	return tm;
}

/* VJ's idea. Save last timestamp seen from this destination and hold
 * it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter
 * synchronized state.
 */
bool tcp_remember_stamp(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	bool ret = false;

	if (dst) {
		struct tcp_metrics_block *tm;

		rcu_read_lock();
		tm = tcp_get_metrics(sk, dst, true);
		if (tm) {
			struct tcp_sock *tp = tcp_sk(sk);

			if ((s32)(tm->tcpm_ts - tp->rx_opt.ts_recent) <= 0 ||
			    ((u32)get_seconds() - tm->tcpm_ts_stamp > TCP_PAWS_MSL &&
			     tm->tcpm_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
				tm->tcpm_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
				tm->tcpm_ts = tp->rx_opt.ts_recent;
			}
			ret = true;
		}
		rcu_read_unlock();
	}
	return ret;
}

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#define t4_flush_tlb_mm(mm)        flush_tlb_mm_range_p(mm, 0UL, TLB_FLUSH_ALL, 0UL)
#else
#define t4_flush_tlb_mm(mm)        flush_tlb_mm(mm)
#endif

void flush_tlb_mm_offload(struct mm_struct *mm)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
		t4_flush_tlb_mm(mm);
#endif
#endif
}

__u32 secure_tcp_sequence_number_offload(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	if (secure_tcp_seq_p)
		return secure_tcp_seq_p(saddr, daddr, sport, dport);
	return 0;
}

static int find_kallsyms_lookup_name(void)
{
	int err = 0;

#if defined(KPROBES_KALLSYMS)
	struct kprobe kp;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	err = register_kprobe(&kp);
	if (!err) {
		kallsyms_lookup_name_p = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
#else
	kallsyms_lookup_name_p = (void *)KALLSYMS_LOOKUP;
#endif
	if (!err)
		err = kallsyms_lookup_name_p == NULL;

	return err;
}

#define FIND_SYMBOL(name, ptr) do { \
	ptr = (void *)kallsyms_lookup_name_p(name); \
	if (!ptr) { \
		pr_err("Could not locate " name "\n"); \
		return -1; \
	} \
} while (0)

int prepare_tom_for_offload(void)
{
	if (!kallsyms_lookup_name_p) {
		int err = find_kallsyms_lookup_name();

		if (err) {
			pr_err("find_kallsyms_lookup_name failed\n");
			return err;
		}
	}

#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	FIND_SYMBOL("flush_tlb_mm_range", flush_tlb_mm_range_p);
#endif
#if defined(CONFIG_PPC64)
	FIND_SYMBOL("flush_tlb_page", flush_tlb_page_p);
#endif
#endif
#endif

	FIND_SYMBOL("secure_tcp_seq", secure_tcp_seq_p);
	FIND_SYMBOL("tcp_update_metrics", tcp_update_metrics_p);
	FIND_SYMBOL("tcp_reno", tcp_reno_p);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	FIND_SYMBOL("tcpv6_prot", tcpv6_prot_p);
	FIND_SYMBOL("ip6_route_input", ip6_route_input_p);
#endif

	FIND_SYMBOL("sk_filter_charge", sk_filter_charge_p);
	FIND_SYMBOL("sk_filter_uncharge", sk_filter_uncharge_p);

#if defined(CONFIG_PPC64)
	FIND_SYMBOL("hpte_need_flush", hpte_need_flush_p);
	FIND_SYMBOL("pmd_page", pmd_page_p);
#if defined(CONFIG_PPC_BOOK3S)
	FIND_SYMBOL("radix__flush_tlb_pte_p9_dd1",
		    radix__flush_tlb_pte_p9_dd1_p);
#endif
#endif

	FIND_SYMBOL("tcp_init_xmit_timers", tcp_xmit_timers_init_p);
	FIND_SYMBOL("sk_stream_write_space", sk_stream_write_space_p);

#ifdef CONFIG_UDPV6_OFFLOAD
	FIND_SYMBOL("udpv6_prot", udpv6_prot_p);
	FIND_SYMBOL("ipv6_local_rxpmtu", ipv6_local_rxpmtu_p);
	FIND_SYMBOL("ipv6_local_error", ipv6_local_error_p);
	FIND_SYMBOL("ipv6_push_nfrag_opts", ipv6_push_nfrag_opts_p);
#endif /* CONFIG_UDPV6_OFFLOAD */

	return 0;
}
