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

#ifndef __TOM_COMPAT_H
#define __TOM_COMPAT_H

#include <linux/version.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/inet_diag.h>
#include "distro_compat.h"

#define TCP_CONGESTION_CONTROL

#define ACCEPT_QUEUE(sk) (&inet_csk(sk)->icsk_accept_queue.rskq_accept_head)

#define MSS_CLAMP(tp) ((tp)->rx_opt.mss_clamp)
#define SND_WSCALE(tp) ((tp)->rx_opt.snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rx_opt.rcv_wscale)
#define USER_MSS(tp) ((tp)->rx_opt.user_mss)
#define TS_RECENT_STAMP(tp) ((tp)->rx_opt.ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->rx_opt.wscale_ok)
#define TSTAMP_OK(tp) ((tp)->rx_opt.tstamp_ok)
#define SACK_OK(tp) ((tp)->rx_opt.sack_ok)

#define INC_ORPHAN_COUNT(sk) percpu_counter_inc((sk)->sk_prot->orphan_count)
#define RSK_OPS

static inline struct dst_entry *route_req(struct sock *sk,
					const struct request_sock *req)
{
	struct flowi4 fl4;
	return inet_csk_route_req(sk, &fl4, req);
}

static void t4_rsk_destructor(struct request_sock *req)
{
}

static inline void t4_init_rsk_ops(struct proto *t4_tcp_prot,
				   struct request_sock_ops *t4_tcp_ops,
				   struct proto *tcp_prot, int family)
{
	memset(t4_tcp_ops, 0, sizeof(*t4_tcp_ops));
	t4_tcp_ops->family = family;
	t4_tcp_ops->obj_size = sizeof(struct tcp_request_sock);
	t4_tcp_ops->destructor = t4_rsk_destructor;
	t4_tcp_ops->slab = tcp_prot->rsk_prot->slab;
	BUG_ON(!t4_tcp_ops->slab);

	t4_tcp_prot->rsk_prot = t4_tcp_ops;
}

static inline void t4_init_rsk6_ops(struct proto *t4_tcp_prot,
                                   struct request_sock_ops *t4_tcp_ops,
                                   struct proto *tcp_prot, int family)
{
        memset(t4_tcp_ops, 0, sizeof(*t4_tcp_ops));
        t4_tcp_ops->family = family;
        t4_tcp_ops->obj_size = sizeof(struct tcp6_request_sock);
	t4_tcp_ops->destructor = t4_rsk_destructor;
        t4_tcp_ops->slab = tcp_prot->rsk_prot->slab;
	if (!t4_tcp_ops->slab)
		printk(KERN_WARNING
		       "t4_tom: IPv6 administratively disabled. "
		       "No IPv6 offload available\n");

        t4_tcp_prot->rsk_prot = t4_tcp_ops;
}

static inline void t4_set_ca_ops(struct sock *sk,
				 struct tcp_congestion_ops *t_ops)
{
	inet_csk(sk)->icsk_ca_ops = t_ops;
}

#define inet6_rsk(__oreq)	inet_rsk(__oreq)

typedef struct inet_request_sock inet6_request_sock_t;

static inline void t4_set_req_addr(struct request_sock *oreq,
				   __u32 local_ip, __u32 peer_ip)
{
	inet_rsk(oreq)->ir_loc_addr = local_ip;
	inet_rsk(oreq)->ir_rmt_addr = peer_ip;
}

static inline void t4_set_req_opt(struct request_sock *oreq,
				  struct ip_options_rcu *ip_opt)
{
	inet_rsk(oreq)->ireq_opt = ip_opt;
}

static inline void t4_set_inet_sock_opt(struct inet_sock *sk,
					struct ip_options_rcu *ip_opt)
{
	sk->inet_opt = ip_opt;
}

extern int prepare_tom_for_offload(void);
extern __u32 secure_tcp_sequence_number_offload(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);
extern struct page *pmd_page_offload(pmd_t pmd);

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_PPC64)
#if defined(CONFIG_PPC_BOOK3S)
extern void radix__flush_tlb_pte_p9_dd1_offload(unsigned long old_pte,
						struct mm_struct *mm,
						unsigned long address);
static inline unsigned long radix__pte_update_offload(
					struct mm_struct *mm,
					unsigned long addr,
					pte_t *ptep, unsigned long clr,
					unsigned long set, int huge)
{
	unsigned long old_pte;

	if (cpu_has_feature(CPU_FTR_POWER9_DD1)) {

		unsigned long new_pte;

		old_pte = __radix_pte_update(ptep, ~0ul, 0);
		/*
		 * new value of pte
		 */
		new_pte = (old_pte | set) & ~clr;
		radix__flush_tlb_pte_p9_dd1_offload(old_pte, mm, addr);
		if (new_pte)
		__radix_pte_update(ptep, 0, new_pte);
	} else
        	old_pte = __radix_pte_update(ptep, clr, set);
	if (!huge)
		assert_pte_locked(mm, addr);

	return old_pte;
}

static inline unsigned long t4_pte_update(struct mm_struct *mm,
					  unsigned long addr,
					  pte_t *ptep, unsigned long clr,
					  unsigned long set, int huge)
{
	if (radix_enabled())
		return radix__pte_update_offload(mm, addr, ptep, clr, set, huge);
	return hash__pte_update(mm, addr, ptep, clr, set, huge);
}
#else
#define t4_pte_update pte_update
#endif

#ifdef CONFIG_PPC_STD_MMU_64
static inline void t4_ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
                                      pte_t *ptep)
{

        if ((pte_val(*ptep) & _PAGE_RW) == 0)
                return;

        t4_pte_update(mm, addr, ptep, _PAGE_RW, 0, 0);
}
#else
#define t4_ptep_set_wrprotect ptep_set_wrprotect
#endif

static inline spinlock_t *t4_pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
        return ptlock_ptr(pmd_page_offload(*pmd));
}

#define t4_pte_offset_map_lock(mm, pmd, address, ptlp)     \
({                                                      \
        spinlock_t *__ptl = t4_pte_lockptr(mm, pmd);       \
        pte_t *__pte = pte_offset_map(pmd, address);    \
        *(ptlp) = __ptl;                                \
        spin_lock(__ptl);                               \
        __pte;                                          \
})

#else
#if defined(CONFIG_ARM64)
#ifndef __HAVE_ARCH_PTEP_SET_WRPROTECT
static inline void t4_ptep_set_wrprotect(struct mm_struct *mm,
					 unsigned long addr,
					 pte_t *ptep)
{
	pte_t old_pte = *ptep;
	pte_t pte = pte_wrprotect(old_pte);

	if (pte_valid_user(pte)) {
		if (pte_dirty(pte) && pte_write(pte))
			pte_val(pte) &= ~PTE_RDONLY;
		else
			pte_val(pte) |= PTE_RDONLY;
	}

	set_pte(ptep, pte);
}
#else
#define t4_ptep_set_wrprotect ptep_set_wrprotect
#endif
#else
#define t4_ptep_set_wrprotect ptep_set_wrprotect
#endif
#define t4_pte_offset_map_lock pte_offset_map_lock
#endif /* CONFIG_PPC64 */

extern void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr);
extern void flush_tlb_mm_offload(struct mm_struct *mm);
#endif /* CONFIG_T4_ZCOPY_SENDMSG_MODULE */

#define t4_inet_put_port(hash_info, sk) inet_put_port(sk)

/* Are BHs disabled already? */
static inline void t4_inet_inherit_port(struct inet_hashinfo *hash_info,
					struct sock *lsk, struct sock *newsk)
{
	local_bh_disable();
	__inet_inherit_port(lsk, newsk);
	local_bh_enable();
}

static inline void skb_gl_set(struct sk_buff *skb, struct ddp_gather_list *gl)
{
	skb_dst_set(skb, (void *)gl);
}

static inline struct ddp_gather_list *skb_gl(const struct sk_buff *skb)
{
	return (struct ddp_gather_list *)skb_dst(skb);
}

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
/*
 * We hide the Zero-Copy (ZCOPY) Virtual Address in the skb's "dst" field ...
 */
static inline void skb_vaddr_set(struct sk_buff *skb, unsigned long va)
{
	skb_dst_set(skb, (void *)va);
}

static inline unsigned long skb_vaddr(const struct sk_buff *skb)
{
	return (unsigned long)skb_dst(skb);
}
#endif

static inline void tom_eat_ddp_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_dst_set(skb, NULL);
	__skb_unlink(skb, &sk->sk_receive_queue);
	kfree_skb(skb);
}

static inline void tom_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_dst_set(skb, NULL);
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

#define DECLARE_TASK_FUNC(task, task_param) \
        static void task(struct work_struct *task_param)

#define WORK2TOMDATA(task_param, task) \
	container_of(task_param, struct tom_data, task)

#define T4_INIT_WORK(task_handler, task, adapter) \
        INIT_WORK(task_handler, task)

#define T4_DECLARE_WORK(task, func, data) \
	DECLARE_WORK(task, func)

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)

/* Older kernels don't have a PUD; if that's the case, simply fold that level.
 */
#ifndef PUD_SIZE
# define pud_t			pgd_t
# define pud_offset(pgd, addr)	(pgd)
# define pud_none(pud)		0
# define pud_bad(pud)		0
# define pud_present(pud)	0
#endif

/* Unfortunately, flush_tlb_range() is not available on all platforms and 
 * configurations and we must fall back to an implementation based on
 * flush_tlb_page(). Good thing that tlb flushing is in the exception path
 * only.
 */ 
#if defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
static inline void _t4_flush_tlb_range(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
        for (; start < end; start += PAGE_SIZE)
                flush_tlb_page_offload(vma, start);
}
#else
static inline void _t4_flush_tlb_range(struct vm_area_struct *vma,
				       unsigned long start, unsigned long end)
{
	for (; start < end; start += PAGE_SIZE)
		flush_tlb_page(vma, start);
}
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE) && defined(CONFIG_64BIT)
static inline void _t4_flush_tlb_mm(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
	flush_tlb_mm_offload(vma->vm_mm);
}
#else
static inline void _t4_flush_tlb_mm(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
	flush_tlb_range(vma, start, end);
}
#endif

#if defined(CONFIG_X86)
# if !defined(CONFIG_SMP)
#  define t4_flush_tlb_range flush_tlb_range
# elif defined(CONFIG_64BIT)
#  define t4_flush_tlb_range _t4_flush_tlb_mm
# else
#  define t4_flush_tlb_range _t4_flush_tlb_range
# endif
#elif defined(CONFIG_PPC)
# define t4_flush_tlb_range _t4_flush_tlb_range
#else
# define t4_flush_tlb_range flush_tlb_range
#endif
#if defined(CONFIG_T4_ZCOPY_HUGEPAGES)
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !(vma->vm_flags & (VM_SHARED|VM_EXEC));
}
#else
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !((vma->vm_flags & (VM_SHARED|VM_EXEC)) ||
		  is_vm_hugetlb_page(vma));
}
#endif

#if defined(CONFIG_T4_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
static __inline__ pte_t *t4_huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd = NULL;

        pgd = pgd_offset(mm, addr);
        if (pgd_present(*pgd)) {
                pud = pud_offset(pgd, addr);
                if (pud_present(*pud))
                        pmd = pmd_offset(pud, addr);
        }
        return (pte_t *) pmd;
}
#else
#error CONFIG_T4_ZCOPY_HUGEPAGES not supported on non-x86
#endif
#endif
#endif /* ZCOPY_SENDMSG */

#ifndef KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

#define TCP_PAGE(sk)   (sk->sk_frag.page)
#define TCP_OFF(sk)    (sk->sk_frag.offset)

static inline void tom_sysctl_set_de(struct ctl_table *tbl)
{}

static inline struct ctl_table_header *tom_register_sysctl_table(
						   struct ctl_table * table,
						   int insert_at_head)
{
	return register_sysctl_table(table);
}

#define T4_IP_INC_STATS_BH(net, field) IP_INC_STATS(net, field)
#define T4_TCP_INC_STATS_BH(net, field) TCP_INC_STATS(net, field)
#define T4_NET_INC_STATS_BH(net, field) NET_INC_STATS(net, field)
#define T4_NET_INC_STATS_USER(net, field) NET_INC_STATS(net, field)
#define T4_UDP_INC_STATS_USER(net, field, proto) UDP_INC_STATS(net, field, proto)
#define T4_UDP6_INC_STATS_USER(net, field, proto)  UDP6_INC_STATS(net, field, proto)
#define T4_ICMP6_INC_STATS_BH(net, idev, field) ICMP6_INC_STATS(net, idev, field)
#define T4_ICMP6MSGOUT_INC_STATS_BH(net, idev, type) ICMP6MSGOUT_INC_STATS(net, idev, type)
#define T4_TCP_INC_STATS(net, field)	TCP_INC_STATS(net, field)
#define t4_type_compat void
#define t4_pci_dma_mapping_error(p, a) pci_dma_mapping_error(p, a)

#define t4_get_user_pages_locked_with_flags_nowait(__a, __b, __c, __d, __e) \
	get_user_pages_locked(__a, __b, __c | FOLL_NOWAIT, __d, __e)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define t4_get_user_pages_locked_with_flags(__a, __b, __c, __d, __e) \
	get_user_pages_locked(__a, __b, __c, __d, __e)
#else
#define t4_get_user_pages_locked_with_flags(__a, __b, __c, __d, __e) \
	get_user_pages_fast(__a, __b, __c, __d)
#endif

#define t4_get_user_pages_locked get_user_pages_locked

#define GET_USER_PAGES(addr, nr_pages, write, pages) \
	 get_user_pages_fast(addr, nr_pages, write, pages)

#define __GET_USER_PAGES(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking) \
	__get_user_pages(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking)

static inline void t4_reqsk_free(struct request_sock *req)
{
        if (req->rsk_listener)
                sock_put(req->rsk_listener);
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void tom_skb_set_napi_id(struct sk_buff *skb,
				       unsigned int napi_id)
{
	skb->napi_id = napi_id;
}

static inline unsigned int tom_skb_get_napi_id(struct sk_buff *skb)
{
	return skb->napi_id;
}

static inline void tom_sk_set_napi_id(struct sock *sk, unsigned int napi_id)
{
	sk->sk_napi_id = napi_id;
}

static inline bool tom_sk_can_busy_loop(struct sock *sk)
{
	return sk_can_busy_loop(sk);
}

static inline void tom_sk_busy_loop(struct sock *sk, int nonblock)
{
	sk_busy_loop(sk, nonblock);
}

#define t4_pte_exec pte_user_exec

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

#if !defined(T4_TCP_HDR)
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif
#endif

#if !defined(SEC_INET_CONN_REQUEST)
static inline int security_inet_conn_request(struct sock *sk,
					     struct sk_buff *skb,
					     struct request_sock *req)
{
	return 0;
}
#endif

#if defined(OLD_OFFLOAD_H)
/*
 * Extended 'struct proto' with additional members used by offloaded
 * connections.
 */
struct sk_ofld_proto {
        struct proto proto;    /* keep this first */
        int (*read_sock)(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor);
};

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
extern int  install_special_data_ready(struct sock *sk);
extern void restore_special_data_ready(struct sock *sk);
#else
static inline int install_special_data_ready(struct sock *sk) { return 0; }
static inline void restore_special_data_ready(struct sock *sk) {}
#endif

#if defined(CONFIG_STRICT_KERNEL_RWX) && defined(CONFIG_TCP_OFFLOAD_MODULE)
extern void offload_socket_ops(struct sock *sk);
extern void restore_socket_ops(struct sock *sk);
#else
static inline void offload_socket_ops(struct sock *sk) {}
static inline void restore_socket_ops(struct sock *sk) {}
#endif

#endif

#if defined(DEACTIVATE_OFFLOAD)
struct toedev;
static inline int deactivate_offload(struct toedev *dev)
{
        return -1;
}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#define TUNABLE_INT_CTL_NAME(name) CTL_UNNUMBERED
#define TUNABLE_INT_RANGE_CTL_NAME(name) CTL_UNNUMBERED
#define TOM_INSTANCE_DIR_CTL_NAME CTL_UNNUMBERED
#define ROOT_DIR_CTL_NAME CTL_UNNUMBERED

#if defined(PPC64_TLB_BATCH_NR)
static inline void flush_tlb_mm_p(struct mm_struct *mm)
{
}

static inline void flush_tlb_page_p(struct vm_area_struct *vma,
				  unsigned long vmaddr)
{
}
#endif

#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_num num
#define inet_id id
#endif

static inline bool sk_has_sleepers(struct sock *sk)
{
        /* wq_has_sleeper() has smp_mb() in it ... */
        return skwq_has_sleeper(sk->sk_wq);
}

static inline void sk_wakeup_sleepers(struct sock *sk, bool interruptable)
{
	if (sk_has_sleepers(sk)) {
		if (interruptable)
			wake_up_interruptible(sk_sleep(sk));
		else
			wake_up_all(sk_sleep(sk));
	}
}

static inline void t4_set_req_port(struct request_sock *oreq,
				   __be16 source, __be16 dest)
{
	inet_rsk(oreq)->ir_rmt_port = source;
	inet_rsk(oreq)->ir_num = ntohs(dest);
}

static inline __be16 t4_get_req_lport(struct request_sock *oreq)
{
	return htons(inet_rsk(oreq)->ir_num);
}

typedef unsigned int socklen_t;

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_num num
#define inet_id id
#endif

static inline void t4_tcp_parse_options(const struct sock *sk, const struct sk_buff *skb,
                                        struct tcp_options_received *opt_rx,
                                        u8 **hvpp, int estab)
{
        tcp_parse_options(sock_net(sk), skb, opt_rx, estab, NULL);
}

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

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK          0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT         13
#endif

static inline struct rtattr *
__rta_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
	struct rtattr *rta;
	int size = RTA_LENGTH(attrlen);

	rta = (struct rtattr*)skb_put(skb, RTA_ALIGN(size));
	rta->rta_type = attrtype;
	rta->rta_len = size;
	memset(RTA_DATA(rta) + attrlen, 0, RTA_ALIGN(size) - size);
	return rta;
}

#define __RTA_PUT(skb, attrtype, attrlen) \
({     if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
               goto rtattr_failure; \
       __rta_reserve(skb, attrtype, attrlen); })

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

#define sk_sendmessage_page(sk)  ((sk)->sk_frag.page)

static inline struct sk_buff *t4_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto,
						 u16 vlan_tci)
{
	return vlan_insert_tag(skb, vlan_proto, vlan_tci);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,4,5)
#define ip6_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_dst_lookup_flow(__sk, __fl6, __final_dst)
#else
#define ip6_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_dst_lookup_flow(sock_net(__sk), __sk, __fl6, __final_dst)
#endif

#define ip6_sk_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep, connected) \
	ip6_sk_dst_lookup_flow(__sk, __fl6, __final_dst, connected)

#define sk_data_ready_compat(__sk, __bytes) \
	(__sk)->sk_data_ready(__sk)

/*
 * The story of sk_filter_charge()/sk_filter_uncharge() is long and taudry.
 * Older kernels used to make them available and then intermediate kernels hid
 * sk_filter_uncharge() (so we used sk_filter_release() possibly incorrectly).
 * Finally in 3.15 they got hidden completely so now we need to get pointers
 * to them in the kernel namelist ...
 */

extern void (*sk_filter_charge_p)(struct sock *, struct sk_filter *);
extern void (*sk_filter_uncharge_p)(struct sock *, struct sk_filter *);

#define sk_filter_charge_compat(__sk, __fp) sk_filter_charge_p(__sk, __fp)
#define sk_filter_uncharge_compat(__sk, __fp) sk_filter_uncharge_p(__sk, __fp)

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

extern struct sk_ofld_proto t4_tcp_prot;
extern struct sk_ofld_proto t4_tcp_v6_prot;
extern int *sysctl_tcp_moderate_rcvbuf_p;

extern void (*sk_stream_write_space_p)(struct sock*);
#define sk_stream_write_space_compat sk_stream_write_space_p

extern void (*tcp_xmit_timers_init_p)(struct sock *);
#define tcp_xmit_timers_init_compat(__a) tcp_xmit_timers_init_p(__a)
#define inet_twsk_deschedule_compat(__a) inet_twsk_deschedule_put(__a)
#define inet_reqsk_alloc(__a, __b) inet_reqsk_alloc(__a, __b, false)
#define inet_csk_reqsk_queue_added(__a, TCP_TIMEOUT_INIT) \
        inet_csk_reqsk_queue_added(__a)

static inline void t4_inet_twsk_purge(struct inet_hashinfo *hashinfo,
				      int family)
{
	struct inet_timewait_sock *tw;
	struct sock *sk;
	struct hlist_nulls_node *node;
	unsigned int slot;

	for (slot = 0; slot <= hashinfo->ehash_mask; slot++) {
		struct inet_ehash_bucket *head = &hashinfo->ehash[slot];
restart_rcu:
		cond_resched();
		rcu_read_lock();
restart:
		sk_nulls_for_each_rcu(sk, node, &head->chain) {
			if (sk->sk_state != TCP_TIME_WAIT)
				continue;
			if ((sk->sk_family == AF_INET) &&
				(sk_ofld_proto_get_tomhandlers(sk) !=
					&t4_tcp_prot.proto))
				continue;
#if defined(CONFIG_TCPV6_OFFLOAD)
			if ((sk->sk_family == AF_INET6) &&
				(sk_ofld_proto_get_tomhandlers(sk) !=
					&t4_tcp_v6_prot.proto))
				continue;
#endif

			tw = inet_twsk(sk);
			if ((tw->tw_family != family) ||
				refcount_read(&twsk_net(tw)->count))
				continue;

			if (unlikely(!refcount_inc_not_zero(&tw->tw_refcnt)))
				continue;

			if (unlikely((tw->tw_family != family) ||
				refcount_read(&twsk_net(tw)->count))) {
				inet_twsk_put(tw);
				goto restart;
			}

			rcu_read_unlock();
			local_bh_disable();
			inet_twsk_deschedule_put(tw);
			local_bh_enable();
			goto restart_rcu;
		}
		/* If the nulls value we got at the end of this lookup is
		 * not the expected one, we must restart lookup.
		 * We probably met an item that was moved to another chain.
		*/
		if (get_nulls_value(node) != slot)
			goto restart;
		rcu_read_unlock();
	}
}

#define inet_twsk_hashdance_compat(__tw, __sk, __hiptr) \
		inet_twsk_hashdance(__tw, __sk, __hiptr)

#define sock_create_kern(__a, __b, __c, __d) \
	sock_create_kern(&init_net, __a, __b, __c, __d)
#define sk_wait_data(__a, __b) sk_wait_data(__a, __b, NULL)

#define sock_wake_async_compat(__a, __b, __c, __d) sock_wake_async(__b, __c, __d)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define access_ok_compat(__a, __b, __c) access_ok(__a, __b, __c)
#else
#define access_ok_compat(__a, __b, __c) access_ok(__b, __c)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
static inline int bh_insert_handle(struct tom_data *d,
				   struct sock *sk,
				   int tid)
{
	int id;

	spin_lock_bh(&d->idr_lock);
	id = idr_alloc(&d->hwtid_idr, sk, tid, tid+1, GFP_NOWAIT);
	spin_unlock_bh(&d->idr_lock);
	return id;
}

static inline void bh_remove_handle(struct tom_data *d,
				    int tid)
{
	spin_lock_bh(&d->idr_lock);
	idr_remove(&d->hwtid_idr, tid);
	spin_unlock_bh(&d->idr_lock);
}

static inline int conn_insert_handle(struct tom_data *d,
				     struct sock *sk,
				     int tid)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&d->aidr_lock);
	id = idr_alloc(&d->aidr, sk, tid, tid+1, GFP_NOWAIT);
	spin_unlock_bh(&d->aidr_lock);
	idr_preload_end();
	return id;
}

static inline void bh_conn_remove_handle(struct tom_data *d,
					 int tid)
{
	spin_lock(&d->aidr_lock);
	idr_remove(&d->aidr, tid);
	spin_unlock(&d->aidr_lock);
}

static inline void conn_remove_handle(struct tom_data *d,
				      int tid)
{
	spin_lock_bh(&d->aidr_lock);
	idr_remove(&d->aidr, tid);
	spin_unlock_bh(&d->aidr_lock);
}
#else
static inline void bh_remove_handle(struct tom_data *d,
				    int tid)
{
	xa_erase_bh(&d->hwtid_idr, tid);
}

static inline void bh_conn_remove_handle(struct tom_data *d,
					 int tid)
{
	xa_erase(&d->aidr, tid);
}

static inline void conn_remove_handle(struct tom_data *d,
				      int tid)
{
	xa_erase_bh(&d->aidr, tid);
}
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
extern void (*ip6_route_input_p)(struct sk_buff *skb);
#endif
#define inet6_reqsk_alloc inet_reqsk_alloc
#define net_random()		prandom_u32()
#define FLOWI_FLAG_CAN_SLEEP    0
#endif /* __TOM_COMPAT_H */
