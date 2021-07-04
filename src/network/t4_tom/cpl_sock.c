/*
 * This file implements the interface between the socket layer and
 * the HW TCP/CPL, including the protocol operations for Chelsio's HW TCP.
 *
 * Large portions of this file are taken from net/ipv4/tcp.c.
 * See that file for copyrights of the original code.
 * Any additional code is
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/toedev.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/kref.h>
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#include <linux/pagemap.h>
#include <linux/mm.h>
#endif

#include <net/offload.h>
#include <net/tcp.h>
#include <net/ip.h>
#if defined(CONFIG_NET_RX_BUSY_POLL)
#include <net/busy_poll.h>
#endif

#if defined(CONFIG_TCPV6_OFFLOAD)
#include <net/transp_v6.h>
#endif
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include "l2t.h"
#include "defs.h"
#include "t4_ddp.h"
#include "tom.h"
#include "t4_tcb.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "trace.h"
#include "t4_tls.h"

#define DEFAULT_RCV_COALESCE_SIZE 16224U

#ifdef CONFIG_TCPV6_OFFLOAD
extern struct proto *tcpv6_prot_p;
#endif

/* Release callback invoked by kref_put() in chelsio_destroy_sock() */
void t4_cplios_release(struct kref *ref)
{
	struct cpl_io_state *cplios =
		container_of(ref, struct cpl_io_state, kref);

	kfree(cplios);
}

/*
 * This must be called with the socket locked, otherwise dev may be NULL.
 */
static inline int chelsio_wspace(const struct sock *sk)
{
	struct toedev *dev = CPL_IO_STATE(sk)->toedev;

	return dev ? TOM_TUNABLE(dev, max_host_sndbuf) - sk->sk_wmem_queued : 0;
}

/*
 * TCP socket write_space callback.  Follows sk_stream_write_space().
 */
void t4_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct socket_wq *wq;

	if (chelsio_wspace(sk) >= sk_stream_min_wspace(sk) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		rcu_read_lock();
		wq = rcu_dereference(sk->sk_wq);
		if (sk_has_sleepers(sk))
			wake_up_interruptible_poll(&wq->wait, POLLOUT |
							      POLLWRNORM |
							      POLLWRBAND);
		if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async_compat(sock, wq, SOCK_WAKE_SPACE, POLL_OUT);
		rcu_read_unlock();
	}
}

static inline int tcp_memory_free(struct sock *sk)
{
	return chelsio_wspace(sk) > 0;
}

/*
 * Wait for memory to become available, either space in a socket's send buffer
 * or system memory.
 */
static int wait_for_mem(struct sock *sk, long *timeo_p)
{
	int sndbuf, err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	bool noblock = (*timeo_p ? false : true);
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	/*
	 * We open code tcp_memory_free() because we need it outside the
	 * socket lock and chelsio_wspace() isn't safe there.
	 */
	sndbuf = TOM_TUNABLE(CPL_IO_STATE(sk)->toedev, max_host_sndbuf);

	if (sndbuf > sk->sk_wmem_queued)
		current_timeo = vm_wait = (prandom_u32() % (HZ / 5)) + 2;

	add_wait_queue(sk_sleep(sk), &wait);

	while (1) {
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);

		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
			goto do_error;
		if (!*timeo_p) {
			if (noblock)
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto do_nonblock;
		}
		if (signal_pending(current))
			goto do_interrupted;
		sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		if (sndbuf > sk->sk_wmem_queued && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		sk_wait_event(sk, &current_timeo, sk->sk_err ||
						  (sk->sk_shutdown & SEND_SHUTDOWN) ||
						  (sndbuf > sk->sk_wmem_queued &&
						  !vm_wait), &wait);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}
out:
	remove_wait_queue(sk_sleep(sk), &wait);
	return err;

do_error:
	err = -EPIPE;
	goto out;
do_nonblock:
	err = -EAGAIN;
	goto out;
do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;
}

void skb_entail(struct sock *sk, struct sk_buff *skb, int flags)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ULP_SKB_CB(skb)->seq = tp->write_seq;
	ULP_SKB_CB(skb)->flags = flags;
	__skb_queue_tail(&cplios->tx_queue, skb);
	sk->sk_wmem_queued += skb->truesize;
	// tcp_charge_skb(sk, skb);

	// Do not share pages across sk_buffs
	if (TCP_PAGE(sk) && TCP_OFF(sk)) {
		put_page(TCP_PAGE(sk));
		TCP_PAGE(sk) = NULL;
		TCP_OFF(sk) = 0;
	}
}

/*
 * Returns true if a connection should send more data to the TOE ASAP.
 */
static inline int should_push(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *dev = cplios->toedev;

	/*
	 * If we've released our offload resources there's nothing to do ...
	 */
        if (dev == NULL)
		return 0;

	/*
	 * If there aren't any work requests in flight, or there isn't enough
	 * data in flight, or Nagle is off then send the current TX_DATA
	 * otherwise hold it and wait to accumulate more data.
	 */
	return cplios->wr_credits == cplios->wr_max_credits ||
		tp->snd_nxt - tp->snd_una <= TOM_TUNABLE(dev, tx_hold_thres) ||
		!cplios->nagle;
}

/*
 * Returns true if a TCP socket is corked.
 */
static inline int corked(const struct tcp_sock *tp, int flags)
{
	return (flags & MSG_MORE) | (tp->nonagle & TCP_NAGLE_CORK);
}

/*
 * Returns true if a send should try to push new data.
 */
static inline int send_should_push(struct sock *sk, int flags)
{
	return should_push(sk) && !corked(tcp_sk(sk), flags);
}

static inline void tx_skb_finalize(struct sk_buff *skb)
{
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	/*
	 * XXX We don't want to finalize an skb if it's flagged for ZCOPY
	 * XXX since we'll end up losing the flag.  This needs to be looked
	 * XXX at more closely since we're blindly clearing a bunch of flags
	 * XXX here.  Most of these flags (including those for ZCOPY)
	 * XXX probably ought to be retained rather than tossed and we
	 * XXX should certainly have an assert for flags that shouldn't
	 * XXX find their way into this routine ...
	 */
	if (cb->flags & (ULPCB_FLAG_ZCOPY|
			 ULPCB_FLAG_ZCOPY_COW|
			 ULPCB_FLAG_ZCOPY_COW_SKIP))
		return;
#endif

	if (!(cb->flags & ULPCB_FLAG_NO_HDR))
		cb->flags = ULPCB_FLAG_NEED_HDR;
	cb->flags |= ULPCB_FLAG_NO_APPEND;
}

static inline void mark_urg(struct tcp_sock *tp, int flags,
			    struct sk_buff *skb)
{
	if (unlikely(flags & MSG_OOB)) {
		tp->snd_up = tp->write_seq;
		ULP_SKB_CB(skb)->flags = ULPCB_FLAG_URG | ULPCB_FLAG_BARRIER |
					 ULPCB_FLAG_NO_APPEND |
					 ULPCB_FLAG_NEED_HDR;
	}
}

/*
 * Decide if the last frame on the send queue needs any special annotations
 * (e.g., marked URG) and whether it should be transmitted immediately or
 * held for additional data.  This is the only routine that performs the full
 * suite of tests for a Tx packet and therefore must be called for the last
 * packet added by the various send*() APIs.
 */
static void t4_tcp_push(struct sock *sk, int flags)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int qlen = skb_queue_len(&cplios->tx_queue);

	if (likely(qlen)) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct sk_buff *skb = skb_peek_tail(&cplios->tx_queue);

		mark_urg(tp, flags, skb);

		if (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) &&
		    corked(tp, flags)) {
			ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_HOLD;
			return;
		}

		ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_HOLD;
		if (qlen == 1 &&
		    ((ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) ||
		     should_push(sk)))
			t4_push_frames(sk, 1);
	}
}

static void tcp_uncork(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->nonagle & TCP_NAGLE_CORK) {
		tp->nonagle &= ~TCP_NAGLE_CORK;
		t4_tcp_push(sk, 0);
	}
}

/*
 * Try to transmit the send queue if it has just one packet.  This is intended
 * to be called as full packets are added to the send queue by the various
 * send*() APIs when we expect additional packets to be generated by the
 * current API call.  It should not be called for the last packet generated,
 * use the full t4_tcp_push call above for that.
 */
static inline void push_frames_if_head(struct sock *sk)
{
	if (skb_queue_len(&CPL_IO_STATE(sk)->tx_queue) == 1)
		t4_push_frames(sk, 1);
}

static struct sk_buff *alloc_tx_skb(struct sock *sk, int size)
{
	struct sk_buff *skb;

	skb = alloc_skb(size + TX_HEADER_LEN, sk->sk_allocation);
	if (likely(skb)) {
		skb_reserve(skb, TX_HEADER_LEN);
		skb_entail(sk, skb, ULPCB_FLAG_NEED_HDR);
		skb_reset_transport_header(skb);
	}
	return skb;
}

/*
 * Calculate the size for a new send sk_buff.  It's maximum size so we can
 * pack lots of data into it, unless we plan to send it immediately, in which
 * case we size it more tightly.
 *
 * Note: we don't bother compensating for MSS < PAGE_SIZE because it doesn't
 * arise in normal cases and when it does we are just wasting memory.
 */
static inline int select_size(struct sock *sk, int io_len, int flags, int len)
{
	const int pgbreak = SKB_MAX_HEAD(len);

	/*
	 * If the data wouldn't fit in the main body anyway, put only the
	 * header in the main body so it can use immediate data and place all
	 * the payload in page fragments.
	 */
	if (io_len > pgbreak)
		return 0;

	/*
	 * If we will be accumulating payload get a large main body.
	 */
	if (!send_should_push(sk, flags))
		return pgbreak;

	return io_len;
}

static int chelsio_sendpage(struct sock *sk, struct page *page, int offset,
			    size_t size, int flags)
{
	long timeo;
	int mss, err, copied = 0;
	struct cpl_io_state *cplios;
	struct tcp_sock *tp = tcp_sk(sk);

	lock_sock(sk);

	if (sk->sk_prot->sendpage != chelsio_sendpage) {
		release_sock(sk);
		if (sk->sk_prot->sendpage)
			return sk->sk_prot->sendpage(sk, page, offset, size, flags);
		else
			return sk->sk_socket->ops->sendpage(sk->sk_socket, page,
							    offset, size, flags);
	}

	cplios = CPL_IO_STATE(sk);
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for connection establishment to finish. */
	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	    (err = sk_stream_wait_connect(sk, &timeo)) != 0)
		goto out_err;

	if (ma_fail_chelsio_sendpage(sk, timeo))
		return -EAGAIN;

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	mss = cplios->mss;

	cplios_set_flag(cplios, CPLIOS_TX_MORE_DATA);
	while (size > 0) {
		int copy, i;
		struct sk_buff *skb = skb_peek_tail(&cplios->tx_queue);

		if (!skb || (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) ||
		    (copy = mss - skb->len) <= 0) {
new_buf:
			if (!tcp_memory_free(sk))
				goto wait_for_sndbuf;

			if (is_tls_offload(sk) && tls_tx_key(sk)) {
				skb = alloc_tls_tx_skb(sk, select_size(sk,
						       size, flags,
						       TLS_TX_HEADER_LEN),
						       true);
				if (skb)
					ULP_SKB_CB(skb)->ulp.tls.type =
						CONTENT_TYPE_APP_DATA;
			} else {
				skb = alloc_tx_skb(sk, 0);
			}
			if (!skb)
				goto wait_for_memory;

			copy = mss;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		} else {
			tx_skb_finalize(skb);
			push_frames_if_head(sk);
			goto new_buf;
		}

		skb->len += copy;
		if (skb->len == mss)
			tx_skb_finalize(skb);
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		tp->write_seq += copy;
		copied += copy;
		offset += copy;
		size -= copy;

		if (corked(tp, flags) &&
		    (sk_stream_wspace(sk) < sk_stream_min_wspace(sk)))
			ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_NO_APPEND;

		if (!size)
			break;

		if (unlikely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND))
			push_frames_if_head(sk);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if ((err = wait_for_mem(sk, &timeo)) != 0)
			goto do_error;
	}

out:
	cplios_reset_flag(cplios, CPLIOS_TX_MORE_DATA);
	if (copied)
		t4_tcp_push(sk, flags);
done:
	release_sock(sk);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	if (sock_flag(sk, SOCK_OFFLOADED))
		cplios_reset_flag(cplios, CPLIOS_TX_MORE_DATA);
	copied = sk_stream_error(sk, flags, err);
	goto done;
}

/*
 * Add a list of skbs to a socket send queue.  This interface is intended for
 * use by in-kernel ULPs.  The callers must comply with the max size limit of the
 * device and have a headroom of at least TX_HEADER_LEN bytes.
 */
int t4_sendskb(struct sock *sk, struct sk_buff *skb, int flags)
{
	struct sk_buff *next;
	struct cpl_io_state *cplios;
	struct tcp_sock *tp = tcp_sk(sk);
	int err, copied = 0;
	long timeo;
	unsigned int cb_flags;

	lock_sock(sk);
	cplios = CPL_IO_STATE(sk);
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	    (err = sk_stream_wait_connect(sk, &timeo)) != 0)
		goto out_err;

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	/*
	 * We check for send buffer space once for the whole skb list.  It
	 * isn't critical if we end up overrunning the send buffer limit as we
	 * do not allocate any new memory.  The benefit is we don't need to
	 * perform intermediate packet pushes.
	 */
	while (!tcp_memory_free(sk)) {
		sk_set_bit(SOCK_NOSPACE, sk);
		if ((err = wait_for_mem(sk, &timeo)) != 0)
			goto out_err;
	}

	while (skb) {
		cb_flags = ULP_SKB_CB(skb)->flags|ULPCB_FLAG_NO_APPEND;
		/* No WR header for memory write skb */
		if (likely(!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_MEMWRITE))) {
			if (unlikely(skb_headroom(skb) < TX_HEADER_LEN)) {
				err = -EINVAL;
				goto out_err;
			}

			if (unlikely(!skb->len)) {
				err = -EMSGSIZE;
				goto out_err;
			}
			tp->write_seq += skb->len + ulp_extra_len(skb) +
					skb_ulp_len_adjust(skb);

			cb_flags |= ULPCB_FLAG_NEED_HDR;
		}
		next = skb->next;
		skb->next = NULL;
		skb_entail(sk, skb, cb_flags);
		copied += skb->len;
		skb = next;
	}
done:
	if (likely(skb_queue_len(&cplios->tx_queue)))
		t4_push_frames(sk, 1);
	release_sock(sk);
	return copied;

out_err:
	if (copied == 0)
		copied = sk_stream_error(sk, flags, err);
	goto done;
}
EXPORT_SYMBOL(t4_sendskb);

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
/*
 * ZCOPY_SENDMSG maps (if necessary) and pins a user space buffer instead of
 * copying the payload from user- to kernel space. In normal mode of
 * operation, we block until the DMA has completed and it is safe to return
 * (considering that the user might modifies the buffer). Since host bus
 * performance (PCI-E x8 and PCI-X 2.0) now exceeds the wire speed, this
 * actually works pretty well. In addition, I added some tunables to do a
 * hybrid scheme where the end of the user space buffer is copied (at the same
 * the beginning of the buffer is DMAed). The mechanism provides enough
 * pipelinging to achieve 10Gbps linerate on a single connection with moderate
 * CPU utilization.
 *
 * Now, the exception (which as usual makes up for most of the code and 
 * complexity): while unlikely, there are scenarios where we want to return 
 * before the DMA completes (i.e. the DMA might not complete if a connection
 * doesn't drain (somebody unplugged the cable *&%!) or we want to return for 
 * anther reason, i.e. because we got a signal. In that case, we must make 
 * sure that the user doesn't modify the buffer before the DMA has 
 * completed... yes, you guessed correctly, by remapping the buffer as COW and
 * yes, that has some cost associated with it starting with mandatory TLB 
 * flush and potential page fault and buffer copy (what we wanted to avoid).
 * However, it is NOT THE NORMAL case and rare!
 *
 * Written by Felix Marti (felix@chelsio.com)
 */
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/hugetlb.h>

#define ZCOPY_PRT(m)

/*
 * zcopy_to_skb() maps the user space buffer (from) and fills in the skb
 * page descriptors to point to the buffer.
 */

static int t4_zcopy_to_skb(struct sock *sk, struct sk_buff *skb,
			   struct iov_iter *from, size_t copy)
{
	int frag = 0;
	int total = 0;
	unsigned int off;
	unsigned long numpages;
	unsigned long locked;
	unsigned long lock_limit;
	unsigned long startaddr = (unsigned long)from->iov->iov_base +
				  from->iov_offset;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	off = startaddr & (PAGE_SIZE - 1);
	numpages = (copy + off + (PAGE_SIZE - 1)) / PAGE_SIZE;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	if (!capable(CAP_IPC_LOCK)) {
		down_read(&current->mm->mmap_sem);
		lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
		locked = numpages + current->mm->pinned_vm;
		if (locked > lock_limit) {
			up_read(&current->mm->mmap_sem);
			return -ENOMEM;
		}
		up_read(&current->mm->mmap_sem);
	}
#else
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	locked = atomic64_add_return(numpages, &current->mm->pinned_vm);
	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		atomic64_sub(numpages, &current->mm->pinned_vm);
		return -ENOMEM;
	}
#endif

	while (total != copy) {
		struct page *pages[MAX_SKB_FRAGS];
		size_t off;
		ssize_t ret;
		int copied = 0;
		int n = 0;

		if (frag == MAX_SKB_FRAGS) {
			/* come back with new buffer */
			skb_vaddr_set(skb, startaddr);
			return total;
		}

		ret = iov_iter_get_pages(from, pages, copy - total,
					 MAX_SKB_FRAGS - frag, &off);	
		if (ret < 0)
			return -EFAULT;

		while (ret) {
			int size = min_t(int, ret, PAGE_SIZE - off);

			skb_fill_page_desc(skb, frag++, pages[n++], off, size);
			off = 0;
			ret -= size;
			copied += size;
		}
		iov_iter_advance(from, copied);
		skb->len += copied;
		skb->data_len += copied;
		skb->truesize += copied;
		sk->sk_wmem_queued += copied;
		cplios->zcopy_dma_unacked += copied;
		total += copied;
	}
	skb_vaddr_set(skb, startaddr);
	return total;
}

/*
 * If we're on an older kernel, we don't have the pte_offset_map_lock() macro
 * available to prevent race conditions accessing PTEs in an atomic fashion.
 * But on newer kernels, we use that mechanism exclusively and don't take the
 * memory map spin lock ...  This code is modeled on the mprotect() code
 * which does exactly what we want but isn't exported from the kernel.
 */
#if defined(pte_offset_map_lock)

#  define mprotect_page_table_lock(mm) \
	do { } while (0)
#  define mprotect_page_table_unlock(mm) \
	do { } while (0)

#else

#  define mprotect_page_table_lock(mm) \
	do { spin_lock(&(mm)->page_table_lock); } while (0)
#  define mprotect_page_table_unlock(mm) \
	do { spin_unlock(&(mm)->page_table_lock); } while (0)

#  define pte_offset_map_lock(mm, pmd, address, ptl) \
	pte_offset_map(pmd, address)
#  define pte_unmap_unlock(pte, ptl) \
	pte_unmap(pte)

#endif /* !deinfed(pte_offset_map_lock) */

/*
 * We have an skb which has outstanding zero-copy DMA references to user pages
 * but we need to return to the user.  This sometimes happens when an
 * application sets up a timer or the user types a ^C.  Since the DMA hasn't
 * been acknowledged yet, we need to mark all of the pages referenced by the
 * skb as copy-on-write in order to fulfill standard UNIX write() semantics.
 * (I.e. writes to application memory buffers after a write() call returns cannot
 * affect the actual write results.)
 * In the case the VMA is read-only, we don't want to have mapcount decreased
 * later when in ULPCB_FLAG_ZCOPY_COW state so don't transition to that state.
 * Also, zcopy_skb_dma_pending() is called when in ULPCB_FLAG_ZCOPY state
 * at different stages of skb path through TX lists so make sure read-only
 * VMA's only looked at once.
 */
static int zcopy_skb_dma_pending(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct vm_area_struct *vma;
	unsigned int wr_hdr_len = 
	    ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR ? 
	        0 : sizeof (struct fw_ofld_tx_data_wr);
	unsigned int len = skb->len - wr_hdr_len;
	unsigned long address = skb_vaddr(skb);
	unsigned long end = PAGE_ALIGN(address + len);
	int i;

	address &= PAGE_MASK;

	mmap_write_lock(current->mm);
	vma = find_vma(current->mm, skb_vaddr(skb));
	if (!(vma->vm_flags & VM_WRITE)) {
		vma->vm_flags &= ~VM_MAYWRITE;
		mmap_write_unlock(current->mm);
		ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY;
		ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ZCOPY_COW_SKIP;
		cplios->zcopy_dma_unacked -= len;
		return 0;
	}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE)
	/*
	 * If Transparent Huge Pages are configured into the kernel then our
	 * write buffer may overlap one or more THPs.  At the Virtual Memory
	 * Area level these look like "normal" (non-HUGE) VMAs.  But burried
	 * within the PGD/P4D/PUD/PMD structures, we may have THPs and a normal
	 * Copy-On-Write process of marking PTEs won't work.  It is possible
	 * to handle these natively but difficult and any code to do this
	 * would be subject to future architechtural changes in THPs.  So,
	 * instead we do another Get User Pages call with a request to "split"
	 * any THPs which are found into "normal" pages and then we drop the
	 * additional reference counts.
	 */
	if (!is_vm_hugetlb_page(vma)) {
		struct page *pages[MAX_SKB_FRAGS];
		int numpages;
		int locked = 1;

		numpages = t4_get_user_pages_locked_with_flags_nowait(skb_vaddr(skb),
					    skb_shinfo(skb)->nr_frags,
					    FOLL_SPLIT,
					    pages, &locked);
		if (numpages > 0)
			for (i=0; i < numpages; i++)
				put_page(pages[i]);
	}
#endif

	mprotect_page_table_lock(current->mm);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++, address += PAGE_SIZE) { 
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		/* make sure the page doesn't go away */
		atomic_inc(&skb_frag_page(frag)->_mapcount);

		/*
		 * Dive down the PGD/P4D/PUD/PMD/PTE hierarchy for the page and
		 * mark it COW.  When we have a ZERO_PAGE() mapping, some
		 * portions of the hierarchy may be missing.  Since the
		 * ZERO_PAGE() is already COW and can never change, there's
		 * nothing we need to do.
		 */
		if ((pgd = pgd_offset(current->mm, address),
		     !(pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))) &&
		    (p4d = p4d_offset(pgd, address),
		     !(p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))) &&
		    (pud = pud_offset(p4d, address),
		     !(pud_none(*pud) || unlikely(pud_bad(*pud)))) &&
		    (pmd = pmd_offset(pud, address),
		     !(pmd_none(*pmd) || unlikely(pmd_bad(*pmd))))) {
			spinlock_t *ptl __attribute__((unused));
			pte_t *pte = t4_pte_offset_map_lock(current->mm, pmd,
							 address, &ptl);
			if (pte != NULL) {
#if defined(CONFIG_ARM64)
				BUG_ON(t4_pte_exec(*pte));
#endif
				if (pte_present(*pte))
					t4_ptep_set_wrprotect(current->mm,
							      address, pte);
			}
			pte_unmap_unlock(pte, ptl);
		}
	}
	mprotect_page_table_unlock(current->mm);

	t4_flush_tlb_range(vma, skb_vaddr(skb), end);
	mmap_write_unlock(current->mm);

	ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY;
	ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ZCOPY_COW;
	cplios->zcopy_dma_unacked -= len;
#ifdef T4_TRACE
	T4_TRACE5(TIDTB(sk),
		  "zcopy_skb_dma_pending: address 0x%lx len %u mm %p "
		  "mm_count %d need_hdr %d", 
		  address, len, current->mm, 
		  atomic_read(&current->mm->mm_count),
		  ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR);
#endif

	return 0;
}

static void zcopy_skb_dma_complete(struct sock *sk, struct sk_buff *skb)
{
	int i;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		atomic_dec(&skb_frag_page(frag)->_mapcount);
	}

	ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY_COW;
}

static int zcopy_dma_pending(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	int ret = 0;

	wr_queue_walk(sk, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
			ret = zcopy_skb_dma_pending(sk, skb);
			if (ret)
				return ret;
		}
	}

	skb_queue_walk(&cplios->tx_queue, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
			ret = zcopy_skb_dma_pending(sk, skb);
			if (ret)
				return ret;
		}
	}

	return 0;
}

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
/*
 * Clean up any residual state for Zero-Copy TX Data skb's.
 */
void t4_zcopy_cleanup_skb(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int hdr_len = 0;

	/*
	 * If ULPCB_FLAG_NEED_HDR isn't set, then we've gone through
	 * t4_push_frames() and incremented tx_dma_pending (because Zero-Copy
	 * skb's always start out with { ULPCB_FLAG_NEED_HDR,
	 * ULPCB_FLAG_COMPL, ULPCB_FLAG_ZCOPY } and ULPCB_FLAG_NEED_HDR is
	 * only removed in t4_push_frames() when ULPCB_FLAG_COMPL is set.
	 * This is fragile logic so it must only be changed with care.
	 */
	if (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR)) {
		hdr_len = sizeof (struct fw_ofld_tx_data_wr);
	}

	/*
	 * If ULPCB_FLAG_ZCOPY is set, then either the skb is still on the
	 * Socket Write Queue or the Hardware TX Data Work Request Write Queue
	 * and we've charged it's potential or outstanding DMA to
	 * zcopy_dma_unacked.
	 *
	 * If ULPCB_FLAG_ZCOPY_COW is set, then we've marked all the user
	 * pages backing the skb as Copy On Write and allowed an early return
	 * to the user application.  In this case, the skb was on the Hardware
	 * TX Data Work Request Write Queue and we must have received a Write
	 * Acknowlegement from the hardware for this skb's TX Data Work
	 * Request.
	 */
	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
		ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY;
		cplios->zcopy_dma_unacked -= (skb->len - hdr_len);
		if (!cplios->zcopy_dma_unacked) {
			if (likely(!sock_flag(sk, SOCK_DEAD)))
				__wake_up(sk_sleep(sk), TASK_INTERRUPTIBLE, 0, NULL);
		}
	} else if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY_COW)
		zcopy_skb_dma_complete(sk, skb);

	skb_vaddr_set(skb, 0);
}
#endif

static void zcopy_wait(struct sock *sk, long timeout, int ret_pending)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	DEFINE_WAIT(wait);

	timeout = max_t(long, HZ / 2, timeout);
	while (cplios->zcopy_dma_unacked &&
	       !(sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))) {
		if (ret_pending) {
			if (signal_pending(current) || !timeout) {
#ifdef T4_TRACE
				T4_TRACE4(TIDTB(sk), "zcopy_wait: sk_err %d "
					  "signal_pending 0x%x timeout %ld "
					  "zcopy_dma_unacked %d", sk->sk_err, 
					  signal_pending(current), timeout,
					  cplios->zcopy_dma_unacked);
#endif
				if (!zcopy_dma_pending(sk)) {
					BUG_ON(cplios->zcopy_dma_unacked);
					break;
				}
			}
		} else if (!timeout)
			timeout = HZ / 2;
#ifdef T4_TRACE
		T4_TRACE1(TIDTB(sk), "zcopy_wait: GTS zcopy_dma_unacked %d",
			  cplios->zcopy_dma_unacked);
#endif
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		release_sock(sk);
		timeout = schedule_timeout(timeout);
		lock_sock(sk);
	}
	if (sk->sk_err == ECONNRESET) {
		if (cplios->zcopy_dma_unacked) {
			if (!zcopy_dma_pending(sk))
				BUG_ON(cplios->zcopy_dma_unacked);
		}
	}
	finish_wait(sk_sleep(sk), &wait);
}
#endif


static inline int t4_skb_copy_to_page_nocache(struct sock *sk,
					      struct iov_iter *from,
					      struct sk_buff *skb,
					      struct page *page,
					      int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
					copy, skb->len);
	if (err)
		return err;

	skb->len             += copy;
	skb->data_len        += copy;
	skb->truesize        += copy;
	sk->sk_wmem_queued   += copy;
	return 0;
}

static int chelsio_sendmsg(struct sock *sk,
			   struct msghdr *msg, size_t size)
{
	struct cpl_io_state *cplios;
	long timeo;
	struct sk_buff *skb = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *tdev = NULL;
	int mss, flags, err;
	int copied = 0;
	struct tom_data *d;
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	int zcopy_size = 0;
	int zcopied = 0;
	int partial_thres;
#endif
	int tls_size = 0;
	struct tls_ofld_info *tls_ofld = NULL;

	lock_sock(sk);
	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err)
			goto out_err;
	}
	/*
	 * Offloaded active opens can fail and revert back to the stack.
	 * Yet the offloaded ops have already been made visible to applications
	 * meaning they could well be executing after the transition back to
	 * the stack.  That has unfortunate consequences.  If we find ourselves
	 * in an offloaded op that could have started in SYN_SENT we need to
	 * check if we should still be in there.
	 */
	if (sk->sk_prot->sendmsg != chelsio_sendmsg) {
		release_sock(sk);
		if (sk->sk_prot->sendmsg)
			return sk->sk_prot->sendmsg(sk, msg, size);
		else
			return sk->sk_socket->ops->sendmsg(sk->sk_socket,
								msg, size);
	}
	if (ma_fail_chelsio_sendmsg(sk, timeo))
		return -EAGAIN;
	cplios = CPL_IO_STATE(sk);
	tdev = cplios->toedev;

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	mss = cplios->mss;
	d = TOM_DATA(tdev);
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	partial_thres = (cplios->port_speed > SPEED_10000) ?
			TOM_TUNABLE(tdev, zcopy_sendmsg_partial_xlthres) :
			TOM_TUNABLE(tdev, zcopy_sendmsg_partial_thres);

	if (size >= partial_thres
	    && !(msg->msg_iter.nr_segs > 1)
	    && !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN)
	    && !corked(tp, flags)
	    && can_do_mlock()
	    && !uaccess_kernel()
	    && !is_tls_offload(sk))
		zcopy_size = size -
				TOM_TUNABLE(tdev, zcopy_sendmsg_partial_copy);

	/* In the case of NON-BLOCKING IO we don't want to exceed the
	 * sendbuffer at all which could cause delays in the zcopy path
	 */
	if ((zcopy_size > 0) && (flags & MSG_DONTWAIT)) {
		int rem = sk->sk_sndbuf - sk->sk_wmem_queued;

		if (rem <= 0) {
			err = -EAGAIN;
			goto do_error;
		} else if (size > rem)
			size = rem;
	}

	/* If any of the pages are problematic or if the address range crosses
	 * a VMA boundary or if base address of any iovec falls in the vm area
	 * with VM_EXEC or VM_SHARED flags set, despite the fact that vm_flags
	 * may vary between the iovec's in the message,we just reject the zero
	 * copy effort.
	 */
	if (zcopy_size) {
		int iovlen;
		const struct iovec *iov;
		struct vm_area_struct *vma;

		mmap_read_lock(current->mm);
		for (iovlen = msg->msg_iter.nr_segs, iov = msg->msg_iter.iov;
		     iovlen--; iov++) {
			unsigned long from = (unsigned long)iov->iov_base;

			vma = find_vma(current->mm, from);
			if (!vma || (vma->vm_start > from)
			    || (vma->vm_end < from + size)
			    || !zcopy_vma(vma)) {
				zcopy_size = 0;
				break;
			}
		}
		mmap_read_unlock(current->mm);
	}
#endif
	cplios_set_flag(cplios, CPLIOS_TX_MORE_DATA);

	while (msg_data_left(msg)) {
		int copy = 0;

		skb = skb_peek_tail(&cplios->tx_queue);
		if (skb) {
			copy = mss - skb->len;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
		/*
		 * Inline TLS, strip 5B header when tx is encrypted by HW.
		 */
		if (is_tls_offload(sk) && tls_tx_key(sk))
			tls_ofld = TLS_IO_STATE(sk);

		if (tls_ofld && !tls_ofld->sd.left) {
			struct tls_hdr thdr;

			tls_ofld = TLS_IO_STATE(sk);
			tls_size = tls_header_read(&thdr, &msg->msg_iter);
			size -= TLS_HEADER_LENGTH;
			tls_ofld->sd.left = tls_size;
			tls_ofld->sd.type = thdr.type;
			copied += TLS_HEADER_LENGTH;
			if (thdr.type != CONTENT_TYPE_APP_DATA) {
				t4_push_frames(sk, 0);
				copy = 0;
			}
		}


		if (!skb
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
		    || zcopy_size > 0
#endif
		    || (skb && ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND)
		    || copy <= 0) {
new_buf:
			if (skb) {
				tx_skb_finalize(skb);
				push_frames_if_head(sk);
			}
			if (!tcp_memory_free(sk))
				goto wait_for_sndbuf;

			if (is_tls_offload(sk) && tls_tx_key(sk)) {
				skb = alloc_tls_tx_skb(
						sk, select_size(sk, tls_size,
						flags, TLS_TX_HEADER_LEN),
						false);
			} else {
				skb = alloc_tx_skb(
						sk, select_size(sk, size, flags,
						TX_HEADER_LEN));
			}
			if (unlikely(!skb))
				goto wait_for_memory;

			skb->ip_summed = CHECKSUM_UNNECESSARY;
			copy = mss;
		}

		if (copy > size)
			copy = size;
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
		if (zcopy_size > 0) {
			copy = min_t(int, copy, zcopy_size);
			if (is_tls_offload(sk) && tls_tx_key(sk))
				copy = min_t(int, copy, tls_ofld->sd.left);

			copy = t4_zcopy_to_skb(sk, skb, &msg->msg_iter, copy);

			if (copy < 0) {
				if (err == -EFAULT)
					goto do_fault;

				zcopy_size = 0;
				continue;
			}
			copied += copy;
			zcopied += copy;
			size -= copy;
			zcopy_size -= copy;
			/* Decrement tls data copied */
			if (is_tls_offload(sk) && tls_tx_key(sk))
				tls_ofld->sd.left -= copy;

			tx_skb_finalize(skb);
			ULP_SKB_CB(skb)->flags = ULP_SKB_CB(skb)->flags
						| ULPCB_FLAG_COMPL
						| ULPCB_FLAG_ZCOPY;
			if (!size) {
				cplios_reset_flag(cplios, CPLIOS_TX_MORE_DATA);
				t4_push_frames(sk, 1);
				goto done;
			} else {
				t4_push_frames(sk, 1);
				continue;
			}
		}
#endif

		if (skb_tailroom(skb) > 0) {
			copy = min(copy, skb_tailroom(skb));
			if (is_tls_offload(sk) && tls_tx_key(sk))
				copy = min_t(int, copy, tls_ofld->sd.left);
	  
			err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
									copy);
			if (err)
				goto do_fault;
		} else {
			bool merge;
			int off = TCP_OFF(sk);
			int i = skb_shinfo(skb)->nr_frags;
			struct page *page = TCP_PAGE(sk);
			int pg_size = PAGE_SIZE;

			if (page)
				pg_size <<= compound_order(page);

			if (off < pg_size &&
			    skb_can_coalesce(skb, i, page, off)) {
				merge = 1;
				goto copy;
			}
			merge = 0;
			/* IV DSGL as last entry in skb frags. Prefer
			 * to send single PDU for fast path, can also be
			 * ensured by setting frag size MSS */
			if (i == (is_tls_offload(sk) ? (MAX_SKB_FRAGS - 1) :
				  MAX_SKB_FRAGS))
				goto new_buf;
			if (page && off == pg_size) {
				put_page(page);
				TCP_PAGE(sk) = page = NULL;
				pg_size = PAGE_SIZE;
			}

			if (!page) {
				gfp_t gfp = sk->sk_allocation;
				int order = d->send_page_order;

				if (order) {
					page = alloc_pages(
							gfp|
							__GFP_COMP|
							__GFP_NOWARN|
							__GFP_NORETRY,
							order);
					if (page)
						pg_size <<=
							compound_order(page);
				}
				if (!page) {
					page = alloc_page(gfp);
					pg_size = PAGE_SIZE;
				}
				if (!page)
					goto wait_for_memory;
				off = 0;
			}
copy:
			if (copy > pg_size - off)
				copy = pg_size - off;
			if (is_tls_offload(sk) && tls_tx_key(sk))
				copy = min_t(int, copy, tls_ofld->sd.left);

			err = t4_skb_copy_to_page_nocache(sk, &msg->msg_iter,
							  skb, page, off, copy);
			if (unlikely(err)) {
				/*
				 * If the page was new, give it to the
				 * socket so it does not get leaked.
				 */
				if (!TCP_PAGE(sk)) {
					TCP_PAGE(sk) = page;
					TCP_OFF(sk) = 0;
				}
				goto do_fault;
			}

			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1],
						 copy);
			} else {
				skb_fill_page_desc(skb, i, page, off, copy);
				if (off + copy < pg_size) {
					/* space left keep page */
					get_page(page);
					TCP_PAGE(sk) = page;
				} else {
					TCP_PAGE(sk) = NULL;
				}
			}
			TCP_OFF(sk) = off + copy;
		}

		if (unlikely(skb->len == mss))
			tx_skb_finalize(skb);
		tp->write_seq += copy;
		copied += copy;
		size -= copy;

		/* decrement tls data copied */
		if (is_tls_offload(sk) && tls_tx_key(sk))
			tls_ofld->sd.left -= copy;

		if (corked(tp, flags) &&
		   (sk_stream_wspace(sk) < sk_stream_min_wspace(sk)))
			ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_NO_APPEND;

		if (size == 0)
			goto out;

		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND)
			push_frames_if_head(sk);
		continue;
wait_for_sndbuf:
		sk_set_bit(SOCK_NOSPACE, sk);
wait_for_memory:
		err = wait_for_mem(sk, &timeo);
		if (err)
			goto do_error;
	}
out:
	cplios_reset_flag(cplios, CPLIOS_TX_MORE_DATA);
	if (copied)
		t4_tcp_push(sk, flags);
done:
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	if (zcopied > 0 && tdev)
		zcopy_wait(sk, timeo,
			   TOM_TUNABLE(tdev, zcopy_sendmsg_ret_pending_dma));
#endif
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		__skb_unlink(skb, &cplios->tx_queue);
		sk->sk_wmem_queued -= skb->truesize;
		__kfree_skb(skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	if (sock_flag(sk, SOCK_OFFLOADED))
		cplios_reset_flag(CPL_IO_STATE(sk), CPLIOS_TX_MORE_DATA);
	copied = sk_stream_error(sk, flags, err);
	goto done;
}


static inline int is_delack_mode_valid(struct toedev *dev, struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	return cplios->ulp_mode == ULP_MODE_NONE ||
		(cplios->ulp_mode == ULP_MODE_TCPDDP &&
		 dev->ttid >= TOE_ID_CHELSIO_T4);
}

/*
 * Set of states for which we should return RX credits.
 */
#define CREDIT_RETURN_STATE (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2)

/*
 * Called after some received data has been read.  It returns RX credits
 * to the HW for the amount of data processed.
 */
void t4_cleanup_rbuf(struct sock *sk, int copied)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp;
	struct toedev *dev;
	int dack_mode, must_send;
	u32 thres, credits, dack = 0;

	if (!sk_in_state(sk, CREDIT_RETURN_STATE))
		return;

	t4_select_window(sk);	
	tp = tcp_sk(sk);
	credits = tp->copied_seq - tp->rcv_wup;
	if (unlikely(!credits))
		return;

	dev = cplios->toedev;
	thres = TOM_TUNABLE(dev, rx_credit_thres);

	if (unlikely(thres == 0))
		return;
		
	if (is_delack_mode_valid(dev, sk)) {
		dack_mode = t4_select_delack(sk);
		if (unlikely(dack_mode != cplios->delack_mode)) {
			u32 r = tp->rcv_nxt - cplios->delack_seq;
			if (r >= tp->rcv_wnd || r >= 16 * MSS_CLAMP(tp))
				dack = F_RX_DACK_CHANGE |
				       V_RX_DACK_MODE(dack_mode);
		}
	} else
		dack = F_RX_DACK_CHANGE | V_RX_DACK_MODE(1);


	/*
	 * For coalescing to work effectively ensure the receive window has
	 * at least 16KB left. Can ignore check for TLS as no coalescing.
	 */
	must_send = credits + 16384 >= tp->rcv_wnd;

	if (must_send || credits >= thres)
		tp->rcv_wup += t4_send_rx_credits(sk, credits, dack, must_send);
}
EXPORT_SYMBOL(t4_cleanup_rbuf);

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		u32 offset = seq - ULP_SKB_CB(skb)->seq;
		if (offset < skb->len) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

static inline int ddp_rcv_coalesce_enabled(struct cpl_io_state *cplios,
					   int last_recv_len)
{
	struct toedev *tdev = cplios->toedev;
	int should_ddp;

	switch (cplios->port_speed) {
	case 100:
	case 1000:
		should_ddp =
			last_recv_len >
				min((int)DEFAULT_RCV_COALESCE_SIZE-1,
					 TOM_TUNABLE(tdev, ddp_thres));
		break;
	case 10000:
	case 25000:
		should_ddp = last_recv_len > TOM_TUNABLE(tdev, ddp_thres);
		break;
	default:
		should_ddp = last_recv_len > TOM_TUNABLE(tdev, ddp_xlthres);
		break;
	}
	return should_ddp;
}

/*
 * Returns whether a connection should enable DDP.  This happens when all of
 * the following conditions are met:
 * - the connection's ULP mode is DDP
 * - DDP is not already enabled
 * - the last receive was above the DDP threshold
 * - receive buffers are in user space
 * - receive side isn't shutdown (handled by caller)
 * - the connection's receive window is big enough so that sizable buffers
 *   can be posted without closing the window in the middle of DDP (checked
 *   when the connection is offloaded)
 */
static int sk_should_ddp(const struct sock *sk, const struct tcp_sock *tp,
			 int last_recv_len)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *d = TOM_DATA(tdev);
	unsigned int wsf;
	int should_ddp = cplios->ulp_mode == ULP_MODE_TCPDDP &&
			!DDP_STATE(sk)->ddp_setup &&
			((can_do_mlock() && !uaccess_kernel()) ||
			TOM_TUNABLE(tdev, kseg_ddp));

	if (cplios->opt2 & V_RX_COALESCE(M_RX_COALESCE))
		should_ddp = should_ddp &&
				ddp_rcv_coalesce_enabled(cplios, last_recv_len);
	
	if (!should_ddp)
		return 0;

	/* d->lldi->sge_ingpadboundary refers to minimum indicate size */
	wsf = cplios->port_speed ? DIV_ROUND_UP(cplios->port_speed, SPEED_10000) : 1;
	if (tcp_sk(sk)->rcv_wnd < (d->lldi->sge_ingpadboundary + wsf*DDP_RSVD_WIN))
		return 0;

	return !bitmap_full(d->ppod_bmap, d->nppods);
}

static inline int is_ddp(const struct sk_buff *skb)
{
	return skb_gl(skb) != NULL;
}

static inline int is_ddp_psh(const struct sk_buff *skb)
{
        return is_ddp(skb) && (skb_ulp_ddp_flags(skb) & DDP_BF_PSH);
}

/*
 * Copy data from an sk_buff to an iovec.  Deals with RX_DATA, which carry the
 * data in the sk_buff body, and with RX_DATA_DDP, which place the data in a
 * DDP buffer.
 */
static inline int copy_data(const struct sk_buff *skb, int offset,
			    struct msghdr *msg, int len)
{
	if (likely(!is_ddp(skb)))                             /* RX_DATA */
		return skb_copy_datagram_msg(skb, offset, msg, len);
	else if (likely(skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY)) { /* user DDP */
		iov_iter_advance(&msg->msg_iter, len);
		return 0;
	}
	return -EINVAL;
}

/*
 * Peek at data in a socket's receive buffer.
 */
static int peekmsg(struct sock *sk, struct msghdr *msg,
		   size_t len, int nonblock, int flags)
{
	long timeo;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq, offset;
	size_t avail;          /* amount of available data in current skb */

	lock_sock(sk);
	timeo = sock_rcvtimeo(sk, nonblock);
	peek_seq = tp->copied_seq;

	do {
		if (unlikely(tp->urg_data && tp->urg_seq == peek_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
						 -EAGAIN;
				break;
			}
		}

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			offset = peek_seq - ULP_SKB_CB(skb)->seq;
			if (offset < skb->len)
				goto found_ok_skb;
		}

		/* empty receive queue */
		if (copied)
			break;
		if (sock_flag(sk, SOCK_DONE))
			break;
		if (sk->sk_err) {
			copied = sock_error(sk);
			break;
		}
		if (sk_no_receive(sk))
			break;
		if (sk->sk_state == TCP_CLOSE) {
			copied = -ENOTCONN;
			break;
		}
		if (!timeo) {
			copied = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			copied = sock_intr_errno(timeo);
			break;
		}

		if (sk->sk_backlog.tail) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			sk_wait_data(sk, &timeo);

		if (unlikely(peek_seq != tp->copied_seq)) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application "
				       "bug, race in MSG_PEEK.\n",
				       current->comm, current->pid);
			peek_seq = tp->copied_seq;
		}
		continue;

found_ok_skb:
		avail = skb->len - offset;
		if (len < avail)
			avail = len;

		/*
		 * Do we have urgent data here?  We need to skip over the
		 * urgent byte.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - peek_seq;

			if (urg_offset < avail) {
				/*
				 * The amount of data we are preparing to copy
				 * contains urgent data.
				 */
				if (!urg_offset) { /* First byte is urgent */
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						peek_seq++;
						offset++;
						avail--;
						if (!avail)
							continue;
					}
				} else {
					/* stop short of the urgent data */
					avail = urg_offset;
				}
			}
		}

		/*
		 * If MSG_TRUNC is specified the data is discarded.
		 */
		if (likely(!(flags & MSG_TRUNC)))
			if (copy_data(skb, offset, msg, avail)) {
				if (!copied)
					copied = -EFAULT;
				break;
			}
		peek_seq += avail;
		copied += avail;
		len -= avail;
	} while (len > 0);

	release_sock(sk);
	return copied;
}

static int sk_wait_data_uninterruptible(struct sock *sk)
{
	int rc;
	long timeo = MAX_SCHEDULE_TIMEOUT;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_UNINTERRUPTIBLE);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, &timeo,
			   !skb_queue_empty(&sk->sk_receive_queue), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

/*
 * Called after a user buffer is posted to await DDP completion.  The waiting
 * mode depends on the receive flags, which in turn determine the HW DDP flags.
 *
 * - Without MSG_WAITALL we set up the DDP buffer with non-zero initial offset
 *   and enable the HW timeout.  In this case we sleep uninterruptably since we
 *   know the buffer will complete or timeout in reasonable time.
 * - With MSG_WAITALL HW timeout is initially disabled.  If a signal arrives
 *   and the DDP is still on-going we turn on the timer and disable
 *   no-invalidate, then sleep uninterruptably until the buffer completes.
 */
static inline int await_ddp_completion(struct sock *sk, int rcv_flags,
				       long *timeo)
{
	if (unlikely(rcv_flags & MSG_WAITALL)) {
		sk_wait_data(sk, timeo);
		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    sk_no_receive(sk))
			return 0;

		/* Got signal or timed out */
		t4_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS,
				 V_TF_DDP_PSH_NO_INVALIDATE1(1ULL) |
				 V_TF_DDP_PUSH_DISABLE_1(1ULL), 0);
	}
	return sk_wait_data_uninterruptible(sk);
}

#if defined(CONFIG_CHELSIO_IO_SPIN)
/*
 * Return nanosecond "cycle counter".  This is used to time short intervals
 * via simple unsigned integer subtraction.  E.g. (t1 - t0) < interval.
 */
static inline unsigned long long get_ns_cycles(void)
{
	return (unsigned long long)ktime_to_ns(ktime_get());
}
#endif

/*
 * Receive data from a socket into an application buffer.
 */
static int chelsio_recvmsg(struct sock *sk,
			   struct msghdr *msg, size_t len, int nonblock,
			   int flags, int *addr_len)
{
	struct cpl_io_state *cplios;
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0, buffers_freed = 0;
	unsigned long avail;	/* amount of available data in current skb */
	int target;		/* Read at least this many bytes */
	int request;
	long timeo;
	int user_ddp_ok, user_ddp_pending = 0;
	struct ddp_state *p;

#if defined(CONFIG_CHELSIO_IO_SPIN)
	/*
	 * Initialize I/O spin state variables.  (We need to initialize
	 * spin_ns; the others are to avoid annoying compiler warnings.)
	 */
	unsigned int spin_us = 0;
	unsigned long long spin_ns = 0;
	unsigned long long spin_start = 0;
#endif

	/* Urgent data is handled by the SW stack's receive */
	if (unlikely(flags & MSG_OOB))
		return tcp_prot.recvmsg(sk, msg, len, nonblock, flags,
					addr_len);

	if (unlikely(flags & MSG_PEEK))
		return peekmsg(sk, msg, len, nonblock, flags);

	if (tom_sk_can_busy_loop(sk) && skb_queue_empty(&sk->sk_receive_queue) &&
	    (sk->sk_state == TCP_ESTABLISHED))
		tom_sk_busy_loop(sk, nonblock);

	lock_sock(sk);

	if (sk->sk_prot->recvmsg != chelsio_recvmsg) {
		release_sock(sk);
		return sk->sk_prot->recvmsg(sk, msg, len, nonblock,
						flags, addr_len);
	}

	cplios = CPL_IO_STATE(sk);

	if (is_tls_offload(sk) && tls_rx_key(sk))
		return chelsio_tlsv4_recvmsg(sk, msg, len, nonblock, flags,
					     addr_len);

	timeo = sock_rcvtimeo(sk, nonblock);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	request = len;
	user_ddp_ok = (target <= iov_iter_single_seg_count(&msg->msg_iter)) &&
			!((flags & MSG_WAITALL) && (msg->msg_iter.nr_segs > 1));

	p = DDP_STATE(sk);

	/*
	 * Check to see if we need to grow receive window.
	 */
	if (unlikely (cplios_flag(sk , CPLIOS_UPDATE_RCV_WND)))
		t4_cleanup_rbuf(sk, copied);

	if (p->ddp_setup)
		p->cancel_ubuf = 0;
	
#if defined(CONFIG_CHELSIO_IO_SPIN)
	/*
	 * If the administrator has selected to have us spin for recvmsg()
	 * I/O, setup our I/O spin state variables.  Rather than immediately
	 * going to sleep waiting for ingress data when none is available, we
	 * keep spinning for the specified time interval (specified in
	 * microseconds) before giving up and sleeping waiting for new ingress
	 * data.  For latency-sensitive applications this can be a big win
	 * (even though it does waste CPU).
	 *
	 * Note that we can actually be called with the socket in closing
	 * state and with our offload resources released (including our TOE
	 * Device).  So we need to be paranoid here.
	 */
	if (cplios->toedev != NULL) {
		spin_us = TOM_TUNABLE(cplios->toedev, recvmsg_spin_us);
		if (spin_us) {
			spin_ns = (unsigned long long)spin_us * 1000;
			spin_start = get_ns_cycles();
		}
	}
#endif

	do {
		struct sk_buff *skb;
		u32 offset;

		p = DDP_STATE(sk);
again:

		if (unlikely(tp->urg_data && tp->urg_seq == tp->copied_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
						 -EAGAIN;
				break;
			}
		}
 
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb)
			goto found_ok_skb;

		/*
		 * The receive queue is empty and here we are asking for more
		 * data.  Before we do anything else, check to see if we have
		 * data queued up to send and if there's available write
		 * space.  If so, push it along and free up the write space.
		 * This is a major win for request-response style
		 * communication patterns and doesn't hurt bulk data
		 * applications.
		 */
		if (cplios->wr_credits &&
		    skb_queue_len(&cplios->tx_queue) &&
		    t4_push_frames(sk, cplios->wr_credits == cplios->wr_max_credits))
			sk->sk_write_space(sk);

		if (copied >= target && !sk->sk_backlog.tail &&
		    !user_ddp_pending)
			break;

		if (copied) {
#ifdef T4_TRACE
			T4_TRACE5(TIDTB(sk), 
				  "chelsio_recvmsg: copied - break %d %d %d %d %d",
				  sk->sk_err, sk->sk_state == TCP_CLOSE,
				  sk_no_receive(sk), !timeo,
				  signal_pending(current));
#endif
		
			if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
			    sk_no_receive(sk) ||
			    signal_pending(current))
				break;

			if (!timeo) {
				if (!sk->sk_backlog.tail && user_ddp_pending && t4_ddp_ubuf_pending(sk)) {
					long mintimeo = TOM_TUNABLE(cplios->toedev, recvmsg_ddp_wait_us);

					if (mintimeo > 0) {
						mintimeo = usecs_to_jiffies(mintimeo);
						sk_wait_data(sk, &mintimeo);
					}
				}
				break;
			}

		} else {
#ifdef T4_TRACE
			T4_TRACE5(TIDTB(sk), 
				  "chelsio_recvmsg: !copied - break %d %d %d %d %d",
				  sock_flag(sk, SOCK_DONE), sk->sk_err,
				  sk_no_receive(sk), 
				  sk->sk_state == TCP_CLOSE, !timeo);
#endif
		
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}
			if (sk_no_receive(sk))
				break;
			if (sk->sk_state == TCP_CLOSE) {
				copied = -ENOTCONN; /* SOCK_DONE is off here */
				break;
			}
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		if (sk->sk_backlog.tail && !user_ddp_pending) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
			t4_cleanup_rbuf(sk, copied);
			continue;
		}

		if (user_ddp_pending) {
			/* One shot at DDP if we already have enough data */
			if (copied >= target) {
				user_ddp_ok = 0;
			}
#ifdef T4_TRACE
			T4_TRACE0(TIDTB(sk), "chelsio_recvmsg: AWAIT");
#endif
			sk_wait_data(sk, &timeo);

			if (t4_ddp_cancel_push_disable(sk, !!(flags & MSG_WAITALL))) {
				t4_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS,
					V_TF_DDP_PSHF_ENABLE_1(1ULL) |
					V_TF_DDP_PSH_NO_INVALIDATE1(1ULL) |
					V_TF_DDP_PUSH_DISABLE_1(1ULL),
					V_TF_DDP_PSHF_ENABLE_1(1ULL));
			}
#ifdef T4_TRACE
			T4_TRACE0(TIDTB(sk), "chelsio_recvmsg: AWAITed");
#endif
		} else if (copied >= target)
			break;
		else {
			t4_cleanup_rbuf(sk, copied);

		if ((flags & MSG_WAITALL) && p->ddp_setup &&
		     t4_ddp_indicate_ok(p)) {
			if ((iov_iter_single_seg_count(&msg->msg_iter) <=
			     p->ind_size) || !user_ddp_ok) {
					p->indicate = tcp_sk(sk)->rcv_nxt;
					t4_setup_indicate_modrx(sk);
					p->indout_count++;
				} else if (user_ddp_ok) {
					p->ubuf_ddp_pending =
					   user_ddp_pending =
					   !t4_post_ubuf(sk, msg,
							 nonblock, flags);
					if (!p->ubuf_ddp_pending) {
						p->post_failed++;
						if (p->post_failed >=
						    TOM_TUNABLE(cplios->toedev, ddp_maxfail))
							t4_shutdown_ddp(sk);
					}

				}
			}

#if defined(CONFIG_CHELSIO_IO_SPIN)
			/*
			 * If we're configured for spinning a bit before
			 * giving up and going to sleep to wait for ingress
			 * data, just retry to see if any data has arrived ...
			 */
			if (spin_ns &&
			    get_ns_cycles() - spin_start < spin_ns) {
				release_sock(sk);
				lock_sock(sk);
				continue;
			}
#endif

			sk_wait_data(sk, &timeo);

#if defined(CONFIG_CHELSIO_IO_SPIN)
			/*
			 * If we're configured to spin a bit and the caller
			 * has indicated that it wants to get all of the
			 * requested data length, then set up our I/O spin
			 * state to spin again.  Otherwise, turn off I/O
			 * spinning because the only reason we're back is
			 * because there's more data or we timed out.  (Mostly
			 * this just saves the call to get_ns_cycles().)
			 */
			if (spin_ns) {
				if (flags & MSG_WAITALL)
					spin_start = get_ns_cycles();
				else
					spin_ns = 0;
			}
#endif

#ifdef T4_TRACE
			T4_TRACE0(TIDTB(sk), "chelsio_recvmsg: DATA AWAITed");
#endif
			if (t4_ddp_cancel_push_disable(sk, !!(flags & MSG_WAITALL))) {
				t4_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS,
					V_TF_DDP_PSHF_ENABLE_1(1ULL) |
					V_TF_DDP_PSH_NO_INVALIDATE1(1ULL) |
					V_TF_DDP_PUSH_DISABLE_1(1ULL),
					V_TF_DDP_PSHF_ENABLE_1(1ULL));
			}
		}
		continue;

found_ok_skb:
		if (!skb->len) {		/* ubuf dma is complete */
#ifdef T4_TRACE
			T4_TRACE1(TIDTB(sk),
			    "chelsio_recvmsg: zero len skb flags 0x%x",
			    skb_ulp_ddp_flags(skb));
#endif
			BUG_ON(!(skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY));

			user_ddp_pending = 0;
			tom_eat_ddp_skb(sk, skb);

			if (!copied && !timeo) {
				copied = -EAGAIN;
				break;
			}

			if (copied < target)
				continue;

			break;
		}

		offset = tp->copied_seq - ULP_SKB_CB(skb)->seq;
		if (offset >= skb->len) {
#ifdef T4_TRACE
			T4_TRACE3(TIDTB(sk),
				  "chelsio_recvmsg: BUG: OFFSET > LEN"
				  " seq 0x%x skb->len %dflags 0x%x",
				  ULP_SKB_CB(skb)->seq, skb->len, 
				  ULP_SKB_CB(skb)->flags);
#endif
			printk("chelsio_recvmsg: BUG: OFFSET > LEN seq %#x "
			       "skb->len %d copied %#x flags %#x",
			       ULP_SKB_CB(skb)->seq, skb->len, 
			       tp->copied_seq, ULP_SKB_CB(skb)->flags);
			BUG_ON(1);
		}
		avail = skb->len - offset;
		if (len < avail) {
			if (is_ddp(skb) &&  (skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY)) {
#ifdef T4_TRACE
				T4_TRACE5(TIDTB(sk),
					  "chelsio_recvmsg: BUG: len < avail"
					  " len %u skb->len %d offset %d"
					  " flags 0x%x avail %u",
					  len, skb->len, offset,
					  skb_ulp_ddp_flags(skb), avail);
#endif
			};
			avail = len;
		}
#ifdef T4_TRACE
		T4_TRACE5(TIDTB(sk),
			  "chelsio_recvmsg: seq 0x%x skb->len %d offset %d"
			  " avail %d flags 0x%x",
			  ULP_SKB_CB(skb)->seq, skb->len, offset, avail, 
			  ULP_SKB_CB(skb)->flags);
#endif

		/*
		 * Check if the data we are preparing to copy contains urgent
		 * data.  Either stop short of urgent data or skip it if it's
		 * first and we are not delivering urgent data inline.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;

			if (urg_offset < avail) {
				if (urg_offset) {
					/* stop short of the urgent data */
					avail = urg_offset;
				} else if (!sock_flag(sk, SOCK_URGINLINE)) {
					/* First byte is urgent, skip */
					tp->copied_seq++;
					offset++;
					avail--;
					if (!avail)
						goto skip_copy;
				}
			}
		}

                if (p->ddp_setup && !is_ddp(skb) && !p->ddp_off &&
		    (ULP_SKB_CB(skb)->seq == p->indicate)) {
                        p->indicate = 0;
			if (skb_copy_datagram_msg(skb, offset, msg, avail)) {
				if (!copied) {
					copied = -EFAULT;
					break;
				}
                        }
			if (ULP_SKB_CB(skb)->psh && !(flags & MSG_WAITALL))
				user_ddp_ok = 0;

                	if (likely(!sk_no_receive(sk))) {
				unsigned int iov_seg_len =
				    iov_iter_single_seg_count(&msg->msg_iter);

				if (t4_ddp_indicate_ok(p) &&
				    iov_seg_len &&
				    ((iov_seg_len <= p->ind_size) ||
				      !user_ddp_ok)) {
                                        	p->indicate = tcp_sk(sk)->rcv_nxt;
                                        	t4_setup_indicate_modrx(sk);
                                        	p->indout_count++;
				} else if (iov_seg_len &&
					   user_ddp_ok && !user_ddp_pending) {
                        		p->ubuf_ddp_pending = user_ddp_pending =
					!t4_post_ubuf(sk, msg, nonblock, flags);
					if (!p->ubuf_ddp_pending) {
						p->post_failed++;
						if (p->post_failed >=
						    TOM_TUNABLE(cplios->toedev, ddp_maxfail))
							t4_shutdown_ddp(sk);
					}

					if (!(flags & MSG_WAITALL) && user_ddp_pending)
						user_ddp_ok = 0; 
                		}
			}
                }

		/*
		 * If MSG_TRUNC is specified the data is discarded.
		 */
		else if (likely(!(flags & MSG_TRUNC)))
			if (!is_ddp(skb)) {
				if (skb_copy_datagram_msg(skb, offset,
					msg, avail)) {
					if (!copied) {
						copied = -EFAULT;
						break;
					}
				}
			}

		tp->copied_seq += avail;
		copied += avail;
		len -= avail;

		if (is_ddp(skb)) {
			iov_iter_advance(&msg->msg_iter, avail);
			tp->rcv_wup += avail;
		}
skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq))
			tp->urg_data = 0;

		/*
		 * If the buffer is fully consumed free it.  If it's a DDP
		 * buffer also handle any events it indicates.
		 */
		if (avail + offset >= skb->len) {
			unsigned int fl = skb_ulp_ddp_flags(skb);
			int exitnow, got_psh = 0, nomoredata = 0;
	
			if (p->ddp_setup && is_ddp(skb)) {
				if (fl & 1) {
					if (is_ddp_psh(skb) && user_ddp_pending)
						got_psh = 1;
					if (fl & DDP_BF_NOCOPY)
						p->ubuf_ddp_pending = user_ddp_pending = 0;
					if ((fl & DDP_BF_NODATA) && nonblock)
						nomoredata = 1;
				}
				tom_eat_ddp_skb(sk, skb);
				skb = NULL;
			}
			if (likely(skb))
				tom_eat_skb(sk, skb);
			buffers_freed++;

			exitnow = got_psh || nomoredata;
			if  (copied >= target && !skb_peek(&sk->sk_receive_queue) && exitnow)
				break;
				
		}

	} while (len > 0);
	
	/*
	 * If we can still receive decide what to do in preparation for the
	 * next receive.  Note that RCV_SHUTDOWN is set if the connection
	 * transitioned to CLOSE but not if it was in that state to begin with.
	 */

	/*
	 * If we have DDP pending, turn off DDP and pull in any
	 * completed DDP skbs on the receive queue.
	 */
	if (user_ddp_pending) {
		struct sk_buff *skb;

		user_ddp_ok = 0;
		t4_cancel_ubuf(sk, &timeo);
		p = DDP_STATE(sk);
		p->ubuf_ddp_pending  = user_ddp_pending = 0;
		smp_rmb();

		/*
		 * Scan receive queue to absorb any completed DDPs.
		 * The receive queue may contain some number of DDP
		 * skbs (is_ddp() tests true), possibly followed by
		 * some number of "normal" skbs.  If our scan finds a
		 * "normal" skb we can terminate the scan for DDP skbs
		 * since the hardware won't ever turn DDP back on by
		 * itself.
		 */
		while ((skb = skb_peek(&sk->sk_receive_queue)) != NULL) {
			unsigned int offset, avail;

			/*
			 * If this is a normal skb then we're done
			 * scanning for DDP skbs.  If there's more
			 * room to receive the non-DDP skb we may as
			 * well grab the data.
			 */
			if (!is_ddp(skb)) {
				if (len > 0) {
					if (copied < 0)
						copied = 0;
					goto again;
				} else
					break;
			}

			/*
			 * Update our statistics, buffer pointers,
			 * etc. and consume the skb.
			 *
			 * XXX Why do we need to check for skb->len
			 * XXX being non-zero?
			 */
			if (skb->len) {
				offset = tp->copied_seq - ULP_SKB_CB(skb)->seq;
				avail = skb->len - offset;
				tp->copied_seq += avail;
				tp->rcv_wup += avail;
				copied += avail;
				len -= avail;
				iov_iter_advance(&msg->msg_iter, avail);
				buffers_freed++;
			}
			tom_eat_ddp_skb(sk, skb);
		}
	}

	/* Recheck SHUTDOWN conditions as t4_cancel_ubuf can release sock lock */
	if (!(sk->sk_err || sk->sk_state == TCP_CLOSE ||
	      cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN) ||
	      sk_no_receive(sk))) {
		if (p->ddp_setup) {
			if ((p->avg_request_len < (TOM_TUNABLE(cplios->toedev, ddp_thres) >> 1)) &&
				(request < (TOM_TUNABLE(cplios->toedev, ddp_thres) >> 1)) &&
				 !p->indout_count)
					t4_shutdown_ddp(sk);
			else
				t4_ddp_post_indicate(sk);
			p->avg_request_len = (p->avg_request_len + request) >> 1;
		} else if (!p->post_failed && sk_should_ddp(sk, tp, copied)) {
			if (!t4_enter_ddp(sk, sock_rcvlowat(sk, 0, DDP_RSVD_WIN), 0, nonblock))
				p = DDP_STATE(sk);
		}
	} 

	if (buffers_freed)
		t4_cleanup_rbuf(sk, copied);
	release_sock(sk);
	return copied;
}

/*
 * A visitor-pattern based receive method that runs the supplied receive actor
 * directly over the data in the receive queue.
 *
 * Caller must acquire the socket lock.
 */
int t4_read_sock(struct sock *sk, read_descriptor_t *desc,
		 sk_read_actor_t recv_actor)
{
	u32 offset = 0;
	int used, copied = 0;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	while ((skb = tcp_recv_skb(sk, tp->copied_seq, &offset)) != NULL) {
		size_t len = skb->len - offset;

		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;
			if (urg_offset < len)
				len = urg_offset;
			if (!len)
				break;
		}
		used = recv_actor(desc, skb, offset, len);
		if (unlikely(used < 0)) {
			if (!copied)
				return used;
			break;
		} else if (likely(used <= len)) {
			tp->copied_seq += used;
			copied += used;
			offset += used;
		}
		if (offset != skb->len)
			break;

		tom_eat_skb(sk, skb);
		if (!desc->count)
			break;
	}

	if (copied > 0)
		t4_cleanup_rbuf(sk, copied);

	return copied;
}

/*
 * Offload splice_read() implementation.  We need our own because the original
 * calls tcp_read_sock.
 */
#include <linux/splice.h>

struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

static int tcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;

	return skb_splice_bits_pub(skb, offset, tss->pipe, tss->len,
				   tss->flags);
}

static ssize_t chelsio_splice_read(struct sock *sk, loff_t *ppos,
				   struct pipe_inode_info *pipe, size_t len,
				   unsigned int flags)
{
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	int ret;
	long timeo;
	ssize_t spliced;
	read_descriptor_t rd_desc;

	/* We can't seek on a socket input */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;
	rd_desc.arg.data = &tss;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & SPLICE_F_NONBLOCK);
	while (tss.len) {
		ret = t4_read_sock(sk, &rd_desc, tcp_splice_data_recv);
		if (ret < 0)
			break;
		if (!ret) {
			if (spliced)
				break;
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk_no_receive(sk))
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;
		if (tss.len == 0)
			break;

		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    sk_no_receive(sk) || !timeo ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	return spliced ? spliced : ret;
}

/*
 * Close a connection by sending a CPL_CLOSE_CON_REQ message.  Cannot fail
 * under any circumstances.  We take the easy way out and always queue the
 * message to the write_queue.  We can optimize the case where the queue is
 * already empty though the optimization is probably not worth it.
 */
static void close_conn(struct sock *sk)
{
	struct sk_buff *skb;
	struct cpl_close_con_req *req;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int tid = cplios->tid;
	unsigned int len = roundup(sizeof(struct cpl_close_con_req), 16);

	skb = alloc_skb_nofail(len);
	req = (struct cpl_close_con_req *)__skb_put(skb, len);
	memset(req, 0, len);
        req->wr.wr_hi = htonl(V_FW_WR_OP(FW_TP_WR) |
			      V_FW_WR_IMMDLEN(sizeof(*req) - sizeof(req->wr)));
        req->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*req), 16)) |
                               V_FW_WR_FLOWID(tid));

        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_CON_REQ, tid));

	tcp_uncork(sk);
	skb_entail(sk, skb, ULPCB_FLAG_NO_HDR|ULPCB_FLAG_NO_APPEND);
	if (sk->sk_state != TCP_SYN_SENT)
		t4_push_frames(sk, 1);
}

/*
 * State transitions and actions for close.  Note that if we are in SYN_SENT
 * we remain in that state as we cannot control a connection while it's in
 * SYN_SENT; such connections are allowed to establish and are then aborted.
 */
static unsigned char new_state[16] = {
	/* current state:     new state:      action: */
	/* (Invalid)       */ TCP_CLOSE,
	/* TCP_ESTABLISHED */ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
	/* TCP_SYN_SENT    */ TCP_SYN_SENT,
	/* TCP_SYN_RECV    */ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
	/* TCP_FIN_WAIT1   */ TCP_FIN_WAIT1,
	/* TCP_FIN_WAIT2   */ TCP_FIN_WAIT2,
	/* TCP_TIME_WAIT   */ TCP_CLOSE,
	/* TCP_CLOSE       */ TCP_CLOSE,
	/* TCP_CLOSE_WAIT  */ TCP_LAST_ACK | TCP_ACTION_FIN,
	/* TCP_LAST_ACK    */ TCP_LAST_ACK,
	/* TCP_LISTEN      */ TCP_CLOSE,
	/* TCP_CLOSING     */ TCP_CLOSING,
};

/*
 * Perform a state transition during close and return the actions indicated
 * for the transition.  Do not make this function inline, the main reason
 * it exists at all is to avoid multiple inlining of tcp_set_state.
 */
static int make_close_transition(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];

	tcp_set_state(sk, next & TCP_STATE_MASK);
	return next & TCP_ACTION_FIN;
}

#define SHUTDOWN_ELIGIBLE_STATE (TCPF_ESTABLISHED | TCPF_SYN_RECV | TCPF_CLOSE_WAIT)

/*
 * Shutdown the sending side of a connection. Much like close except
 * that we don't receive shut down or set_sock_flag(sk, SOCK_DEAD).
 *
 * Note: this does not do anything for SYN_SENT state as tcp_shutdown
 * does, however this function is not really called for SYN_SENT because
 * inet_shutdown handles that state specially.  So no harm.
 */
static void chelsio_shutdown(struct sock *sk, int how)
{
        if (sk->sk_prot->shutdown != chelsio_shutdown)
                return sk->sk_prot->shutdown(sk, how);

	if ((how & SEND_SHUTDOWN) &&
	    sk_in_state(sk, SHUTDOWN_ELIGIBLE_STATE) &&
	    !ma_fail_chelsio_shutdown(sk) &&
	    make_close_transition(sk))
		close_conn(sk);
}

static void chelsio_close(struct sock *sk, long timeout)
{
	struct cpl_io_state *cplios;
	int data_lost, old_state;

	lock_sock(sk);

        if (sk->sk_prot->close != chelsio_close) {
                release_sock(sk);
                return sk->sk_prot->close(sk, timeout);
        }

	cplios = CPL_IO_STATE(sk);
	sk->sk_shutdown |= SHUTDOWN_MASK;

	if (ma_fail_chelsio_close(sk))
		return;

	/*
	 * We need to flush the receive buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!  Make a note
	 * of whether any received data will be lost so we can decide whether
	 * to FIN or RST.
	 */
	data_lost = skb_queue_len(&sk->sk_receive_queue);
	if (is_tls_offload(sk)) {
		struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

		data_lost |= skb_queue_len(&tls_ofld->sk_recv_queue);
		t4_tls_purge_receive_queue(sk);
	}
	t4_purge_receive_queue(sk);

	/*
	 * If the connection is in DDP mode, disable DDP and have any
	 * outstanding data and FIN (!!!) delivered to the host since HW
	 * might fail a ABORT_REQ if a fin is held. 
	 */
	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		t4_enable_ddp(sk, 0);

	if (sk->sk_state == TCP_CLOSE)  /* Nothing if we are already closed */
		;
	else if (data_lost || sk->sk_state == TCP_SYN_SENT) {
		// Unread data was tossed, zap the connection.
		T4_NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		t4_send_reset(sk, CPL_ABORT_SEND_RST, NULL);
		release_tcp_port(sk);
		goto unlock;
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		T4_NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
	} else if (make_close_transition(sk)) {	/* Regular FIN-based close */
		close_conn(sk);
	}

	if (timeout)
		sk_stream_wait_close(sk, timeout);

unlock:
	old_state = sk->sk_state;
	sock_hold(sk); /* must last past the potential inet_csk_destroy_sock */
	sock_orphan(sk);
	INC_ORPHAN_COUNT(sk);

	release_sock(sk); /* Final release_sock in connection's lifetime. */

	/*
	 * There are no more user references at this point.  Grab the socket
	 * spinlock and finish the close.
	 */
	local_bh_disable();
	bh_lock_sock(sk);

	/*
	 * Because the socket was orphaned before the bh_lock_sock
	 * either the backlog or a BH may have already destroyed it.
	 * Bail out if so.
	 */
	if (old_state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	if (sk->sk_state == TCP_FIN_WAIT2 && tcp_sk(sk)->linger2 < 0 &&
	    !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN)) {
		struct sk_buff *skb;

		skb = alloc_skb(sizeof(struct cpl_abort_req), GFP_ATOMIC);
		if (skb) {
			t4_send_reset(sk, CPL_ABORT_SEND_RST, skb);
			T4_NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONLINGER);
		}
	}
#if 0
	if (sk->sk_state != TCP_CLOSE) {
		sk_stream_mem_reclaim(sk);
		if (atomic_read(sk->sk_prot->orphan_count) > sysctl_tcp_max_orphans ||
		    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
		     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
			if (net_ratelimit())
				printk(KERN_INFO
				       "TCP: too many orphaned sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		}
	}
#endif

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/*
 * Our analog of tcp_free_skb().
 */
static inline void chelsio_tcp_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_wmem_queued -= skb->truesize;

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY_COW)
		t4_zcopy_cleanup_skb(sk, skb);
	else
		skb_vaddr_set(skb, 0);
#endif
	__kfree_skb(skb);
}

void t4_purge_write_queue(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&cplios->tx_queue)))
		chelsio_tcp_free_skb(sk, skb);
	// tcp_mem_reclaim(sk);
}

/*
 * Switch a socket to the SW TCP's protocol operations.
 */
void t4_install_standard_ops(struct sock *sk)
{
	struct sk_ofld_proto *oproto;

	/*
	 * Once we switch to the standard TCP operations our destructor
	 * (chelsio_destroy_sock) will not be called.  That function normally
	 * cleans up socket DDP state so we need to do that here to avoid
	 * leaking DDP resources.  Note that while the socket may live on for
	 * a long time DDP isn't usable with the standard ops, so DDP state
	 * can be released at this time.
	 */
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	t4_cleanup_ddp(sk);
	cplios->ulp_mode = ULP_MODE_NONE;

	oproto = (struct sk_ofld_proto *)sk->sk_prot;
#if defined(CONFIG_TCPV6_OFFLOAD)
	if (sk->sk_family == AF_INET)
		smp_store_release(&sk->sk_prot, &tcp_prot);
	else
		smp_store_release(&sk->sk_prot, tcpv6_prot_p);
#else
	smp_store_release(&sk->sk_prot, &tcp_prot);
#endif
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	restore_socket_ops(sk);
	if (sk->sk_write_space == t4_write_space)
		sk->sk_write_space = sk_stream_write_space_compat;
	if (likely(sk->sk_filter)) {
		sk_filter_uncharge_compat(sk, sk->sk_filter);
		sk->sk_filter = NULL;
	}
	if (sk->sk_user_data)
		restore_special_data_ready(sk);
	tcp_xmit_timers_init_compat(sk);
	cplios_oproto_put(sk, cplios, oproto);
}

/*
 * Wait until a socket enters on of the given states.
 */
static int wait_for_states(struct sock *sk, unsigned int states)
{
	struct socket_wq _sk_wq;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	int err = 0, count = 0;
	int maxcount = 5;

	if (toedev_in_shutdown(CPL_IO_STATE(sk)->toedev))
		return 0;
	/*
	 * We want this to work even when there's no associated struct socket.
	 * In that case we provide a temporary wait_queue_head_t.
	 */
	if (sk->sk_wq == NULL) {
		init_waitqueue_head(&_sk_wq.wait);
		_sk_wq.fasync_list = NULL;
		init_rcu_head_on_stack(&_sk_wq.rcu);
		sk->sk_wq = &_sk_wq;
	}

	add_wait_queue(sk_sleep(sk), &wait);
	while (!sk_in_state(sk, states)) {
		signed long current_timeo = msecs_to_jiffies(200);

		if (count == maxcount) {
			err = -EBUSY;
			break;
		}
		count++;

		set_current_state(TASK_UNINTERRUPTIBLE);
		release_sock(sk);
		if (!sk_in_state(sk, states))
			current_timeo = schedule_timeout(current_timeo);
		__set_current_state(TASK_RUNNING);
		lock_sock(sk);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	if (sk->sk_wq == &_sk_wq)
		sk->sk_wq = NULL;
	return err;
}

static void t4_tls_release_context(struct kref *ref)
{
        struct tls_ofld_info *tls_ofld =
                container_of(ref, struct tls_ofld_info, kref);
        struct sock *sk = tls_ofld->sk;

        clear_tls_keyid(sk);
        if (tls_ofld->k_ctx) {
                kfree(tls_ofld->k_ctx);
                tls_ofld->k_ctx = NULL;
        }
        stop_hndsk_work(sk);
        tls_ofld->tls_offload = 0;
}

static int chelsio_disconnect(struct sock *sk, int flags)
{
	struct cpl_io_state *cplios;
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

        if (sk->sk_prot->disconnect != chelsio_disconnect)
                return sk->sk_prot->disconnect(sk, flags);

	cplios = CPL_IO_STATE(sk);
	if (is_tls_offload(sk))
		t4_tls_purge_receive_queue(sk);
	t4_purge_receive_queue(sk);
	t4_purge_write_queue(sk);

	if (sk->sk_state != TCP_CLOSE) {
		sk->sk_err = ECONNRESET;
		t4_send_reset(sk, CPL_ABORT_SEND_RST, NULL);

		if ((err = wait_for_states(sk, TCPF_CLOSE))) {
			if (printk_ratelimit())
				pr_err("%s: Either Abort rpl did not get processed "
					"or the wait timed-out; err = %d \n",
					__func__, err);
			return err;
		}
	}
	if (sk->sk_prot->disconnect != chelsio_disconnect)
		return sk->sk_prot->disconnect(sk, flags);

	if (is_tls_offload(sk))
		t4_tls_purge_receive_queue(sk);
	t4_purge_receive_queue(sk);
	__skb_queue_purge(&cplios->ooo_queue);

	/*
	 * We don't know the correct value for max_window but we know an
	 * upper limit.
	 */
	tp->max_window = 0xFFFF << SND_WSCALE(tp);
	if (is_tls_offload(sk)) {
		struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

		kref_put(&tls_ofld->kref, t4_tls_release_context);
	}

	/*
	 * Now switch to Linux's TCP operations and let it finish the job.
	 */
	t4_install_standard_ops(sk);
	return tcp_disconnect(sk, flags);
}

/*
 * Our version of tcp_v4_destroy_sock().  We need to do this because
 * tcp_writequeue_purge() that is used in the original doesn't quite match
 * our needs.  If we ever hook into the memory management of the SW stack we
 * may be able to use tcp_v4_destroy_sock() directly.
 */
static t4_type_compat chelsio_destroy_sock(struct sock *sk)
{
	struct cpl_io_state *cplios;

        if (sk->sk_prot->destroy != chelsio_destroy_sock)
                return sk->sk_prot->destroy(sk);

	cplios = CPL_IO_STATE(sk);
	t4_cleanup_ddp(sk);
	if (is_tls_offload(sk))
		t4_tls_purge_receive_queue(sk);

	cplios->ulp_mode = ULP_MODE_NONE;
	t4_purge_write_queue(sk);
	if (is_tls_offload(sk)) {
		struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

		kref_put(&tls_ofld->kref, t4_tls_release_context);
	}

	cplios->toedev = NULL;
	cplios_oproto_put(sk, cplios, sk_ofld_proto_get(sk));

#if defined(CONFIG_TCPV6_OFFLOAD)
	if (sk->sk_family == AF_INET)
		smp_store_release(&sk->sk_prot, &tcp_prot);
	else
		smp_store_release(&sk->sk_prot, tcpv6_prot_p);
#else
	smp_store_release(&sk->sk_prot, &tcp_prot);
#endif
	sk->sk_prot->destroy(sk);
}

/* IP socket options we do not support on offloaded connections */
#define UNSUP_IP_SOCK_OPT ((1 << IP_OPTIONS))

/*
 * Socket option code for IP.  We do not allow certain options while a
 * connection is offloaded.  Some of the other options we handle specially,
 * and the rest are directed to the SW IP for their usual processing.
 */
static int t4_ip_setsockopt(struct sock *sk, int level, int optname,
			    sockptr_t optval, int optlen, int call_compat)
{

	if (level != SOL_IP)
		return -ENOPROTOOPT;

	/* unsupported options */
	if ((1 << optname) & UNSUP_IP_SOCK_OPT) {
		printk(KERN_WARNING
		       "IP option %d ignored on offloaded TCP connection\n",
		       optname);
		return -ENOPROTOOPT;
	}

	/* specially handled options */
	if (optname == IP_TOS) {
		struct inet_sock *inet = inet_sk(sk);
		int val = 0, err = 0;

		if (optlen >= sizeof(int)) {
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
		} else if (optlen >= sizeof(char)) {
			unsigned char ucval;

			if (copy_from_sockptr(&ucval, optval, sizeof(ucval)))
				return -EFAULT;
			val = (int)ucval;
		}

		lock_sock(sk);

		val &= ~3;
		val |= inet->tos & 3;
		if (IPTOS_PREC(val) >= IPTOS_PREC_CRITIC_ECP &&
		    !capable(CAP_NET_ADMIN))
			err = -EPERM;
		else if (inet->tos != val) {
			inet->tos = val;
			sk->sk_priority = rt_tos2priority(val);
			t4_set_tos(sk);
		}

		release_sock(sk);
		return err;
	}

	return inet_csk(sk)->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
}

/*
 * Socket option code for TCP.  We override any option processing that needs to
 * be handled specially for a TOE and leave the other options to SW TCP.
 */
static int do_t4_tcp_setsockopt(struct sock *sk, int level, int optname,
				sockptr_t optval, socklen_t optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int val, err = 0;

	if (optname == TCP_CONGESTION) {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;
		val = strncpy_from_sockptr(name, optval,
					min((socklen_t)(TCP_CA_NAME_MAX - 1),
					     optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;
		return t4_set_cong_control(sk, name);
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_NODELAY: {
		int oldval = tp->nonagle;

		if (val)
			tp->nonagle |= TCP_NAGLE_OFF;
		else
			tp->nonagle &= ~TCP_NAGLE_OFF;

		if (oldval != tp->nonagle)
			t4_set_nagle(sk);
		break;
	}

	case TCP_CORK:
		if (val)
			tp->nonagle |= TCP_NAGLE_CORK;
		else
			tcp_uncork(sk);
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
		}
		break;

	case TCP_QUICKACK:
		if (!val) {
			inet_csk(sk)->icsk_ack.pingpong = 1;
		} else {
			inet_csk(sk)->icsk_ack.pingpong = 0;
		}
		break;

	case TCP_SCHEDCLASS: {
		struct cpl_io_state *cplios;
		struct toedev *tdev;
		struct tom_data *td;
		struct cxgb4_lld_info *lldi;
		unsigned int old_sched_cls;

		/*
		 * Cant's do anything with dead sockets.
		 */
		if (sk->sk_state == TCP_CLOSE) {
			err = -ENOTCONN;
			break;
		}

		cplios = CPL_IO_STATE(sk);
		tdev = cplios->toedev;
		td = TOM_DATA(tdev);
		lldi = td->lldi;

		/*
		 * Valid Scheduler Class values are:
		 *   val < 0: unbind the socket from any scheduling class
		 *   val < N: bind socket to indicated scheduling class
		 */
		if (val >= 0 && val >= lldi->nsched_cls) {
			err = -EINVAL;
			break;
		}
		old_sched_cls = cplios->sched_cls;
		if (val < 0)
			cplios->sched_cls = SCHED_CLS_NONE;
		else
			cplios->sched_cls = val;

		/*
		 * If we've already sent the first data on the connection,
		 * then we've already sent the first FlowC Work Request with
		 * whatever scheduling class was bound at the time.  So we'll
		 * need to send an update.
		 */
		if (old_sched_cls != cplios->sched_cls &&
		    cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
			int flowclen16 = send_tx_schedclass_wr(sk, 0);
			if (flowclen16 < 0)
				err = flowclen16;
		}
		break;
	}

	default:
		release_sock(sk);
		err = tcp_setsockopt(sk, level, optname,
				     optval, optlen);
		goto out;
	}
	release_sock(sk);
out:
	return err;
}

static int t4_tcp_setsockopt(struct sock *sk, int level, int optname,
			     sockptr_t optval, socklen_t optlen)
{
        if (sk->sk_prot->setsockopt != t4_tcp_setsockopt)
                return sk->sk_prot->setsockopt(sk, level, optname, optval,
					       optlen);

	return level != SOL_TCP ?
		t4_ip_setsockopt(sk, level, optname, optval, optlen, 0) :
		do_t4_tcp_setsockopt(sk, level, optname, optval, optlen);
}

#if defined(CONFIG_TCP_OFFLOAD)
static void set_keepalive(struct sock *sk, int on_off)
{
	int old = sock_flag(sk, SOCK_KEEPOPEN) != 0;

	if (sk->sk_prot->set_keepalive != set_keepalive)
		return sk->sk_prot->set_keepalive(sk, on_off);

	if (sk->sk_state != TCP_CLOSE && (on_off ^ old))
		t4_set_keepalive(sk, on_off);
}
#endif

static int chelsio_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tls_key_context uk_ctx;
	int mode = 0;

	switch (cmd) {
	case IOCTL_TLSOM_SET_TLS_CONTEXT:
		if (copy_from_user((void *)&uk_ctx, (void *)arg,
				   sizeof(struct tls_key_context))) {
			return -1;
		}
		return program_key_context(sk, (struct tls_key_context
						*)&uk_ctx);

	case IOCTL_TLSOM_GET_TLS_TOM:
		lock_sock(sk);

		 /* This ioctl call initializes tls offload for this sk if
		  * uninitialized and provides tls offload enable/disable
		  * info to the users.
		  * mode = 1: tls offload is enabled, mode = 0: tls offload is disabled
		  * */
		if (is_tls_offload(sk) || (tls_set_ofld_mode(sk) == 0))
			mode = 1;
		release_sock(sk);
		return put_user(mode, (int __user *)arg);

	case IOCTL_TLSOM_CLR_TLS_TOM:
		return tls_clr_ofld_mode(sk);

	case IOCTL_TLSOM_CLR_QUIES:
		return tls_clr_quiesce(sk);

	default:
		return tcp_ioctl(sk, cmd, arg);
	}
}

struct request_sock_ops t4_rsk_ops, t4_rsk6_ops;

struct sk_ofld_proto t4_tcp_prot, t4_tcp_v6_prot;

/*
 * Set up the offload protocol operations vector.  We start with TCP's and
 * override some of the operations.  Note that we do not override the backlog
 * handler here.
 */
void __init t4_init_offload_ops(void)
{
	t4_tcp_prot.proto = tcp_prot;
	t4_init_rsk_ops(&t4_tcp_prot.proto, &t4_rsk_ops, &tcp_prot, PF_INET);

	t4_tcp_prot.proto.close         = chelsio_close;
	t4_tcp_prot.proto.disconnect    = chelsio_disconnect;
	t4_tcp_prot.proto.destroy       = chelsio_destroy_sock;
	t4_tcp_prot.proto.shutdown      = chelsio_shutdown;
	t4_tcp_prot.proto.setsockopt    = t4_tcp_setsockopt;
	t4_tcp_prot.proto.sendmsg       = chelsio_sendmsg;
	t4_tcp_prot.proto.recvmsg       = chelsio_recvmsg;
	t4_tcp_prot.proto.sendpage      = chelsio_sendpage;
	t4_tcp_prot.proto.ioctl         = chelsio_ioctl;
#if defined(CONFIG_TCP_OFFLOAD)
	t4_tcp_prot.proto.sendskb       = t4_sendskb;
	t4_tcp_prot.proto.read_sock     = t4_read_sock;
	t4_tcp_prot.proto.set_keepalive = set_keepalive;
#endif
	t4_tcp_prot.read_sock = t4_read_sock;
	t4_tcp_prot.splice_read = chelsio_splice_read;

#if defined(CONFIG_TCPV6_OFFLOAD)
	t4_tcp_v6_prot.proto = *tcpv6_prot_p;
        t4_tcp_v6_prot.proto.close         = chelsio_close;
        t4_tcp_v6_prot.proto.disconnect    = chelsio_disconnect;
        t4_tcp_v6_prot.proto.destroy       = chelsio_destroy_sock;
        t4_tcp_v6_prot.proto.shutdown      = chelsio_shutdown;
        t4_tcp_v6_prot.proto.setsockopt    = t4_tcp_setsockopt;
        t4_tcp_v6_prot.proto.sendmsg       = chelsio_sendmsg;
        t4_tcp_v6_prot.proto.recvmsg       = chelsio_recvmsg;
        t4_tcp_v6_prot.proto.sendpage      = chelsio_sendpage;
	t4_tcp_v6_prot.proto.ioctl         = chelsio_ioctl;
#if defined(CONFIG_TCP_OFFLOAD)
        t4_tcp_v6_prot.proto.sendskb       = t4_sendskb;
        t4_tcp_v6_prot.proto.read_sock     = t4_read_sock;
        t4_tcp_v6_prot.proto.set_keepalive = set_keepalive;
#endif
        t4_tcp_v6_prot.read_sock = t4_read_sock;
        t4_tcp_v6_prot.splice_read = chelsio_splice_read;
	t4_init_rsk6_ops(&t4_tcp_v6_prot.proto, &t4_rsk6_ops, tcpv6_prot_p, PF_INET6);
#endif
}
