/*
 * This file implements the Chelsio CPL5 message processing.
 *
 * Copyright (C) 2006-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include "l2t.h"
#include "defs.h"
#include "tom.h"
#include "t4_hw.h"
#include "t4_ddp.h"
#include "t4_tcb.h"
#include "trace.h"

/*
 * Return the # of page pods needed to accommodate a # of pages.
 */
static inline unsigned int pages2ppods(unsigned int pages)
{
	return (pages + PPOD_PAGES - 1) / PPOD_PAGES;
}

static void unmap_ddp_gl(struct pci_dev *pdev,
			 struct ddp_gather_list *gl,
			 unsigned int npages)
{
	if (!npages)
		return;

	pci_unmap_sg(pdev, gl->sgt.sgl, gl->sgt.nents, PCI_DMA_FROMDEVICE);
	sg_free_table(&gl->sgt);
}

static int t4_dma_map_pages(struct pci_dev *pdev, size_t pg_off, size_t len,
			    unsigned int npages, struct ddp_gather_list *p)
{
	int i, j, count, k = 0;
	struct sg_table *sgt = &p->sgt;
	struct scatterlist *sg;

	if (sg_alloc_table_from_pages(sgt, p->pages, npages, 0, len+pg_off,
				      GFP_KERNEL) < 0)
		return -ENOMEM;
	count = pci_map_sg(pdev, sgt->sgl, sgt->nents, PCI_DMA_FROMDEVICE);
	if (!count) {
		sg_free_table(sgt);
		return -ENOMEM;
	}
	for_each_sg(sgt->sgl, sg, count, i) {
		dma_addr_t startaddr = sg_dma_address(sg);
		unsigned int n_pages = (sg_dma_len(sg) + PAGE_SIZE - 1) >> PAGE_SHIFT;

		p->phys_addr[k++] = startaddr;
		for (j = 1; j < n_pages; j++, k++)
			p->phys_addr[k] = startaddr + j*PAGE_SIZE;
	}
	p->length = len;
	p->offset = pg_off;
	p->nelem = npages;
	return 0;
}

static inline int check_nonmatching_gl(struct ddp_gather_list *gl1, struct ddp_gather_list *gl2,
					size_t pg_off, size_t len, unsigned int npages)
{
	int i;

        if (gl1->offset == pg_off && gl1->nelem >= npages &&
            gl1->length >= len) {
                for (i = 0; i < npages; ++i)
                        if (gl1->pages[i] != gl2->pages[i]) {
                                return i;
                        }
                return -1;
        }
	return 0;
}

/**
 *	t4_pin_pages - pin a user memory range and prepare it for DDP
 *	@addr - the starting address
 *	@len - the length of the range
 *	@newgl - contains the pages and physical addresses of the pinned range
 *	@gl - an existing gather list, may be %NULL
 *
 *	Pins the pages in the user-space memory range [addr, addr + len) and
 *	maps them for DMA.  Returns a gather list with the pinned pages and
 *	their physical addresses.  If @gl is non NULL the pages it describes
 *	are compared against the pages for [addr, addr + len), and if the
 *	existing gather list already covers the range a new list is not
 *	allocated.  Returns 0 on success, or a negative errno.  On success if
 *	a new gather list was allocated it is returned in @newgl.
 */ 
int t4_pin_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 struct ddp_state *ds)
{
	int i;
	size_t pg_off;
	struct ddp_gather_list *p;
	int match0, match1;
	unsigned long lock_limit;
	unsigned long locked;
	long err, npages;
	int mm_locked;

	if (!len)
		return -EINVAL;
	if (!access_ok_compat(VERIFY_WRITE, addr, len))
		return -EFAULT;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	p = kmalloc(struct_size(p, phys_addr, npages) +
		    npages * sizeof(struct page *), GFP_KERNEL);
	if (!p) {
		err = -ENOMEM;
		goto free_gl;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	mm_locked = 1;
	down_read(&current->mm->mmap_sem);
	locked = npages + current->mm->pinned_vm;
#else
	mm_locked = 0;
	locked = atomic64_add_return(npages, &current->mm->pinned_vm);
#endif

	if (!capable(CAP_IPC_LOCK)) {
		lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
		if (locked > lock_limit) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
			if (mm_locked)
				up_read(&current->mm->mmap_sem);
#else
			atomic64_sub(npages, &current->mm->pinned_vm);
#endif
			err = -ENOMEM;
			goto free_gl;
		}
	}
	p->type = DDP_TYPE_USER;
	p->pages = (struct page **)&p->phys_addr[npages];
	/*
	 * get_user_pages() will mark the pages dirty so we don't need to do it
	 * later.  See how get_user_pages() uses FOLL_TOUCH | FOLL_WRITE.
	 */
	err = t4_get_user_pages_locked_with_flags(addr, npages, FOLL_WRITE,
				    p->pages, &mm_locked);
	if (mm_locked)
		mmap_read_unlock(current->mm);
	if (err != npages) {
		if (err < 0)
			goto free_gl;
		npages = err;
		err = -EFAULT;
		goto unpin;
	}
	match0 = match1 = 0;
	if (ds->ubuf[0])
		match0 = check_nonmatching_gl(ds->ubuf[0], p, pg_off, len , npages);
	if (ds->ubuf[1])
		match1 = check_nonmatching_gl(ds->ubuf[1], p, pg_off, len , npages);

	if (match0 >=0 && match1 >=0) {
		err = t4_dma_map_pages(pdev, pg_off, len, npages, p);
		if (err < 0)
			goto unpin;
		*newgl = p;
		if (ds->ubuf[0] && ds->ubuf[1])
			;
		else if (ds->ubuf[0])
			ds->cur_ubuf = 1;
		else
			ds->cur_ubuf = 0;
		return 0;
	}
	if (match0 < 0)
		ds->cur_ubuf=0;
	else
		ds->cur_ubuf=1;
unpin:
	for (i = 0; i < npages; ++i)
		put_page(p->pages[i]);
free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

/**
 *      t4_map_pages - map a kernel memory range and prepare it for DDP
 *	and assumes caller handles page refcounting.
 *	In all other respects same as t4_pin_pages.
 *      @addr - the starting address
 *      @len - the length of the range
 *      @newgl - contains the pages and physical addresses of the range
 *      @gl - an existing gather list, may be %NULL
 */

int t4_map_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 struct ddp_state *ds)
{
	int i, err=0;
	size_t pg_off;
	unsigned int npages;
	struct ddp_gather_list *p;
	int match;

	if (!len)
		return -EINVAL;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	p = kmalloc(sizeof(struct ddp_gather_list) +
		    npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		    GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->type = DDP_TYPE_KERNEL;
	p->pages = (struct page **)&p->phys_addr[npages];
	
	for (i=0; i < npages; i++) {
		if ((addr < VMALLOC_START) || (addr >= VMALLOC_END))
			p->pages[i] = virt_to_page((void *)addr);
		else
			p->pages[i] = vmalloc_to_page((void *)addr);
		addr += PAGE_SIZE;
	}

	match = 0;
	if (ds->ubuf[0])
		match = check_nonmatching_gl(ds->ubuf[0], p, pg_off, len , npages);
	if (match >=0) {
		err = t4_dma_map_pages(pdev, pg_off, len, npages, p);
		if (err < 0)
			goto free_gl;
		*newgl = p;
		ds->cur_ubuf = 0;
		return 0;
	}

free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

static inline void ddp_gl_free_pages(struct ddp_gather_list *gl)
{
        int i;

        for (i = 0; i < gl->nelem; ++i)
		put_page(gl->pages[i]);
}

void t4_free_ddp_gl(struct sock *sk, unsigned int idx)
{
	struct ddp_gather_list *gl;
	struct ddp_state *p = DDP_STATE(sk);

	gl = p->ubuf[idx]; 
	if (gl->type & DDP_TYPE_USER)
		ddp_gl_free_pages(gl);
	p->ubuf[idx] = NULL;
	kfree(gl);
}

/*
 * Allocate page pods for DDP buffer 1 (the user buffer) and set up the tag in
 * the TCB.  We allocate page pods in multiples of PPOD_CLUSTER_SIZE.  First we
 * try to allocate enough page pods to accommodate the whole buffer, subject to
 * the ddp_maxpages limit.
 * If that fails we try to allocate PPOD_CLUSTER_SIZE page pods
 * before failing entirely.
 */
static int t4_alloc_buf1_ppods(struct sock *sk, struct ddp_state *p,
			    unsigned long addr, unsigned int len)
{
	int tag, npages, nppods;
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(tdev);

	npages = ((addr & ~PAGE_MASK) + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nppods = min(pages2ppods(npages),
			pages2ppods(TOM_TUNABLE(tdev, ddp_maxpages)));
	nppods = ALIGN(nppods, PPOD_CLUSTER_SIZE);
	tag = t4_alloc_ppods(d, nppods);

	if (tag < 0 && nppods > PPOD_CLUSTER_SIZE) {
		nppods = PPOD_CLUSTER_SIZE;
		tag = t4_alloc_ppods(d, nppods);
	}
	if (tag < 0)
		return -ENOMEM;
	p->ubuf_nppods = nppods;
	p->ubuf_tag = tag;
	return nppods;
}

static inline u64 select_ddp_flags(const struct sock *sk, int buf_idx,
					     int nonblock, int rcv_flags)
{
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	unsigned long long flush = !TOM_TUNABLE(tdev, ddp_push_wait);

	if (buf_idx == 1) {
		if (unlikely(rcv_flags & MSG_WAITALL))
			return V_TF_DDP_PSH_NO_INVALIDATE1(1ULL)|
				V_TF_DDP_PUSH_DISABLE_1(1ULL);

		if (nonblock)
			return V_TF_DDP_BUF1_FLUSH(1ULL);

		return V_TF_DDP_PSHF_ENABLE_1(1ULL)|V_TF_DDP_BUF1_FLUSH(flush);
	}

	if (unlikely(rcv_flags & MSG_WAITALL))
		return V_TF_DDP_PUSH_DISABLE_0(1ULL);

	return V_TF_DDP_PSHF_ENABLE_0(1ULL)|V_TF_DDP_BUF0_FLUSH(flush);
}

/**
 * setup_iovec_ppods - setup HW page pods for a user iovec
 * @sk: the associated socket
 * @msg: the msghdr for access to iterator
 *
 * Pins a user iovec and sets up HW page pods for DDP into it.  We allocate
 * page pods for user buffers on the first call per socket.  Afterwards we
 * limit the buffer length to whatever the existing page pods can accommodate.
 * Returns a negative error code or the length of the mapped buffer.
 *
 * The current implementation handles iovecs with only one entry.
 */
static int t4_setup_iovec_ppods(struct sock *sk, struct msghdr *msg)
{
	int err, nppods, tag;
	unsigned int len, idx;
	struct ddp_gather_list *gl;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct ddp_state *p = &cplios->ddp_state;
	struct dma_pool *pool = TOM_DATA(cplios->toedev)->dma_pool;
	const struct iovec *iov = msg->msg_iter.iov;
	unsigned long addr = (unsigned long)iov->iov_base +
				msg->msg_iter.iov_offset;

	if (p->ubuf[0] && p->ubuf[1]) {
		p->cur_ubuf ^= 1;
		nppods = p->ubuf[p->cur_ubuf]->nppods;
		tag = p->ubuf[p->cur_ubuf]->tag;
	} else if (!p->ubuf_nppods) {
		err = t4_alloc_buf1_ppods(sk, p, addr,
				iov_iter_single_seg_count(&msg->msg_iter));
		if (err < 0)
			return err;
		nppods = p->ubuf_nppods;
		tag = p->ubuf_tag;
	} else {
		nppods = p->ubuf_nppods;
		tag = p->ubuf_tag;
	}
	len = nppods * PPOD_PAGES * PAGE_SIZE;

	len -= addr & ~PAGE_MASK;
	if (len > M_TCB_RX_DDP_BUF0_LEN)
		len = M_TCB_RX_DDP_BUF0_LEN;
	len = min_t(int, len, iov_iter_single_seg_count(&msg->msg_iter));

	if (!uaccess_kernel())
		err = t4_pin_pages(p->pdev, addr, len, &gl, p);
	else
		err = t4_map_pages(p->pdev, addr, len, &gl, p);
	if (err < 0)
		return err;

	if (gl) {
		if (p->ubuf[0] && p->ubuf[1]) {
			struct ddp_gather_list *cur_gl = p->ubuf[p->cur_ubuf];

			unmap_ddp_gl(p->pdev, cur_gl, cur_gl->nelem);
			t4_free_ddp_gl(sk, p->cur_ubuf);
		}
		p->ubuf[p->cur_ubuf] = gl;
		gl->tag = tag;
		gl->nppods = nppods;
		p->ubuf_nppods = p->ubuf_tag = 0;
		p->ddp_color = (p->ddp_color + 1) % PPOD_SIZE;
		gl->color = p->ddp_color;
		if (pool && (gl->nelem > PPOD_PAGES)) {
			struct tom_data *td = TOM_DATA(cplios->toedev);
			unsigned int ppod_addr = gl->tag * PPOD_SIZE +
							td->ddp_llimit;
			unsigned int total_ppods = pages2ppods(gl->nelem);
			unsigned int podchunk;
			struct dsgl_req *req;

			for (idx = 0; idx < total_ppods; idx += podchunk,
				ppod_addr += podchunk*PPOD_SIZE) {
				podchunk = ((total_ppods - idx) >=
						NUM_ULP_TX_SC_DSGL_PPODS) ?
						NUM_ULP_TX_SC_DSGL_PPODS :
						(total_ppods - idx);
				req = kmalloc(sizeof(*req), GFP_KERNEL);
				if (req) {
					req->dsgl_vaddr =
						dma_pool_alloc(pool,
							       GFP_KERNEL,
							       &req->dsgl_iova);
					if (req->dsgl_vaddr) {
						err = t4_set_dsgl_ppods(cplios,
									gl,
									req,
									ppod_addr,
									podchunk,
									len,
									idx);
						if (err < 0) {
							dma_pool_free(pool,
								      req->dsgl_vaddr,
								      req->dsgl_iova);
							kfree(req);
							return err;
						}
						gl->type |= DDP_TYPE_DSGL;
					}
				}
			}
		} else
			gl->type &= ~DDP_TYPE_DSGL;
		if (!(gl->type & DDP_TYPE_DSGL))
			err = t4_setup_ppods(cplios,
					     gl,
					     pages2ppods(gl->nelem),
					     gl->tag,
					     len);
		if (err < 0)
			return err;
	}
	return len;
}

int t4_post_ubuf(struct sock *sk, struct msghdr *msg,
		 int nonblock, int rcv_flags)
{
	int len, ret;
	u64 flags;
	struct ddp_state *p = DDP_STATE(sk);

	len = t4_setup_iovec_ppods(sk, msg);
	if (len < 0)
		return len;

	p->buf_state[1].cur_offset = 0;
	p->buf_state[1].flags = DDP_BF_NOCOPY;
	p->buf_state[1].gl = p->ubuf[p->cur_ubuf];

	flags = select_ddp_flags(sk, 1, nonblock, rcv_flags);

	t4_set_ddp_tag(sk, 1, p->ubuf[p->cur_ubuf]->tag << 6 |
		       p->ubuf[p->cur_ubuf]->color);
	p->ddp_tag = p->ubuf[p->cur_ubuf]->tag;
	p->cur_buf = 1;

	ret = t4_setup_ddpbufs(sk, 0, 0, len, 0, V_TF_DDP_BUF1_VALID(1ULL) |
			 V_TF_DDP_ACTIVE_BUF(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL) |
			flags,
			 V_TF_DDP_PSHF_ENABLE_1(1ULL) |
			 V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL) |
			 V_TF_DDP_PSH_NO_INVALIDATE0(1ULL) | V_TF_DDP_PSH_NO_INVALIDATE1(1ULL) |
			 V_TF_DDP_BUF1_FLUSH(1ULL) | V_TF_DDP_PUSH_DISABLE_1(1ULL) |
			 V_TF_DDP_BUF1_VALID(1ULL) | V_TF_DDP_BUF0_VALID(1ULL) |
			 V_TF_DDP_ACTIVE_BUF(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL));
	return ret;
}

/*
 * 
 */
void t4_cancel_ubuf(struct sock *sk, long *timeo)
{
	struct ddp_state *p = DDP_STATE(sk);
	int rc;
	int ubuf_pending;
	long gettcbtimeo;
	int canceled=0;
	int norcv=0;
	int err;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	if (!p->ddp_setup || !p->pdev)
		return;

	gettcbtimeo = max_t(long, msecs_to_jiffies(1), *timeo);
	p->cancel_ubuf = 1;

       if (t4_ddp_ubuf_pending(sk)) {
                release_sock(sk);
                lock_sock(sk);
        }

	ubuf_pending = t4_ddp_ubuf_pending(sk);

	while (ubuf_pending && !norcv) {
#ifdef T4_TRACE
		T4_TRACE3(TIDTB(sk), 
		  "t4_cancel_ubuf: flags0 0x%x flags1 0x%x get_tcb_count %d",
		  p->buf_state[0].flags & DDP_BF_NOCOPY, 
		  p->buf_state[1].flags & DDP_BF_NOCOPY,
		  p->get_tcb_count);
#endif
		if (!canceled && !p->get_tcb_count) {
			canceled = 1;
			err = t4_cancel_ddpbuf(sk, p->cur_buf);
			BUG_ON(err < 0);
		}

		add_wait_queue(sk_sleep(sk), &wait);

		do {
			rc = sk_wait_event(sk, &gettcbtimeo, 
					   !(DDP_STATE(sk)->ddp_setup ? DDP_STATE(sk)->get_tcb_count : 0) &&
					   !(sk->sk_shutdown & RCV_SHUTDOWN), &wait);
			p = DDP_STATE(sk);
			
			if (signal_pending(current))
				break;

			gettcbtimeo = max_t(long, gettcbtimeo << 1, *timeo);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);

		remove_wait_queue(sk_sleep(sk), &wait);

		ubuf_pending = t4_ddp_ubuf_pending(sk);

		if (signal_pending(current))
			break;
	}

	while (t4_ddp_ubuf_pending(sk) && !norcv) {
		if (!canceled && !p->get_tcb_count) {
			canceled=1;
			err = t4_cancel_ddpbuf(sk, p->cur_buf);
			BUG_ON(err < 0);
		}

		do {
			release_sock(sk);
			gettcbtimeo = (net_random() % (HZ / 2)) + 2;
			__set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(gettcbtimeo);
			lock_sock(sk);
			p = DDP_STATE(sk);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);
	}

	if (p->ddp_setup)
		p->cancel_ubuf = 0;
		
	return;
}

/*
 * Clean up DDP state that needs to survive until socket close time, such as the
 * DDP buffers.  The buffers are already unmapped at this point as unmapping
 * needs the PCI device and a socket may close long after the device is removed.
 */
void t4_cleanup_ddp(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (!p->ddp_setup)
		return;

	p->ddp_setup = 0;
	p->state = 0;

	if (p->ubuf[0])
		t4_free_ddp_gl(sk, 0);
        if (p->ubuf[1])
		t4_free_ddp_gl(sk, 1);
}

/*
 * This is a companion to t4_cleanup_ddp() and releases the HW resources
 * associated with a connection's DDP state, such as the page pods.
 * It's called when HW is done with a connection.   The rest of the state
 * remains available until both HW and the app are done with the connection.
 */
void t4_release_ddp_resources(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (p->ddp_setup) {
		struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);
		
		if (p->ubuf[0] && p->ubuf[0]->nppods) {
			t4_free_ppods(d, p->ubuf[0]->tag, p->ubuf[0]->nppods);
			p->ubuf[0]->nppods = 0;
		}
                if (p->ubuf[1] && p->ubuf[1]->nppods) {
                        t4_free_ppods(d, p->ubuf[1]->tag, p->ubuf[1]->nppods);
                        p->ubuf[1]->nppods = 0;
                }
		if (p->ubuf_nppods) {
                        t4_free_ppods(d, p->ubuf_tag, p->ubuf_nppods);
                        p->ubuf_nppods = 0;
		}
		if (p->ubuf[0])
			unmap_ddp_gl(p->pdev, p->ubuf[0], p->ubuf[0]->nelem);
		if (p->ubuf[1])
			unmap_ddp_gl(p->pdev, p->ubuf[1], p->ubuf[1]->nelem);
	}
	p->pdev = NULL;
}

/*
 * Prepare a socket for DDP.  Must be called when the socket is known to be
 * open.
 */
int t4_enter_ddp(struct sock *sk, unsigned int target, unsigned int waitall, int nonblock)
{
	unsigned int dack_mode = 0;
	struct ddp_state *p = DDP_STATE(sk);
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(tdev);
	unsigned int indicate_size;

	if (p->state == DDP_ENABLED)
		return 0;

	p->state = DDP_ENABLED;
	p->pdev = d->pdev;
	p->buf_state[0].cur_offset = 0;
	p->buf_state[0].flags = 0;
	p->buf_state[0].gl = NULL;
	p->cur_buf = p->cur_ubuf = p->ubuf_nppods = 0;
	p->ubuf[0] = NULL;
	p->ubuf[1] = NULL;
	p->ubuf_ddp_pending = 0;
	p->indicate = 0;
	p->avg_request_len = 0;
	p->ddp_tag = INVALID_TAG;
	p->ddp_color = 0;
	p->post_failed = 0;

	indicate_size = roundup(target, d->lldi->sge_ingpadboundary);
	indicate_size -= (sizeof(struct cpl_rx_data) -
			  sizeof(struct rss_header));
	indicate_size = max(target, indicate_size);
	p->ind_size = indicate_size;
	t4_set_ddp_buf(sk, 0, 0, indicate_size);
	t4_set_tcb_field_rpl(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1ULL) |
                                V_TF_DDP_INDICATE_OUT(1ULL) |
                                V_TF_DDP_BUF0_VALID(1ULL) | V_TF_DDP_BUF1_VALID(1ULL) |
                                V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL),
                                V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL) ,
				DDP_COOKIE_ENABLE);

	dack_mode = t4_select_delack(sk);

        if (dack_mode == 1) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
						    V_TF_DACK_MSS(1ULL)|
						    V_TF_DACK(1ULL),
						    V_TF_DACK(1ULL));
        } else if (dack_mode == 2) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
						    V_TF_DACK_MSS(1ULL)|
						    V_TF_DACK(1ULL),
						    V_TF_DACK_MSS(1ULL));
        } else if (dack_mode == 3) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
						    V_TF_DACK_MSS(1ULL)|
						    V_TF_DACK(1ULL),
						    V_TF_DACK_MSS(1ULL)|
						    V_TF_DACK(1ULL));
        }

	return 0;
}

/* Pagepod allocator */

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
int t4_alloc_ppods(struct tom_data *td, unsigned int n)
{
	int tag;

	if (unlikely(!td->ppod_bmap))
		return -1;

	spin_lock_bh(&td->ppod_map_lock);
	tag = cxgb4_alloc_ppods(td->ppod_bmap, td->nppods, td->start_tag, n,
				PPOD_CLUSTER_SIZE-1);
	if (likely(tag >= 0)) {
		unsigned int end_tag = tag + n;

		td->start_tag = end_tag < td->nppods ? end_tag : 0;
	} else {
		td->start_tag = 0;
		tag = cxgb4_alloc_ppods(td->ppod_bmap, td->nppods, 0, n,
					PPOD_CLUSTER_SIZE-1);
	}
	spin_unlock_bh(&td->ppod_map_lock);

	return tag;
}

void t4_free_ppods(struct tom_data *td, unsigned int tag, unsigned int n)
{
	spin_lock_bh(&td->ppod_map_lock);
	cxgb4_free_ppods(td->ppod_bmap, tag, n);
	spin_unlock_bh(&td->ppod_map_lock);
}
