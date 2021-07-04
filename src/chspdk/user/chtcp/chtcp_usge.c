/*
 * Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2 or the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <sys/ioctl.h>

#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ether.h>

#include <linux/ipv6.h>
#include <linux/ip.h>

#include "spdk/log.h"
#include "spdk_internal/event.h"
#include "spdk/nvmf.h"

#include "chtcp_ucompat.h"

#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_hw.h"
#include "t4_msg.h"
#include "t4fw_interface.h"

#include "chtcp_umain.h"
#include "chtcp_ioctl.h"
#include "chtcp_ucm.h"
#include "chtcp_usge.h"

extern struct chtcp_root g_chtcp_root;
static void chtcp_free_rx_bufs(struct chtcp_sge_fl *q, int n);

/**
 * alloc_ring - allocate resources for an SGE descriptor ring
 * @dev: the PCI device's core device
 * @nelem: the number of descriptors
 * @elem_size: the size of each descriptor
 * @sw_size: the size of the SW state associated with each ring element
 * @phys: the physical address of the allocated ring
 * @metadata: address of the array holding the SW state for the ring
 * @stat_size: extra space in HW ring for status information
 * @node: preferred node for memory allocations
 *
 * Allocates resources for an SGE descriptor ring, such as Tx queues,
 * free buffer lists, or response queues.  Each SGE ring requires
 * space for its HW descriptors plus, optionally, space for the SW state
 * associated with each HW entry (the metadata).  The function returns
 * three values: the virtual address for the HW ring (the return value
 * of the function), the bus address of the HW ring, and the address
 * of the SW ring.
 */
static const struct rte_memzone *
chtcp_alloc_ring(size_t nelem, size_t elem_size, size_t sw_size,
		 void *metadata, size_t stat_size,
		 int socket_id, const char *z_name, const char *z_name_sw)
{

	size_t len = nelem * elem_size + stat_size;
	const struct rte_memzone *tz;
	void *s = NULL;

	tz = rte_memzone_lookup(z_name);
	if (tz) {
		return NULL;
	}

	/*
	 * Allocate TX/RX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_memzone_reserve_aligned(z_name, len, socket_id,
					 RTE_MEMZONE_IOVA_CONTIG, 4096);
	if (!tz)
		return NULL;

	memset(tz->addr, 0, len);
	if (sw_size) {
		s = rte_zmalloc_socket(z_name_sw, nelem * sw_size,
				       RTE_CACHE_LINE_SIZE, socket_id);

		if (!s) {
			return NULL;
		}
	}
	if (metadata)
		*(void **)metadata = s;

	return tz;
}

/**
 * chtcp_rspq_next - advance to the next entry in a response queue
 * @q: the queue
 *
 * Updates the state of a response queue to advance it to the next entry.
 */
static inline void 
chtcp_rspq_next(struct chtcp_sge_rspq *q)
{
	q->cur_desc = (const __be64 *)((const char *)q->cur_desc + q->iqe_len);
	if (unlikely(++q->cidx == q->size)) {
		q->cidx = 0;
		q->cur_desc = q->desc;
	}
}

static inline void 
chtcp_set_rx_sw_desc(struct rx_sw_desc *sd, void *buf,
				  dma_addr_t mapping)
{
	sd->buf = buf;
	sd->dma_addr = mapping;      /* includes size low bits */
}

/**
 * chtcp_fl_cap - return the capacity of a free-buffer list
 * @fl: the FL
 *
 * Returns the capacity of a free-buffer list.  The capacity is less than
 * the size because one descriptor needs to be left unpopulated, otherwise
 * HW will think the FL is empty.
 */
static inline u32 
chtcp_fl_cap(const struct chtcp_sge_fl *fl)
{
	return fl->size - 8;   /* 1 descriptor = 8 buffers */
}

/**
 * chtcp_fl_starving - return whether a Free List is starving.
 * @adapter: pointer to the adapter
 * @fl: the Free List
 *
 * Tests specified Free List to see whether the number of buffers
 * available to the hardware has falled below our "starvation"
 * threshold.
 */
static inline bool 
chtcp_fl_starving(const struct chtcp_uadapter *adapter,
	    const struct chtcp_sge_fl *fl)
{
	const struct chtcp_sge *s = &adapter->sge;

	return fl->avail - fl->pend_cred <= s->fl_starve_thres;
}

/**
 * chtcp_unmap_rx_buf - unmap the current Rx buffer on an SGE free list
 * @q: the SGE free list
 *
 * Unmap the current buffer on an SGE free-buffer Rx queue.   The
 * buffer must be made inaccessible to HW before calling this function.
 *
 * This is similar to @free_rx_bufs above but does not free the buffer.
 * Do note that the FL still loses any further access to the buffer.
 */
static void 
chtcp_unmap_rx_buf(struct chtcp_sge_fl *q)
{
	if (++q->cidx == q->size)
		q->cidx = 0;
	q->avail--;
}

static inline void 
chtcp_ring_fl_db(struct chtcp_uadapter *adap, struct chtcp_sge_fl *q)
{
	if (q->pend_cred >= 8) {
		u32 val = adap->sge_fl_db;

		val |= V_PIDX_T5(q->pend_cred / 8);

		/*
		 * Make sure all memory writes to the Free List queue are
		 * committed before we tell the hardware about them.
		 */
		rte_wmb();

		rte_write32_relaxed(val | V_QID(q->bar2_qid),
			       	    (void *)((uintptr_t)q->bar2_addr +
			       	    SGE_UDB_KDOORBELL));

		/*
		 * This Write memory Barrier will force the write to
		 * the User Doorbell area to be flushed.
		 */
		rte_wmb();
		q->pend_cred &= 7;
	}
}

/**
 * chtcp_refill_fl - refill an SGE Rx buffer ring with mbufs
 * @adap: the adapter
 * @q: the ring to refill
 * @n: the number of new buffers to allocate
 *
 * (Re)populate an SGE free-buffer queue with up to @n new packet buffers,
 * allocated with the supplied gfp flags.  The caller must assure that
 * @n does not exceed the queue's capacity.  If afterwards the queue is
 * found critically low mark it as starving in the bitmap of starving FLs.
 *
 * Returns the number of buffers allocated.
 */
static u32
chtcp_refill_fl(struct chtcp_uadapter *adap, struct chtcp_sge_fl *q, u32 n)
{
	struct chtcp_sge_ofld_rxq *rxq = SPDK_CONTAINEROF(q, struct chtcp_sge_ofld_rxq, fl);
	struct rx_sw_desc *sd = &q->sdesc[q->pidx];
	__be64 *d = &q->desc[q->pidx];
	struct rte_mbuf *buf_bulk[n];
	u32 cred = q->avail, i;
	int ret;

	ret = rte_pktmbuf_alloc_bulk(rxq->rspq.mb_pool, buf_bulk, n);
	if (unlikely(ret != 0)) {
		SPDK_ERRLOG("%s core[%d]: failed to allocate fl entries in bulk\n", 
			adap->pci_devname, rte_lcore_id());
		q->alloc_failed++;
		goto out;
	}

	for (i = 0; i < n; i++) {
		struct rte_mbuf *mbuf = buf_bulk[i];
		struct chtcp_mbuf_private *priv_data;
		dma_addr_t mapping;

		if (!mbuf) {
			SPDK_ERRLOG("%s core[%d]: mbuf alloc failed\n", 
				adap->pci_devname, rte_lcore_id());
			q->alloc_failed++;
			goto out;
		}

		priv_data = CHTCP_MBUF_TO_PRIV(mbuf);
		memset(priv_data, 0, sizeof(struct chtcp_mbuf_private));

		rte_mbuf_refcnt_set(mbuf, 1);

		mbuf->data_off = (RTE_ALIGN(mbuf->buf_iova + RTE_PKTMBUF_HEADROOM,
					    adap->sge.fl_align) -
				  mbuf->buf_iova);
		mbuf->data_len = adap->sge.fl_buf_size;
		mbuf->pkt_len =  mbuf->data_len;
		mbuf->port = rxq->rspq.port_id;

		mapping = (dma_addr_t)(mbuf->buf_iova + mbuf->data_off);
		mapping |= adap->sge.fl_buf_idx;
		*d++ = rte_cpu_to_be_64(mapping);
		chtcp_set_rx_sw_desc(sd, mbuf, mapping);
		sd++;

		q->avail++;
		if (++q->pidx == q->size) {
			q->pidx = 0;
			sd = q->sdesc;
			d = q->desc;
		}
	}

out:    cred = q->avail - cred;
	if (cred == 0)
		return cred;
	q->pend_cred += cred;
	chtcp_ring_fl_db(adap, q);

	if (unlikely(chtcp_fl_starving(adap, q))) {
		/*
		 * Make sure data has been written to free list
		 */
		rte_wmb();
		q->low++;
	}

	return cred;
}

static inline void 
__chtcp_refill_fl(struct chtcp_uadapter *adap, struct chtcp_sge_fl *fl)
{
#define MAX_RX_REFILL 64U
	chtcp_refill_fl(adap, fl, RTE_MIN(MAX_RX_REFILL, chtcp_fl_cap(fl) - fl->avail));
}

static void
chtcp_init_txq(struct chtcp_uadapter *adap, struct chtcp_sge_txq *q,
	       struct chtcp_txq_info *txq_info)
{
	q->cntxt_id = txq_info->u.out.cntxt_id;
	q->bar2_addr = adap->bar2 + txq_info->u.out.bar2_offset;
	q->bar2_qid = txq_info->u.out.bar2_qid;

	q->in_use = 0;
	q->cidx = q->pidx = 0;
	q->stat = (struct sge_qstat *)&q->desc[q->size];
}

int 
chtcp_usge_alloc_ofld_txq(struct chtcp_uadapter *adap,
			  struct chtcp_sge_ofld_txq *txq)
{
	struct chtcp_sge *s = &adap->sge;
	char z_name[RTE_MEMZONE_NAMESIZE];
	char z_name_sw[RTE_MEMZONE_NAMESIZE];
	struct chtcp_txq_info txq_info;
	u32 nentries, socket_id;
	int ret;

	socket_id = rte_lcore_to_socket_id(g_chtcp_root.reactors[txq->reactor_id]->lcore);
	nentries = txq->q.size + (s->stat_len / sizeof(struct tx_desc));

	snprintf(z_name, sizeof(z_name), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 txq->q.port_id, txq->reactor_id, "ofld_tx_ring");

	snprintf(z_name_sw, sizeof(z_name_sw), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 txq->q.port_id, txq->reactor_id, "sw_tx_ring");

	txq->q.mz = chtcp_alloc_ring(txq->q.size, sizeof(struct tx_desc),
			      sizeof(struct tx_sw_desc), &txq->q.sdesc,
			      s->stat_len, socket_id, z_name,
			      z_name_sw);
	if (!txq->q.mz)
		return -ENOMEM;

	txq->q.desc = txq->q.mz->addr;
	txq->q.phys_addr = (uint64_t)txq->q.mz->iova;

	memset(&txq_info, 0, sizeof(txq_info));
	txq_info.u.in.nentries = nentries;
	txq_info.u.in.phys_addr = txq->q.phys_addr;
	txq_info.u.in.port_id = txq->q.port_id; 
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_ALLOC_TXQ_CMD, &txq_info);
	if (ret) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for CHTCP_IOCTL_ALLOC_TXQ: %d\n", 
			adap->pci_devname, rte_lcore_id(), ret);
		return ret;
	}

	chtcp_init_txq(adap, &txq->q, &txq_info);
	TAILQ_INIT(&txq->sendq);

	return 0;
}

static void
chtcp_inline_tx(struct chtcp_sge_txq *q, void *pos, void *data,
	        u32 data_len)
{
	u64 *p;
	u32 left = RTE_PTR_DIFF(q->stat, pos);
	u32 diff;

	if (data_len <= left) {
		rte_memcpy(pos, data, data_len);
		pos += data_len;
	} else {
		rte_memcpy(pos, data, left);
		rte_memcpy(q->desc, RTE_PTR_ADD(data, left), data_len - left);
		pos = RTE_PTR_ADD(q->desc, (data_len - left));
	}

	/* 0-pad to multiple of 16 */
	p = RTE_PTR_ALIGN(pos, 8);
	diff = RTE_PTR_DIFF(p, pos);
	if (diff)
		memset(pos, 0, diff);
	if ((uintptr_t)p & 8) {
		*p = 0;
	}
}

static void
chtcp_init_rxq(struct chtcp_uadapter *adap, struct rte_mempool  *mp, 
	       struct chtcp_sge_ofld_rxq *rxq,
	       struct chtcp_rxq_info *rxq_info)
{
	struct chtcp_sge_rspq *iq = &rxq->rspq;
	struct chtcp_sge_fl *fl = &rxq->fl;

	iq->cur_desc = iq->desc;
	iq->cidx = 0;
	iq->gts_idx = 0;
	iq->cntxt_id = rxq_info->u.out.q_cntxt_id;
	iq->abs_id = rxq_info->u.out.q_abs_id;

	iq->bar2_addr = adap->bar2 + rxq_info->u.out.q_bar2_offset;
	iq->bar2_qid = rxq_info->u.out.q_bar2_qid;

	iq->size--; /* subtract status entry */
	iq->stat = (void *)&iq->desc[iq->size * 8];
	iq->mb_pool = mp;

	fl->cntxt_id = rxq_info->u.out.fl_cntxt_id;
	fl->avail = 0;
	fl->pend_cred = 0;
	fl->pidx = 0;
	fl->cidx = 0;
	fl->alloc_failed = 0;
	
	fl->bar2_addr = adap->bar2 + rxq_info->u.out.fl_bar2_offset;
	fl->bar2_qid = rxq_info->u.out.fl_bar2_qid;
}

int 
chtcp_usge_alloc_ofld_rxq(struct chtcp_uadapter *adap,
			  struct rte_mempool *mp,
			  struct chtcp_sge_ofld_rxq *rxq)
{
	struct chtcp_sge_rspq *iq = &rxq->rspq;
	struct chtcp_sge_fl *fl = &rxq->fl;
	struct chtcp_free_rxq_info fri;
	int ret, flsz = 0;
	struct chtcp_sge *s = &adap->sge;
	char z_name[RTE_MEMZONE_NAMESIZE];
	char z_name_sw[RTE_MEMZONE_NAMESIZE];
	u32 nb_refill, socket_id;
	struct chtcp_rxq_info rxq_info;
	struct chtcp_conm_ctx_info conm_info;

	socket_id = rte_lcore_to_socket_id(g_chtcp_root.reactors[rxq->reactor_id]->lcore);
	/* Size needs to be multiple of 16, including status entry. */
	iq->size = RTE_ALIGN_CEIL(iq->size, 16);

	snprintf(z_name, sizeof(z_name), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 rxq->rspq.port_id, rxq->reactor_id, "rx_ring");
	snprintf(z_name_sw, sizeof(z_name_sw), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 rxq->rspq.port_id, rxq->reactor_id, "sw_rx_ring");

	iq->mz = chtcp_alloc_ring(iq->size, iq->iqe_len, 0, NULL, 0,
				  socket_id, z_name,
				  z_name_sw);
	if (!iq->mz)
		return -ENOMEM;

	iq->desc = iq->mz->addr; 
	iq->phys_addr = (uint64_t)iq->mz->iova;

	/*
	 * Allocate the ring for the hardware free list (with space
	 * for its status page) along with the associated software
	 * descriptor ring.  The free list size needs to be a multiple
	 * of the Egress Queue Unit and at least 2 Egress Units larger
	 * than the SGE's Egress Congrestion Threshold
	 * (fl_starve_thres - 1).
	 */
	if (fl->size < (s->fl_starve_thres - 1 + (2 * 8)))
		fl->size = s->fl_starve_thres - 1 + (2 * 8);
	fl->size = RTE_ALIGN_CEIL(fl->size, 8);

	snprintf(z_name, sizeof(z_name), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 rxq->rspq.port_id, rxq->reactor_id, "fl_ring");
	snprintf(z_name_sw, sizeof(z_name_sw), "ofld_a%d_p%d_r%d_%s", adap->adap_idx,
		 rxq->rspq.port_id, rxq->reactor_id, "sw_fl_ring");

	fl->mz = chtcp_alloc_ring(fl->size, sizeof(__be64),
				  sizeof(struct rx_sw_desc), &fl->sdesc,
				  s->stat_len, socket_id,
				  z_name, z_name_sw);
	if (!fl->mz)
		goto fl_nomem;

	fl->desc = fl->mz->addr; 
	fl->addr = (uint64_t)fl->mz->iova;

	flsz = (fl->size / 8) + (s->stat_len / sizeof(struct tx_desc));

	memset(&rxq_info, 0, sizeof(rxq_info));
	rxq_info.u.in.q_phys_addr = iq->phys_addr;
	rxq_info.u.in.q_size = iq->size;
	rxq_info.u.in.iqe_len = iq->iqe_len;
	rxq_info.u.in.fl_addr = fl->addr;
	rxq_info.u.in.fl_size = flsz;
	rxq_info.u.in.port_id = rxq->rspq.port_id;
	rxq_info.u.in.pack_en = 0;
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_ALLOC_RXQ_CMD, &rxq_info);
	if (ret) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for CHTCP_IOCTL_ALLOC_RXQ: %d\n",
			adap->pci_devname, rte_lcore_id(), ret);
		goto err;
	}

	chtcp_init_rxq(adap, mp, rxq, &rxq_info);

	nb_refill = chtcp_refill_fl(adap, fl, chtcp_fl_cap(fl));
	if (nb_refill != chtcp_fl_cap(fl)) {
		ret = -ENOMEM;
		SPDK_ERRLOG("%s core[%d]: mbuf alloc failed with error: %d\n",
			adap->pci_devname, rte_lcore_id(), ret);
		goto refill_fl_err;
	}

	conm_info.port_id = rxq->rspq.port_id;
	conm_info.iq_id = rxq->rspq.cntxt_id;	
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_SETUP_CONM_CTX_CMD, &conm_info);
	if (ret) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for CHTCP_IOCTL_SETUP_CONM_CTX_CMD: %d\n",
			    adap->pci_devname, rte_lcore_id(), ret);
		goto free_rx_bufs;
	}

	return 0;

free_rx_bufs:
	chtcp_free_rx_bufs(fl, fl->avail);

refill_fl_err:
	fri.port_id = iq->port_id;
	fri.iq_id = iq->cntxt_id;
	fri.fl_id = fl ? fl->cntxt_id : 0xffff;
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_FREE_RXQ_CMD, &fri);
	if (ret) {
		SPDK_ERRLOG("%s core[%d]:ioctl failed for CHTCP_IOCTL_FREE_RXQ: %d\n",
			    adap->pci_devname, rte_lcore_id(), ret);
	}
fl_nomem:
	ret = -ENOMEM;
err:
	iq->cntxt_id = 0;
	iq->abs_id = 0;
	if (iq->desc) {
		rte_memzone_free(iq->mz);
		iq->desc = NULL;
	}

	if (fl && fl->desc) {
		rte_free(fl->sdesc);
		fl->cntxt_id = 0;
		fl->sdesc = NULL;
		rte_memzone_free(fl->mz);
		fl->desc = NULL;
	}

	return ret;
}

static void 
free_txq(struct chtcp_sge_txq *q)
{
	q->cntxt_id = 0;
	q->sdesc = NULL;
	rte_memzone_free(q->mz);
	q->desc = NULL;
}

/**
 *   chtcp_reclaim_tx_desc - reclaims Tx descriptors and their buffers
 *   @q: the Tx queue to reclaim descriptors from
 *   @n: the number of descriptors to reclaim
 *     
 *   Reclaims Tx descriptors from an SGE Tx queue and frees the associated
 *   Tx buffers.  Called with the Tx queue lock held.
 */
static void 
chtcp_reclaim_tx_desc(struct chtcp_sge_txq *q, u32 n, u32 __cidx)
{
	struct tx_sw_desc *d;
	u32 cidx = __cidx;

	d = &q->sdesc[cidx];
	while (n--) {
		if (d->mbuf) {                       /* an SGL is present */
			rte_pktmbuf_free(d->mbuf);
			d->mbuf = NULL;
		}
		
		++d;
		if (++cidx == q->size) {
			cidx = 0;
			d = q->sdesc;
		}
		//RTE_MBUF_PREFETCH_TO_FREE(&q->sdesc->mbuf->pool);
	}
	q->cidx = cidx;
}

static void 
chtcp_free_tx_desc(struct chtcp_sge_txq *q, u32 n)
{
	chtcp_reclaim_tx_desc(q, n, 0);
}

/*
 * Return the number of reclaimable descriptors in a Tx queue.
 */
static inline int 
chtcp_reclaimable(const struct chtcp_sge_txq *q)
{
	int hw_cidx = rte_be_to_cpu_16(q->stat->cidx);

	hw_cidx -= q->cidx;
	if (hw_cidx < 0)
		return hw_cidx + q->size;
	return hw_cidx;
}

/**
 *  chtcp_reclaim_completed_tx - reclaims completed Tx descriptors
 *  @q: the Tx queue to reclaim completed descriptors from
 * 
 * Reclaims Tx descriptors that the SGE has indicated it has processed.
 */
static void 
chtcp_reclaim_completed_tx(struct chtcp_sge_txq *q)
{
	u32 avail = chtcp_reclaimable(q);

	do {
		/* reclaim as much as possible */
		chtcp_reclaim_tx_desc(q, avail, q->cidx);
		q->in_use -= avail;
		avail = chtcp_reclaimable(q);
	} while (avail);
}

void 
chtcp_usge_ofld_txq_release(struct chtcp_uadapter *adap,
			    struct chtcp_sge_ofld_txq *txq)
{
	struct chtcp_free_txq_info fti;
	int ret = 0;

	if (!txq->q.desc) {
		SPDK_ERRLOG("%s core[%d]: no desc found to be freed\n",
			adap->pci_devname, rte_lcore_id());
		return;
	}

	chtcp_reclaim_completed_tx(&txq->q);

	fti.port_id = txq->q.port_id;
	fti.eq_id = txq->q.cntxt_id;
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_FREE_TXQ_CMD, &fti);
	if (ret)
		SPDK_ERRLOG("%s core[%d]:ioctl failed for CHTCP_IOCTL_FREE_TXQ: %d\n",
			    adap->pci_devname, rte_lcore_id(), ret);

	chtcp_free_tx_desc(&txq->q, txq->q.size);

	rte_free(txq->q.sdesc);
	free_txq(&txq->q);
}

/**
 * chtcp_is_ofld_imm - can an Ethernet packet be sent as immediate data?
 * @m: the packet
 *
 * Examines whether an Ethernet packet is small enough to fit as
 * immediate data. 
 */
static inline void 
chtcp_set_if_ofld_imm(const struct rte_mbuf *mbuf)
{
/*
 * Max WR length for FW_OFLD_TX_DATA_WR in immediate only case
 * Work request header + 8-bit immediate data length
 */
#define MAX_IMM_OFLD_TX_DATA_WR_LEN (0xff + sizeof(struct fw_ofld_tx_data_wr))

	if ((mbuf->pkt_len + sizeof(struct fw_ofld_tx_data_wr))
		 <= MAX_IMM_OFLD_TX_DATA_WR_LEN) {
		chtcp_set_mbuf_flag((struct rte_mbuf *)mbuf, CHTCP_MBUF_FLAG_IMM_DATA);
	}
}

/**
 * sgl_len - calculates the size of an SGL of the given capacity
 * @n: the number of SGL entries
 *
 * Calculates the number of flits needed for a scatter/gather list that
 * can hold the given number of entries.
 */
static inline u32 sgl_len(u32 n)
{
	/*
	 * A Direct Scatter Gather List uses 32-bit lengths and 64-bit PCI DMA
	 * addresses.  The DSGL Work Request starts off with a 32-bit DSGL
	 * ULPTX header, then Length0, then Address0, then, for 1 <= i <= N,
	 * repeated sequences of { Length[i], Length[i+1], Address[i],
	 * Address[i+1] } (this ensures that all addresses are on 64-bit
	 * boundaries).  If N is even, then Length[N+1] should be set to 0 and
	 * Address[N+1] is omitted.
	 *
	 * The following calculation incorporates all of the above.  It's
	 * somewhat hard to follow but, briefly: the "+2" accounts for the
	 * first two flits which include the DSGL header, Length0 and
	 * Address0; the "(3*(n-1))/2" covers the main body of list entries (3
	 * flits for every pair of the remaining N) +1 if (n-1) is odd; and
	 * finally the "+((n-1)&1)" adds the one remaining flit needed if
	 * (n-1) is odd ...
	 */
	n--;
	return ((3 * n) / 2) + (n & 1) + 2;
}

/**
 * chtcp_calc_tx_flits_ofld - calculate the number of flits for a packet Tx WR
 * @m: the packet
 * @adap: adapter structure pointer
 *
 * Returns the number of flits needed for a Tx WR for the given Ethernet
 * packet, including the needed WR and CPL headers.
 */
static inline u32 
chtcp_calc_tx_flits_ofld(const struct rte_mbuf *m)
{
	size_t wr_size = sizeof(struct fw_ofld_tx_data_wr);
	u32 flits;

	/*
	 * If the mbuf is small enough, we can pump it out as a work request
	 * with only immediate data.  In that case we just have to have the
	 * TX Packet header plus the mbuf data in the Work Request.
	 */

	if (chtcp_test_mbuf_flag(m, CHTCP_MBUF_FLAG_IMM_DATA))
		return SPDK_CEIL_DIV(m->pkt_len + wr_size, sizeof(__be64));

	/*
	 * Otherwise, we're going to have to construct a Scatter gather list
	 * of the mbuf body and fragments.  We also include the flits necessary
	 * for the TX Packet Work Request and CPL.  We always have a firmware
	 * Write Header (incorporated as part of the cpl_tx_pkt_lso and
	 * cpl_tx_pkt structures), followed by either a TX Packet Write CPL
	 * message or, if we're doing a Large Send Offload, an LSO CPL message
	 * with an embedded TX Packet Write CPL message.
	 */
	flits = (wr_size / 8) + sgl_len(m->nb_segs);

	return flits;
}

/**
 * chtcp_write_sgl - populate a scatter/gather list for a packet
 * @mbuf: the packet
 * @q: the Tx queue we are writing into
 * @sgl: starting location for writing the SGL
 * @end: points right after the end of the SGL
 * @start: start offset into mbuf main-body data to include in the SGL
 * @addr: address of mapped region
 *
 * Generates a scatter/gather list for the buffers that make up a packet.
 * The caller must provide adequate space for the SGL that will be written.
 * The SGL includes all of the packet's page fragments and the data in its
 * main body except for the first @start bytes.  @sgl must be 16-byte
 * aligned and within a Tx descriptor with available space.  @end points
 * write after the end of the SGL but does not account for any potential
 * wrap around, i.e., @end > @sgl.
 */
static void 
chtcp_write_sgl(struct rte_mbuf *mbuf, struct chtcp_sge_txq *q,
		struct ulptx_sgl *sgl, u64 *end, u32 start,
		const dma_addr_t *addr)
{
	u32 i, len;
	struct ulptx_sge_pair *to;
	struct rte_mbuf *m = mbuf;
	u32 nfrags = m->nb_segs;
	struct ulptx_sge_pair buf[nfrags / 2];

	len = m->data_len - start;
	sgl->len0 = rte_cpu_to_be_32(len);
	sgl->addr0 = rte_cpu_to_be_64(addr[0]);

	sgl->cmd_nsge = rte_cpu_to_be_32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			      V_ULPTX_NSGE(nfrags));
	if (likely(--nfrags == 0))
		return;
	/*
	 * Most of the complexity below deals with the possibility we hit the
	 * end of the queue in the middle of writing the SGL.  For this case
	 * only we create the SGL in a temporary buffer and then copy it.
	 */
	to = (u8 *)end > (u8 *)q->stat ? buf : sgl->sge;

	for (i = 0; nfrags >= 2; nfrags -= 2, to++) {
		m = m->next;
		to->len[0] = rte_cpu_to_be_32(m->data_len);
		to->addr[0] = rte_cpu_to_be_64(addr[++i]);
		m = m->next;
		to->len[1] = rte_cpu_to_be_32(m->data_len);
		to->addr[1] = rte_cpu_to_be_64(addr[++i]);
	}
	if (nfrags) {
		m = m->next;
		to->len[0] = rte_cpu_to_be_32(m->data_len);
		to->len[1] = rte_cpu_to_be_32(0);
		to->addr[0] = rte_cpu_to_be_64(addr[i + 1]);
	}
	if (unlikely((u8 *)end > (u8 *)q->stat)) {
		u32 part0 = RTE_PTR_DIFF((u8 *)q->stat,
						  (u8 *)sgl->sge);
		u32 part1;

		if (likely(part0))
			memcpy(sgl->sge, buf, part0);
		part1 = RTE_PTR_DIFF((u8 *)end, (u8 *)q->stat);
		rte_memcpy(q->desc, RTE_PTR_ADD((u8 *)buf, part0), part1);
		end = RTE_PTR_ADD((void *)q->desc, part1);
	}
	if ((uintptr_t)end & 8)           /* 0-pad to multiple of 16 */
		*(u64 *)end = 0;
}

/**
 * chtcp_flits_to_desc - returns the num of Tx descriptors for the given flits
 * @n: the number of flits
 *
 * Returns the number of Tx descriptors needed for the supplied number
 * of flits.
 */
static inline u32 
chtcp_flits_to_desc(u32 n)
{
	return SPDK_CEIL_DIV(n, 8);
}

/**
 * chtcp_txq_avail - return the number of available slots in a Tx queue
 * @q: the Tx queue
 *
 * Returns the number of descriptors in a Tx queue available to write new
 * packets.
 */
static inline u32 
chtcp_txq_avail(const struct chtcp_sge_txq *q)
{
	return q->size - 1 - q->in_use;
}

static void map_mbuf(struct rte_mbuf *mbuf, dma_addr_t *addr)
{
	struct rte_mbuf *m = mbuf;

	for (; m; m = m->next, addr++) {
		*addr = rte_pktmbuf_iova(m);
		assert(*addr);
	}
}

static inline void 
chtcp_txq_advance(struct chtcp_sge_txq *q, u32 n)
{
	q->in_use += n;
	q->pidx += n;
	if (q->pidx >= q->size)
		q->pidx -= q->size;
}

#define PIDXDIFF(head, tail, wrap) \
        ((tail) >= (head) ? (tail) - (head) : (wrap) - (head) + (tail))
#define P_IDXDIFF(q, idx) PIDXDIFF((q)->cidx, idx, (q)->size)

#define IDXDIFF(head, tail, wrap) \
        ((head) >= (tail) ? (head) - (tail) : (wrap) - (tail) + (head))
#define Q_IDXDIFF(q, idx) IDXDIFF((q)->pidx, (q)->idx, (q)->size)
#define R_IDXDIFF(q, idx) IDXDIFF((q)->cidx, (q)->idx, (q)->size)

/**
 * chtcp_ring_tx_db - ring a Tx queue's doorbell
 * @adap: the adapter
 * @q: the Tx queue
 * @n: number of new descriptors to give to HW
 *
 * Ring the doorbel for a Tx queue.
 */
static inline void 
chtcp_ring_tx_db(struct chtcp_uadapter *adap,
	   struct chtcp_sge_txq *q)
{
	int n = Q_IDXDIFF(q, dbidx);
	u32 val = V_PIDX_T5(n);

	/*
	 * Make sure that all writes to the TX Descriptors are committed
	 * before we tell the hardware about them.
	 */
	rte_wmb();

	/*
	 * T4 and later chips share the same PIDX field offset within
	 * the doorbell, but T5 and later shrank the field in order to
	 * gain a bit for Doorbell Priority.  The field was absurdly
	 * large in the first place (14 bits) so we just use the T5
	 * and later limits and warn if a Queue ID is too large.
	 */
//	WARN_ON(val & F_DBPRIO);

	rte_write32(val | V_QID(q->bar2_qid),
		    (void *)((uintptr_t)q->bar2_addr + SGE_UDB_KDOORBELL));

	/*
	 * This Write Memory Barrier will force the write to the User
	 * Doorbell area to be flushed.  This is needed to prevent
	 * writes on different CPUs for the same queue from hitting
	 * the adapter out of order.  This is required when some Work
	 * Requests take the Write Combine Gather Buffer path (user
	 * doorbell area offset [SGE_UDB_WCDOORBELL..+63]) and some
	 * take the traditional path where we simply increment the
	 * PIDX (User Doorbell area SGE_UDB_KDOORBELL) and have the
	 * hardware DMA read the actual Work Request.
	 */
	rte_wmb();
	q->dbidx = q->pidx;
}

static void
chtcp_make_tx_data_wr(struct rte_mbuf *mbuf, struct fw_ofld_tx_data_wr *req)
{
	struct chtcp_mbuf_private *priv = CHTCP_MBUF_TO_PRIV(mbuf);
	u32 wr_ulp_mode = 0;
	u32 opcode = FW_OFLD_TX_DATA_WR;
	u32 immlen = 0;
	u32 len = mbuf->pkt_len;
	u32 fw_credits_needed = priv->credits;
	u32 compl;

	if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_COMPLETION))
		compl = 1;
	else
		compl = 0;

	if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_IMM_DATA))
		immlen += len;

	req->op_to_immdlen = rte_cpu_to_be_32(V_FW_WR_OP(opcode) |
			V_FW_WR_COMPL(compl) |
			V_FW_WR_IMMDLEN(immlen));
	req->flowid_len16 = rte_cpu_to_be_32(V_FW_WR_FLOWID(priv->tid) |
			V_FW_WR_LEN16(fw_credits_needed));
	req->plen = rte_cpu_to_be_32(len);
	wr_ulp_mode = V_TX_ULP_MODE(ULP_MODE_TCPDDP);
	req->lsodisable_to_flags = rte_cpu_to_be_32((wr_ulp_mode) |
					V_TX_SHOVE(1U));
}

/**
 * chtcp_ofld_xmit - add a packet to an ofld Tx queue
 * @txq: the egress queue
 * @mbuf: the packet
 *
 * Add a packet to an SGE Ethernet Tx queue.  Runs with softirqs disabled.
 */
static int 
chtcp_ofld_xmit_data(struct chtcp_sge_ofld_txq *txq,
		     struct rte_mbuf *mbuf)
{
	struct chtcp_mbuf_private *priv_data = CHTCP_MBUF_TO_PRIV(mbuf);
	struct chtcp_uadapter *adap;
	struct fw_ofld_tx_data_wr *wr;
	dma_addr_t addr[mbuf->nb_segs];
	u32 flits, ndesc;
	int last_desc;
	int credits;
	u64 *end;

	adap = txq->adap;

	chtcp_reclaim_completed_tx(&txq->q);

	flits = priv_data->nflits;
	ndesc = chtcp_flits_to_desc(flits);
	credits = chtcp_txq_avail(&txq->q) - ndesc;

	if (unlikely(credits < 0)) {
		SPDK_ERRLOG("%s core[%d]: Tx ring %u full; credits = %d\n",
			adap->pci_devname, rte_lcore_id(), txq->q.cntxt_id, credits);
		return -EBUSY;
	}

	map_mbuf(mbuf, addr);

	wr = (void *)&txq->q.desc[txq->q.pidx];
	end = (u64 *)wr + flits;

	chtcp_make_tx_data_wr(mbuf, wr);

	if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_IMM_DATA)) {
		u8 *buf = rte_pktmbuf_mtod(mbuf, u8 *);

		chtcp_inline_tx(&txq->q, (wr + 1), buf, mbuf->data_len);
		TAILQ_REMOVE(&txq->sendq, priv_data, link);
		rte_pktmbuf_free(mbuf);
		goto ring_db;
	}

	last_desc = txq->q.pidx + ndesc - 1;
	if (last_desc >= (int)txq->q.size)
		last_desc -= txq->q.size;

	chtcp_write_sgl(mbuf, &txq->q, (struct ulptx_sgl *)(wr + 1), end, 0,
		  addr);
	
	txq->q.sdesc[last_desc].mbuf = mbuf;
	txq->q.sdesc[last_desc].sgl = (struct ulptx_sgl *)(wr + 1);
	priv_data = CHTCP_MBUF_TO_PRIV(mbuf);
	TAILQ_REMOVE(&txq->sendq, priv_data, link);

ring_db:
	chtcp_txq_advance(&txq->q, ndesc);
	chtcp_ring_tx_db(adap, &txq->q);
	return 0;
}

static int 
chtcp_ofld_xmit_ctrl(struct chtcp_sge_ofld_txq *txq, struct rte_mbuf *mbuf)
{
	struct chtcp_uadapter *adap = txq->adap;
	struct chtcp_sge_txq *q = &txq->q;
	u32 data_len = mbuf->pkt_len;
	u32 ndesc = SPDK_CEIL_DIV(data_len, sizeof(struct tx_desc));
	u8 *buf = rte_pktmbuf_mtod(mbuf, u8 *);
	void *pos = (void *)&q->desc[q->pidx];
	struct chtcp_mbuf_private *priv_data;
	int credits;

	chtcp_reclaim_completed_tx(&txq->q);

	credits = chtcp_txq_avail(q) - ndesc;

	if (unlikely(credits < 0)) {
		SPDK_ERRLOG("%s core[%d]: Tx ring %u full; credits = %d\n",
			adap->pci_devname, rte_lcore_id(), q->cntxt_id, credits);
		return -EBUSY;
	}

	if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_COMPLETION)) {
		struct work_request_hdr *wr = rte_pktmbuf_mtod(mbuf,
						struct work_request_hdr *);
		wr->wr_hi |= rte_cpu_to_be_32(F_FW_WR_COMPL);
	}

	chtcp_inline_tx(q, pos, buf, data_len);

	priv_data = CHTCP_MBUF_TO_PRIV(mbuf);
	TAILQ_REMOVE(&txq->sendq, priv_data, link);
	rte_pktmbuf_free(mbuf);

	chtcp_txq_advance(q, ndesc);
	chtcp_ring_tx_db(adap, q);

	return 0;
}

void 
chtcp_service_ofld_txq(struct chtcp_sge_ofld_txq *txq)
{
	struct chtcp_mbuf_private *priv_data;
	struct chtcp_mbuf_private *tpriv;
	struct rte_mbuf *mbuf;
	int rc;

	TAILQ_FOREACH_SAFE(priv_data, &txq->sendq, link, tpriv){
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data);

		if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_TX_DATA))
			rc = chtcp_ofld_xmit_data(txq, mbuf);
		else
			rc = chtcp_ofld_xmit_ctrl(txq, mbuf);

		if (rc < 0)
			break;
	}
}

/**
 * chtcp_ofld_queue_xmit - queue a packet to send to ofld Tx queue
 * @txq : ofload txq
 * @mbuf: the packet
 *
 * This is second level q based on q credits
 */
void
chtcp_ofld_queue_xmit(struct chtcp_sge_ofld_txq *txq, struct rte_mbuf *mbuf)
{
	CHTCP_QUEUE_MBUF(&txq->sendq, mbuf, link);

	chtcp_service_ofld_txq(txq);
}

void 
chtcp_process_csk_sendq(struct chtcp_sock *csk)
{
	struct chtcp_mbuf_private *priv_data;
	struct chtcp_mbuf_private *tpriv;
	struct rte_mbuf *mbuf;
	u32 credits_needed;

	TAILQ_FOREACH_SAFE(priv_data, &csk->sendq, link, tpriv){
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data);

		if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_TX_DATA)) {
			chtcp_set_if_ofld_imm(mbuf);
			priv_data->nflits = chtcp_calc_tx_flits_ofld(mbuf);
			credits_needed = SPDK_CEIL_DIV((8 * priv_data->nflits), 16);
		} else {
			credits_needed = SPDK_CEIL_DIV(mbuf->pkt_len, 16);
		}

		if (csk->wr_cred < credits_needed) {
			SPDK_DEBUGLOG(chtcp, "%s core[%d]: no fw "
				      "credits: csk %p cr needed %u avail %u\n",
				      csk->adap->pci_devname, rte_lcore_id(), 
				      csk, credits_needed, csk->wr_cred);
			csk->flags |= CHTCP_CSK_FLAG_NO_WR_CREDIT;
			break;
		}

		TAILQ_REMOVE(&csk->sendq, priv_data, link);

		csk->wr_cred -= credits_needed;
		csk->wr_una_cred += credits_needed;
		CHTCP_MBUF_TO_PRIV(mbuf)->credits = credits_needed;

		if (likely(chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_TX_DATA))) {
			if (csk->wr_una_cred >= (csk->wr_max_cred / 4)) {
				chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_COMPLETION);
				csk->wr_una_cred = 0;
			}
		} else if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_COMPLETION))
			csk->wr_una_cred = 0;

		priv_data->tid = csk->tid;

		rte_pktmbuf_refcnt_update(mbuf, 1);
		CHTCP_QUEUE_MBUF(&csk->wr_ack_mbufq, mbuf, ack_link);

		chtcp_ofld_queue_xmit(csk->txq, mbuf);
	}
}

int 
chtcp_queue_tx_mbuf(struct chtcp_sock *csk, struct rte_mbuf *mbuf)
{
	if (!(csk->flags & CHTCP_CSK_FLAG_FLOWC_SENT)) {
		struct rte_mbuf *flowc_mbuf;

		csk->flags |= CHTCP_CSK_FLAG_FLOWC_SENT;
		flowc_mbuf = chtcp_get_flowc_mbuf(csk);
		CHTCP_QUEUE_MBUF(&csk->sendq, flowc_mbuf, link);
	}

	CHTCP_QUEUE_MBUF(&csk->sendq, mbuf, link);

	chtcp_process_csk_sendq(csk);

	return 0;
}

/**
 * chtcp_free_rx_bufs - free the Rx buffers on an SGE free list
 * @q: the SGE free list to free buffers from
 * @n: how many buffers to free
 * 
 * Release the next @n buffers on an SGE free-buffer Rx queue.   The
 * buffers must be made inaccessible to HW before calling this function.
 */
static void 
chtcp_free_rx_bufs(struct chtcp_sge_fl *q, int n)
{
	u32 cidx = q->cidx;
	struct rx_sw_desc *d;

	d = &q->sdesc[cidx];
	while (n--) {
		if (d->buf) {
			rte_pktmbuf_free(d->buf);
			d->buf = NULL;
		}
		++d;
		if (++cidx == q->size) {
			cidx = 0;
			d = q->sdesc;
		}
		q->avail--;
	}
	q->cidx = cidx;
}

static void
chtcp_free_rspq_fl(struct chtcp_uadapter *adap, struct chtcp_sge_rspq *rq,
	     struct chtcp_sge_fl *fl)
{
	struct chtcp_free_rxq_info fri;
	u32 fl_id = fl ? fl->cntxt_id : 0xffff;
	int ret = 0;

	if (!rq->desc) {
		SPDK_ERRLOG("%s core[%d]: no desc found to be freed\n",
			adap->pci_devname, rte_lcore_id());
		return;
	}

	fri.port_id = rq->port_id;
	fri.iq_id = rq->cntxt_id;
	fri.fl_id = fl_id;
	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_FREE_RXQ_CMD, &fri);
	if (ret) {
		SPDK_ERRLOG("%s core[%d]:ioctl failed for CHTCP_IOCTL_FREE_RXQ: %d\n", 
			adap->pci_devname, rte_lcore_id(), ret);
	}

	rq->cntxt_id = 0;
	rq->abs_id = 0;
	rte_memzone_free(rq->mz);
	rq->desc = NULL;

	if (fl) {
		chtcp_free_rx_bufs(fl, fl->avail);
		rte_free(fl->sdesc);
		fl->sdesc = NULL;
		fl->cntxt_id = 0;
		rte_memzone_free(fl->mz);
		fl->desc = NULL;
	}
}

void 
chtcp_usge_ofld_rxq_release(struct chtcp_uadapter *adap,
			    struct chtcp_sge_ofld_rxq *rxq)
{
	if (rxq->rspq.desc)
		chtcp_free_rspq_fl(adap, &rxq->rspq, &rxq->fl);
	else
		SPDK_WARNLOG("%s core[%d]: no desc found to release\n",
			adap->pci_devname, rte_lcore_id());
}

static bool
chtcp_wr_credit_err(const struct chtcp_sock *csk)
{
        struct chtcp_mbuf_private *priv_data;
        u32 credit = 0;

        if (unlikely(csk->wr_cred > csk->wr_max_cred)) {
                SPDK_ERRLOG("%s core[%d]: csk 0x%p, tid %u, credit %u > %u\n",
                        csk->adap->pci_devname, rte_lcore_id(), csk, csk->tid,
                        csk->wr_cred, csk->wr_max_cred);
                return true;
        }

        TAILQ_FOREACH(priv_data, &csk->wr_ack_mbufq, ack_link) {
                credit += priv_data->credits;
        }

        if (unlikely((csk->wr_cred + credit) != csk->wr_max_cred)) {
                SPDK_ERRLOG("%s core[%d]: csk 0x%p, tid %u, credit %u + %u "
                        "!= %u.\n", csk->adap->pci_devname, rte_lcore_id(), csk,
                        csk->tid, csk->wr_cred, credit, csk->wr_max_cred);

                return true;
        }

        return false;
}

int
chtcp_handle_cpl_fw4_ack(struct chtcp_uadapter *adap, const void *rsp)
{
        struct cpl_fw4_ack *rpl = (struct cpl_fw4_ack *)rsp;
        u32 credits = rpl->credits;
        u32 snd_una = rte_be_to_cpu_32(rpl->snd_una);
        u32 tid = GET_TID(rpl);
	u32 wr_una_cred;
        struct chtcp_sock *csk;
        struct chtcp_mbuf_private *priv;
        struct rte_mbuf *mbuf;

        csk = chtcp_lookup_tid(&adap->tids, tid);
        if (unlikely(!csk)) {
                SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
                        adap->pci_devname, rte_lcore_id(), tid);
                return -EFAULT;
        }

        csk->wr_cred += credits;
	wr_una_cred = csk->wr_max_cred - csk->wr_cred;
	if (csk->wr_una_cred > wr_una_cred)
		csk->wr_una_cred = wr_una_cred;

        csk->flags &= ~CHTCP_CSK_FLAG_NO_WR_CREDIT;

        while (credits) {
                priv = TAILQ_FIRST(&csk->wr_ack_mbufq);

                if (unlikely(!priv)) {
                        SPDK_ERRLOG("%s core[%d]: Error: csk 0x%p,%u, cr %u,%u+%u, "
                                "empty.\n", adap->pci_devname, rte_lcore_id(), csk,
                                csk->tid, credits, csk->wr_cred, csk->wr_una_cred);
                        goto wr_credit_err;
                }

                if (unlikely(credits < priv->credits)) {
                        SPDK_ERRLOG("%s core[%d]: Error: csk 0x%p,%u, cr %u,%u+%u, "
                                "< %u.\n", adap->pci_devname, rte_lcore_id(), csk,
                                csk->tid, credits, csk->wr_cred, csk->wr_una_cred, priv->credits);
                        priv->credits -= credits;
                        break;
                }

                TAILQ_REMOVE(&csk->wr_ack_mbufq, priv, ack_link);
                credits -= priv->credits;
                mbuf = CHTCP_PRIV_TO_MBUF(priv);
                rte_pktmbuf_free(mbuf);
        }

        if (unlikely(chtcp_wr_credit_err(csk))) 
                goto wr_credit_err; 

        if (rpl->flags & CPL_FW4_ACK_FLAGS_SEQVAL) {
                if (unlikely(((s32)(snd_una - csk->snd_una) < 0))) {
                        SPDK_ERRLOG("%s core[%d]: Error: csk 0x%p, tid %u, "
                                    "snd_una %u, %u\n", adap->pci_devname,
                                    rte_lcore_id(), csk, csk->tid, snd_una,
                                    csk->snd_una);
                        goto wr_credit_err; 
                }

                if (csk->snd_una != snd_una)
                        csk->snd_una = snd_una;
        }

        chtcp_process_csk_sendq(csk);

        return 0;

wr_credit_err:
	if (csk->state == CHTCP_CSK_STATE_ESTABLISHED) {
        	mbuf = chtcp_alloc_mbuf_res(csk, 0);
        	chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_DISCONNECT);
		CHTCP_QUEUE_MBUF(&csk->recvq, mbuf, link);
		chtcp_send_abort_req(csk, true);
	}

        return 0;
}

static int 
chtcp_handle_rx_data(struct chtcp_sge_ofld_rxq *rxq,
		     struct chtcp_mbuf_q  *mbufq)
{
	struct chtcp_uadapter *adap = rxq->adap;
	struct rte_mbuf *mbuf = CHTCP_MBUF_Q_FIRST(mbufq);
	struct cpl_rx_data *rpl = 
		rte_pktmbuf_mtod(mbuf, struct cpl_rx_data *);
	u32 tid = GET_TID(rpl);
	struct chtcp_sock *csk;
	u32 mbufq_data_len, data_len, seq_num; 
	struct chtcp_mbuf_private *priv_data;

	rte_pktmbuf_adj(mbuf, sizeof(struct cpl_rx_data));

	csk = chtcp_lookup_tid(&adap->tids, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
			adap->pci_devname, rte_lcore_id(), tid);
		return -EFAULT;
	}

	if (csk->state != CHTCP_CSK_STATE_ESTABLISHED)
		goto rel_mbuf;
	
	seq_num = rte_be_to_cpu_32(rpl->seq);
	data_len = rte_be_to_cpu_16(rpl->len);
	mbufq_data_len = CHTCP_MBUF_TO_PRIV(mbuf)->pkt_len - 
				sizeof(struct cpl_rx_data);

	if (unlikely((seq_num != csk->rcv_nxt) || 
		      (mbufq_data_len > data_len))) {
		SPDK_ERRLOG("%s core[%d]: TID %u: seq num 0x%x, expected 0x%x ," 
			"mbuf data_len = %u cpl len =%u\n", adap->pci_devname, 
			rte_lcore_id(), tid, seq_num, csk->rcv_nxt, 
			mbufq_data_len, data_len);

		mbuf = chtcp_alloc_mbuf_res(csk, 0);
		chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_DISCONNECT);
		CHTCP_QUEUE_MBUF(&csk->recvq, mbuf, link);
		chtcp_send_abort_req(csk, true);
		goto rel_mbuf;
	}

	csk->rcv_nxt = seq_num + data_len;
	TAILQ_CONCAT(&csk->recvq, mbufq, link);

	return 0;

rel_mbuf:
	TAILQ_FOREACH(priv_data, mbufq, link) {
		TAILQ_REMOVE(mbufq, priv_data, link);
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data);
		rte_pktmbuf_free(mbuf);
	}
	return 0;
}


static int 
chtcp_process_rspq_fl(struct chtcp_sge_ofld_rxq *rxq,
		      struct chtcp_mbuf_q  *mbufq)
{
	u8 opcode;

	opcode = *(u8 *)rxq->rspq.cur_desc;

	switch (opcode) {
	case CPL_PASS_ACCEPT_REQ:
		chtcp_handle_pass_accept_req(rxq, mbufq);
		break;
	case CPL_RX_DATA:
		chtcp_handle_rx_data(rxq, mbufq);
		break;
	default:
		SPDK_WARNLOG(" Unsupported cpl %u\n", opcode);
	}

	return 0;
}

typedef int (*chtcp_cpl_handler)(struct chtcp_uadapter *adap, const void *);

static chtcp_cpl_handler chtcp_rx_cpl_handlers[NUM_CPL_CMDS] = {
        [CPL_ABORT_RPL_RSS]     = chtcp_handle_abort_rpl_rss,
        [CPL_CLOSE_CON_RPL]     = chtcp_handle_close_con_rpl,
        [CPL_ABORT_REQ_RSS]     = chtcp_handle_abort_req_rss,
        [CPL_PEER_CLOSE]        = chtcp_handle_peer_close,
        [CPL_FW4_ACK]           = chtcp_handle_cpl_fw4_ack,
        [CPL_CLOSE_LISTSRV_RPL] = chtcp_handle_close_listsrv_rpl,
        [CPL_PASS_OPEN_RPL] = chtcp_handle_pass_open_rpl,
        [CPL_PASS_ESTABLISH] = chtcp_handle_pass_establish,
};

static int 
chtcp_process_rspq(struct chtcp_uadapter *adap,
		   struct chtcp_sge_rspq *q, const __be64 *rsp)
{
	struct rss_header *rss;
	u32 opcode;
	int rv;

	if (((const struct rss_header *)rsp)->opcode == CPL_FW4_MSG &&
	    ((const struct cpl_fw4_msg *)(rsp + 1))->type == FW_TYPE_RSSCPL)
		rsp += 2;

	rss = (struct rss_header *)rsp;
	opcode = rss->opcode;

	if (chtcp_rx_cpl_handlers[opcode])
                rv = chtcp_rx_cpl_handlers[opcode](adap, (rss + 1));
        else
		SPDK_ERRLOG("%s core[%d]: Unhandled cpl 0x%x on RXQ abs_id: %d\n",
			adap->pci_devname, rte_lcore_id(),opcode, q->abs_id);
	return rv;
}

/**
 * chtcp_process_responses - process responses from an SGE response queue
 * @q: the ingress queue to process
 * @budget: how many responses can be processed in this round
 *
 * Process responses from an SGE response queue up to the supplied budget.
 * Responses include received packets as well as control messages from FW
 * or HW.
 *
 * Additionally choose the interrupt holdoff time for the next interrupt
 * on this queue.  If the system is under memory shortage use a fairly
 * long delay to help recovery.
 */
static u32 
chtcp_process_responses(struct chtcp_sge_rspq *q, u32 budget)
{
	int rsp_type;
	u32 budget_left = budget;
	const struct rsp_ctrl *rc;
	struct chtcp_sge_ofld_rxq *rxq = SPDK_CONTAINEROF(q, struct chtcp_sge_ofld_rxq, rspq);

	while (likely(budget_left)) {
		u32 stat_pidx = rte_be_to_cpu_16(q->stat->pidx);

		if (q->cidx == stat_pidx)
			break;

		rc = (const struct rsp_ctrl *)
		     ((const char *)q->cur_desc + (q->iqe_len - sizeof(*rc)));

		/*
		 * Ensure response has been read
		 */
		rte_rmb();
		rsp_type = G_RSPD_TYPE(rc->u.type_gen);

		if (likely(rsp_type == X_RSPD_TYPE_FLBUF)) {
			u32 stat_pidx_diff;

			stat_pidx_diff = P_IDXDIFF(q, stat_pidx);
			while (stat_pidx_diff && budget_left) {
				struct chtcp_mbuf_q  mbufq;
				TAILQ_INIT(&mbufq);
				const struct rx_sw_desc *rsd =
					&rxq->fl.sdesc[rxq->fl.cidx];
				u32 len, bufsz, nmbuf=0;

				rc = (const struct rsp_ctrl *)
				     ((const char *)q->cur_desc +
				      (q->iqe_len - sizeof(*rc)));

				rsp_type = G_RSPD_TYPE(rc->u.type_gen);
				if (unlikely(rsp_type != X_RSPD_TYPE_FLBUF))
					break;

				len = rte_be_to_cpu_32(rc->pldbuflen_qid);
				assert(len & F_RSPD_NEWBUF);
				len = G_RSPD_LEN(len);
				struct rte_mbuf *mbuf = rsd->buf;
				CHTCP_MBUF_TO_PRIV(mbuf)->pkt_len = len;
				while (len) {
					struct rte_mbuf *new_mbuf = rsd->buf;

					bufsz = RTE_MIN(new_mbuf->data_len, len);
					new_mbuf->data_len = bufsz;
					new_mbuf->pkt_len = new_mbuf->data_len;
					chtcp_unmap_rx_buf(&rxq->fl);
					len -= bufsz;
					CHTCP_QUEUE_MBUF(&mbufq, new_mbuf, link);
					rsd = &rxq->fl.sdesc[rxq->fl.cidx];
					nmbuf++;
				}
				CHTCP_MBUF_TO_PRIV(mbuf)->nmbuf = nmbuf;

				chtcp_process_rspq_fl(rxq, &mbufq);
				chtcp_rspq_next(q);
				budget_left--;
				stat_pidx_diff--;
			}
			continue;
		} else if (likely(rsp_type == X_RSPD_TYPE_CPL)) {
				chtcp_process_rspq(rxq->adap, q, q->cur_desc);
		} else {
			SPDK_ERRLOG("Invalid rsp type %d\n", rsp_type);
		}

		chtcp_rspq_next(q);
		budget_left--;
	}

	/*
	 * If this is a Response Queue with an associated Free List and
	 * there's room for another chunk of new Free List buffer pointers,
	 * refill the Free List.
	 */

	if ((chtcp_fl_cap(&rxq->fl) - rxq->fl.avail) >= 16)
		__chtcp_refill_fl(rxq->adap, &rxq->fl);

	return budget - budget_left;
}

int
chtcp_poller_cb(void *ctx)
{
	struct chtcp_uadapter *adap;
	struct spdk_reactor *reactor = (struct spdk_reactor *)ctx;
	struct chtcp_sge_ofld_rxq *rxq;
	struct chtcp_sge_rspq *q;
	u32 i, p_id, r_id = reactor->r_index;
	u32 cidx_inc;
	u32 val;

	check_for_arp_failure(&CHTCP_GET_CH_REACTOR(reactor)->acsk_req_list);

	for (i = 0 ; i < g_chtcp_root.num_adapter ; i++) {
		adap = g_chtcp_root.adapter[i];
		for (p_id = 0; p_id < adap->nports; p_id++) {
			chtcp_service_ofld_txq(chtcp_get_txq(adap, p_id, r_id));
			rxq = chtcp_get_rxq(adap, p_id, r_id);
			q = &rxq->rspq;
			if (!chtcp_process_responses(q, 64))
				continue;

			cidx_inc = R_IDXDIFF(q, gts_idx);

			val = V_CIDXINC(cidx_inc) | V_SEINTARM(0);
			rte_write32(val | V_INGRESSQID(q->bar2_qid),
			(void *)((uintptr_t)q->bar2_addr + SGE_UDB_GTS));
			/* This Write memory Barrier will force the
			* write to the User Doorbell area to be
			* flushed.
			*/
			rte_wmb();
			q->gts_idx = q->cidx;
		}
	}

	return 0;
}

