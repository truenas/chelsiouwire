/*
 * Copyright (c) 2009-2021 Chelsio, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#include "iw_cxgb4.h"

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pci.h>

#include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_ioctl.h>

#include <cxgbtool.h>

static int db_delay_usecs = 1;
module_param(db_delay_usecs, int, 0644);
MODULE_PARM_DESC(db_delay_usecs, "Usecs to delay awaiting db fifo to drain");

static int ocqp_support = 1;
module_param(ocqp_support, int, 0644);
MODULE_PARM_DESC(ocqp_support, "Support on-chip SQs (default=1)");

int allow_nonroot_rawqps = 0;
module_param(allow_nonroot_rawqps, int, 0644);
MODULE_PARM_DESC(allow_nonroot_rawqps,
		 "Allow nonroot access to raw qps (default = 0)");

static int max_fr_immd = T4_MAX_FR_IMMD;
module_param(max_fr_immd, int, 0644);
MODULE_PARM_DESC(max_fr_immd, "fastreg threshold for using DSGL instead of immediate");

#ifdef ARCH_HAS_IOREMAP_WC
int t5_en_wc = 1;
#else
int t5_en_wc = 0;
#endif

module_param(t5_en_wc, int, 0644);
MODULE_PARM_DESC(t5_en_wc, "Use BAR2/WC path for kernel users (default 1)");

static int alloc_ird(struct c4iw_dev *dev, u32 ird)
{
	int ret;

	xa_lock_irq(&dev->qps);
	if (ird <= dev->avail_ird) {
		dev->avail_ird -= ird;
		ret = 0;
	} else {
		ret = -ENOMEM;
		pr_warn("%s: device IRD resources exhausted\n",
		       pci_name(dev->rdev.lldi.pdev));
	}
	xa_unlock_irq(&dev->qps);
	return ret;
}

static void free_ird(struct c4iw_dev *dev, int ird)
{
	xa_lock_irq(&dev->qps);
	dev->avail_ird += ird;
	xa_unlock_irq(&dev->qps);
}

static void set_state(struct c4iw_qp *qhp, enum c4iw_qp_state state)
{
	unsigned long flag;
	spin_lock_irqsave(&qhp->lock, flag);
	qhp->attr.state = state;
	spin_unlock_irqrestore(&qhp->lock, flag);
}

static void dealloc_oc_sq(struct c4iw_rdev *rdev, struct t4_sq *sq)
{
	cxgb4_ocqp_pool_free(rdev->lldi.ports[0], sq->dma_addr, sq->memsize);
}

static void dealloc_host_sq(struct c4iw_rdev *rdev, struct t4_sq *sq)
{
	dma_free_coherent(&(rdev->lldi.pdev->dev), sq->memsize, sq->queue,
			  dma_unmap_addr(sq, mapping));
}

static void dealloc_sq(struct c4iw_rdev *rdev, struct t4_sq *sq)
{
	if (t4_sq_onchip(sq))
		dealloc_oc_sq(rdev, sq);
	else
		dealloc_host_sq(rdev, sq);
}

static int alloc_oc_sq(struct c4iw_rdev *rdev, struct t4_sq *sq)
{
	if (!ocqp_support || !ocqp_supported(&rdev->lldi))
		return -ENOSYS;
	sq->dma_addr = cxgb4_ocqp_pool_alloc(rdev->lldi.ports[0], sq->memsize);
	if (!sq->dma_addr)
		return -ENOMEM;
	sq->phys_addr = rdev->oc_mw_pa + sq->dma_addr -
			rdev->lldi.vr->ocq.start;
	sq->queue = (__force union t4_wr *)(rdev->oc_mw_kva + sq->dma_addr -
					    rdev->lldi.vr->ocq.start);
	sq->flags |= T4_SQ_ONCHIP;
	return 0;
}

static int alloc_host_sq(struct c4iw_rdev *rdev, struct t4_sq *sq)
{
	sq->queue = dma_alloc_coherent(&(rdev->lldi.pdev->dev), sq->memsize,
				       &(sq->dma_addr), GFP_KERNEL);
	if (!sq->queue)
		return -ENOMEM;
	sq->phys_addr = virt_to_phys(sq->queue);
	dma_unmap_addr_set(sq, mapping, sq->dma_addr);
	return 0;
}

static void *alloc_ring(struct c4iw_dev *dev, size_t len, dma_addr_t *dma_addr,
			unsigned long *phys_addr, int onchip)
{
	void *p;

	if (onchip && ocqp_support && ocqp_supported(&dev->rdev.lldi)) {
		*dma_addr = cxgb4_ocqp_pool_alloc(dev->rdev.lldi.ports[0], len);
		if (!*dma_addr)
			goto offchip;
		*phys_addr = dev->rdev.oc_mw_pa + *dma_addr -
			     dev->rdev.lldi.vr->ocq.start;
		p = (void *)(dev->rdev.oc_mw_kva + *dma_addr -
			     dev->rdev.lldi.vr->ocq.start);
	} else {
offchip:
		p = dma_alloc_coherent(&dev->rdev.lldi.pdev->dev, len, dma_addr,
				       GFP_KERNEL);
		if (!p)
			return NULL;
		*phys_addr = virt_to_phys(p);
	}
	memset(p, 0, len);
	return p;
}

static int get_fid(struct c4iw_dev *dev, int count)
{
	int f;

	spin_lock_irq(&dev->lock);

	if (count == 1) {
		f = find_first_zero_bit(dev->rdev.fids, dev->rdev.nfids);
	} else {
		f = bitmap_find_next_zero_area(dev->rdev.fids, dev->rdev.nfids, 0, count, 3);
	}

	if (f >= dev->rdev.nfids)
		f = -1;
	else
		bitmap_set(dev->rdev.fids, f, count);
	spin_unlock_irq(&dev->lock);
	if (f >= 0)
		f += dev->rdev.lldi.tids->nhpftids;
	return f;
}

static int del_filter(struct c4iw_raw_qp *rqp, int filter_id)
{
	struct filter_ctx ctx;
	int ret;

	init_completion(&ctx.completion);

	rtnl_lock();
	ret = cxgb4_del_filter(rqp->netdev, filter_id, NULL, &ctx, GFP_KERNEL);
	rtnl_unlock();
	if (!ret) {
		ret = c4iw_wait(&rqp->dev->rdev, &ctx.completion);
		if (!ret)
			ret = ctx.result;
	}
	return ret;
}

static void put_fid(struct c4iw_raw_qp *rqp)
{
	int ret = 0;
	mm_segment_t oldfs;
	int i;

	oldfs = force_uaccess_begin();
	for (i = 0; i < rqp->nfids; i++) {
		do {
			int filter_id;

			filter_id = rqp->fid + i;
			ret = del_filter(rqp, filter_id);
			if (!ret) {
				filter_id += rqp->dev->rdev.nfids;
				ret = del_filter(rqp, filter_id);
			}
			if (!ret || ret != -EBUSY)
				break;
			if (c4iw_fatal_error(&rqp->dev->rdev)) {
				ret = -EIO;
				break;
			}
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(usecs_to_jiffies(500));
		} while (1);
	}
	force_uaccess_end(oldfs);

	if (ret && ret != -E2BIG)
		pr_warn("del filter %u failed ret %d\n",
		       rqp->fid, ret);
	else {
		u32 f;

		f = rqp->fid - rqp->dev->rdev.lldi.tids->nhpftids;
		spin_lock_irq(&rqp->dev->lock);
		bitmap_clear(rqp->dev->rdev.fids, f, rqp->nfids);
		spin_unlock_irq(&rqp->dev->lock);
	}
}

static void free_srq_queue(struct c4iw_srq *srq, struct c4iw_dev_ucontext *uctx,
			   struct c4iw_wr_wait *wr_waitp)
{
	struct c4iw_rdev *rdev = &srq->rhp->rdev;
	struct sk_buff *skb = srq->destroy_skb;
	struct t4_srq *wq = &srq->wq;
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	int wr_len;

	wr_len = sizeof *res_wr + sizeof *res;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.srq.restype = FW_RI_RES_TYPE_SRQ;
	res->u.srq.op = FW_RI_RES_OP_RESET;
	res->u.srq.srqid = cpu_to_be32(srq->idx);
	res->u.srq.eqid = cpu_to_be32(wq->qid);

	c4iw_init_wr_wait(wr_waitp);
	c4iw_ref_send_wait(rdev, skb, wr_waitp, 0, 0, __func__);

	dma_free_coherent(&(rdev->lldi.pdev->dev),
			  wq->memsize, wq->queue,
			  dma_unmap_addr(wq, mapping));
	c4iw_rqtpool_free(rdev, wq->rqt_hwaddr, wq->rqt_size);
	kfree(wq->sw_rq);
	c4iw_put_qpid(rdev, wq->qid, uctx);
	return;
}

static int alloc_srq_queue(struct c4iw_srq *srq, struct c4iw_dev_ucontext *uctx,
			   struct c4iw_wr_wait *wr_waitp)
{
	struct c4iw_rdev *rdev = &srq->rhp->rdev;
	int user = (uctx != &rdev->uctx);
	struct t4_srq *wq = &srq->wq;
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	struct sk_buff *skb;
	int wr_len;
	int eqsize;
	int ret = -ENOMEM;

	wq->qid = c4iw_get_qpid(rdev, uctx);
	if (!wq->qid)
		goto err;

	if (!user) {
		wq->sw_rq = kzalloc(wq->size * sizeof *wq->sw_rq,
				 GFP_KERNEL);
		if (!wq->sw_rq)
			goto err_put_qpid;
		wq->pending_wrs = kzalloc(srq->wq.size * 
			sizeof *srq->wq.pending_wrs, GFP_KERNEL);
		if (!wq->pending_wrs)
			goto err_free_sw_rq;
	}

	wq->rqt_size = wq->size;
	wq->rqt_hwaddr = c4iw_rqtpool_alloc(rdev, wq->rqt_size);
	if (!wq->rqt_hwaddr)
		goto err_free_pending_wrs;
	wq->rqt_abs_idx = (wq->rqt_hwaddr - rdev->lldi.vr->rq.start) >>
			     T4_RQT_ENTRY_SHIFT;

	wq->queue = dma_alloc_coherent(&(rdev->lldi.pdev->dev),
					  wq->memsize, &(wq->dma_addr),
					  GFP_KERNEL);
	if (!wq->queue)
		goto err_free_rqtpool;

	dma_unmap_addr_set(wq, mapping, wq->dma_addr);

	wq->bar2_va = c4iw_bar2_addrs(rdev, wq->qid, T4_BAR2_QTYPE_EGRESS,
					 &wq->bar2_qid,
					 user ? &wq->bar2_pa : NULL);

	/*
	 * User mode must have bar2 access.
	 */
	if (user && !wq->bar2_va) {
		pr_warn(MOD "%s: srqid %u not in BAR2 range.\n",
			pci_name(rdev->lldi.pdev), wq->qid);
		ret = -EINVAL;
		goto err_free_queue;
	}

	/* build fw_ri_res_wr */
	wr_len = sizeof *res_wr + sizeof *res;

	skb = alloc_skb(wr_len, GFP_KERNEL);
	if (!skb)
		goto err_free_queue;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.srq.restype = FW_RI_RES_TYPE_SRQ;
	res->u.srq.op = FW_RI_RES_OP_WRITE;

	/*
	 * eqsize is the number of 64B entries plus the status page size.
	 */
	eqsize = wq->size * T4_RQ_NUM_SLOTS +
		rdev->hw_queue.t4_eq_status_entries;
	res->u.srq.eqid = cpu_to_be32(wq->qid);
	res->u.srq.fetchszm_to_iqid = cpu_to_be32(
		V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
		V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
		V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
		V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering));
	res->u.srq.dcaen_to_eqsize = cpu_to_be32(
		V_FW_RI_RES_WR_DCAEN(0) |
		V_FW_RI_RES_WR_DCACPU(0) |
		V_FW_RI_RES_WR_FBMIN(2) |
		V_FW_RI_RES_WR_FBMAX(3) |
		V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
		V_FW_RI_RES_WR_CIDXFTHRESH(0) |
		V_FW_RI_RES_WR_EQSIZE(eqsize));
	res->u.srq.eqaddr = cpu_to_be64(wq->dma_addr);
	res->u.srq.srqid = cpu_to_be32(srq->idx);
	res->u.srq.pdid = cpu_to_be32(srq->pdid);
	res->u.srq.hwsrqsize = cpu_to_be32(wq->rqt_size);
	res->u.srq.hwsrqaddr = cpu_to_be32(wq->rqt_hwaddr -
					   rdev->lldi.vr->rq.start);

	c4iw_init_wr_wait(wr_waitp);

	ret = c4iw_ref_send_wait(rdev, skb, wr_waitp, 0, wq->qid, __func__);
	if (ret)
		goto err_free_queue;

	pr_debug("srq %u eqid %u pdid %u queue va %p pa 0x%llx\n"
		" bar2_addr %p rqt addr 0x%x size %d\n",
		srq->idx, wq->qid, srq->pdid, wq->queue,
		(u64)virt_to_phys(wq->queue), wq->bar2_va,
		wq->rqt_hwaddr, wq->rqt_size);

	return 0;
err_free_queue:
	dma_free_coherent(&(rdev->lldi.pdev->dev),
			  wq->memsize, wq->queue,
			  dma_unmap_addr(wq, mapping));
err_free_rqtpool:
	c4iw_rqtpool_free(rdev, wq->rqt_hwaddr, wq->rqt_size);
err_free_pending_wrs:
	if (!user)
		kfree(wq->pending_wrs);
err_free_sw_rq:
	if (!user)
		kfree(wq->sw_rq);
err_put_qpid:
	c4iw_put_qpid(rdev, wq->qid, uctx);
err:
	return ret;
}

static void free_raw_txq(struct c4iw_dev *dev, struct c4iw_raw_qp *rqp)
{
	struct fw_eq_eth_cmd c;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	int ret;

	pr_debug("cntxt_id %d\n", rqp->txq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_ETH_CMD_FREE | FW_LEN16(c));
	c.eqid_pkd = htonl(V_FW_EQ_ETH_CMD_EQID(rqp->txq.cntxt_id));
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       pci_name(dev->rdev.lldi.pdev), __func__, ret);
		return;
	}
	if (rqp->txq.flags & T4_SQ_ONCHIP)
		cxgb4_ocqp_pool_free(dev->rdev.lldi.ports[0], rqp->txq.dma_addr,
				     rqp->txq.memsize);
	else
		dma_free_coherent(&pdev->dev, rqp->txq.memsize, rqp->txq.desc,
				  rqp->txq.dma_addr);
}

static int alloc_raw_txq(struct c4iw_dev *dev, struct c4iw_raw_qp *rqp)
{
	int ret, nentries;
	struct fw_eq_eth_cmd c;
	struct t4_eth_txq *txq = &rqp->txq;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	struct fw_params_cmd c2;
	__be32 *p = &c2.param[0].mnem;
	u16 rid = dev->rdev.lldi.rxq_ids[cxgb4_port_idx(rqp->netdev)];

	/* Add status entries */
	nentries = txq->size * T4_TXQ_NUM_SLOTS +
		dev->rdev.hw_queue.t4_eq_status_entries;

	txq->desc = alloc_ring(dev, txq->memsize, &txq->dma_addr,
			       &txq->phys_addr, 1);
	if (!txq->desc)
		return -ENOMEM;

	if (c4iw_onchip_pa(&dev->rdev, txq->phys_addr))
		txq->flags = T4_SQ_ONCHIP;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_ETH_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_EQ_ETH_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_ETH_CMD_ALLOC |
				 F_FW_EQ_ETH_CMD_EQSTART | (sizeof(c) / 16));
	c.autoequiqe_to_viid =
		htonl(V_FW_EQ_ETH_CMD_VIID(cxgb4_port_viid(rqp->netdev)));
	c.fetchszm_to_iqid =
		htonl(V_FW_EQ_ETH_CMD_HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      (txq->flags & T4_SQ_ONCHIP ? F_FW_EQ_ETH_CMD_ONCHIP : 0) |
		      V_FW_EQ_ETH_CMD_PCIECHN(cxgb4_port_chan(rqp->netdev)) |
		      V_FW_EQ_ETH_CMD_FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_EQ_ETH_CMD_IQID(rid));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_ETH_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		      (txq->flags & T4_SQ_ONCHIP ?
			V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_256B) :
			V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_512B)) |
		      V_FW_EQ_ETH_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_ETH_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		if (rqp->txq.flags & T4_SQ_ONCHIP)
			cxgb4_ocqp_pool_free(dev->rdev.lldi.ports[0],
					     rqp->txq.dma_addr,
					     rqp->txq.memsize);
		else
			dma_free_coherent(&pdev->dev, rqp->txq.memsize,
					  rqp->txq.desc, rqp->txq.dma_addr);
		return ret;
	}

	txq->cntxt_id = G_FW_EQ_ETH_CMD_EQID(ntohl(c.eqid_pkd));

	/*
	 * Tell uP to route SGE_EGR_UPDATE CPLs to the send cq.
	 */
	memset(&c2, 0, sizeof(c));
	c2.op_to_vfn = htonl(V_FW_CMD_OP(FW_PARAMS_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | 
			    V_FW_PARAMS_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_EQ_ETH_CMD_VFN(0));
	c2.retval_len16 = htonl(FW_LEN16(c));
	*p++ = htonl(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) | 
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_CMPLIQID_CTRL) |
		V_FW_PARAMS_PARAM_YZ(txq->cntxt_id));
	*p++ = htonl(rqp->scq->cq.cqid);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c2, sizeof(c2), &c2);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error (FW_PARAMS/DMAQ_EQ_CMPLIQID_CTRL) %d\n",
		       __func__, ret);
		free_raw_txq(dev, rqp);
		return ret;
	}
	pr_debug("cntxt_id %d size %d memsize %d dma_addr "
	     "%lx phys_addr %lx\n", txq->cntxt_id, txq->size,
	     txq->memsize, (unsigned long)txq->dma_addr, txq->phys_addr);
	return 0;
}

static void stop_raw_rxq(struct c4iw_dev *dev, struct c4iw_raw_qp *rqp)
{
	struct fw_iq_cmd c;
	int ret;

	pr_debug("iq cntxt_id %d\n", rqp->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_IQ_CMD_IQSTOP | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(rqp->iq.cntxt_id);
	c.fl0id = htons(rqp->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret)
		pr_err(MOD "%s: %s mbox command failed with %d\n",
		       pci_name(dev->rdev.lldi.pdev), __func__, ret);
}

static void free_raw_rxq(struct c4iw_dev *dev, struct c4iw_raw_qp *rqp)
{
	struct fw_iq_cmd c;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	int ret;

	pr_debug("iq cntxt_id %d\n", rqp->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(rqp->iq.cntxt_id);
	c.fl0id = htons(rqp->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       pci_name(dev->rdev.lldi.pdev), __func__, ret);
		return;
	}
	dma_free_coherent(&pdev->dev, rqp->iq.memsize, rqp->iq.desc,
			  rqp->iq.dma_addr);
	dma_free_coherent(&pdev->dev, rqp->fl.memsize, rqp->fl.desc,
			  rqp->fl.dma_addr);
}

static int alloc_raw_rxq(struct c4iw_dev *dev, struct c4iw_raw_qp *rqp)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	u16 rid = dev->rdev.lldi.ciq_ids[cxgb4_port_idx(rqp->netdev)];
	struct t4_iq *iq = &rqp->iq;
	struct t4_fl *fl = &rqp->fl;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	unsigned int chip_ver;

	chip_ver = CHELSIO_CHIP_VERSION(dev->rdev.lldi.adapter_type);
	iq->desc = alloc_ring(dev, iq->memsize, &iq->dma_addr, &iq->phys_addr,
			      0);
	if (!iq->desc)
		return -ENOMEM;

	fl->size = roundup(fl->size, 8);
	fl->desc = alloc_ring(dev, fl->memsize, &fl->dma_addr, &fl->phys_addr,
			      0);
	if (!fl->desc) {
		ret = -ENOMEM;
		goto err;
	}
	flsz = fl->size / 8 + dev->rdev.hw_queue.t4_eq_status_entries;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 (sizeof(c) / 16));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(0) |
		V_FW_IQ_CMD_VIID(cxgb4_port_viid(rqp->netdev)) |
		V_FW_IQ_CMD_IQANUS(X_UPDATESCHEDULING_TIMER) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANDST(X_INTERRUPTDESTINATION_IQ) |
		V_FW_IQ_CMD_IQANDSTINDEX(rid));
	c.iqdroprss_to_iqesize = htons(
		V_FW_IQ_CMD_IQPCIECH(cxgb4_port_chan(rqp->netdev)) |
		F_FW_IQ_CMD_IQO |
		V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
		V_FW_IQ_CMD_IQESIZE(ilog2(T4_IQE_LEN) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->dma_addr);

	c.iqns_to_fl0congen =
		htonl(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      F_FW_IQ_CMD_FL0CONGEN |
		      V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_NIC) |
		      F_FW_IQ_CMD_FL0CONGCIF |
		      (fl->cong_drop ? F_FW_IQ_CMD_FL0CONGDROP : 0) |
		      V_FW_IQ_CMD_FL0FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_IQ_CMD_FL0DATARO(dev->rdev.lldi.relaxed_ordering) |
		      (fl->packed ? F_FW_IQ_CMD_FL0PACKEN : 0)|
		      F_FW_IQ_CMD_FL0PADEN);
	c.fl0dcaen_to_fl0cidxfthresh =
		htons(V_FW_IQ_CMD_FL0FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5 ?
		      X_FETCHBURSTMAX_512B : X_FETCHBURSTMAX_256B));
	c.fl0size = htons(flsz);
	c.fl0addr = cpu_to_be64(fl->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rqp->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		goto err;
	}

	iq->cntxt_id = ntohs(c.iqid);
	iq->size--;			/* subtract status entry */

	fl->cntxt_id = ntohs(c.fl0id);
	fl->avail = fl->pend_cred = 0;
	fl->pidx = fl->cidx = 0;
	fl->db = dev->rdev.lldi.db_reg;

	/* 
	 * Set the congestion management context to enable congestion control
	 * signals from SGE back to TP. This allows TP to drop on ingress when
	 * no FL bufs are available.  Otherwise the SGE can get stuck...
	 */
	if (!is_t4(dev->rdev.lldi.adapter_type)) {
		u32 v, conm;

		v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		    V_FW_PARAMS_PARAM_YZ(iq->cntxt_id);
		conm = 1 << 19; /* CngTPMode 1 */
		rtnl_lock();
		ret = cxgb4_set_params(rqp->netdev, 1, &v, &conm);
		rtnl_unlock();
		if (ret) {
			pr_err("%s set conm ctx error %d\n", __func__,
			       ret);
			free_raw_rxq(dev, rqp);
			return ret;
		}
	}

	pr_debug("fl cntxt_id %d, size %d memsize %d, "
	     "iq cntxt_id %d size %d memsize %d packed %u\n", fl->cntxt_id,
	     fl->size, fl->memsize, iq->cntxt_id, iq->size, iq->memsize, fl->packed);
	return 0;
err:
	if (iq->desc)
		dma_free_coherent(&pdev->dev, iq->memsize, iq->desc,
				  iq->dma_addr);
	if (fl && fl->desc)
		dma_free_coherent(&pdev->dev, fl->memsize, fl->desc,
				  fl->dma_addr);
	return ret;
}

static void free_raw_srq(struct c4iw_dev *dev, struct c4iw_raw_srq *srq)
{
	struct fw_iq_cmd c;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	int ret;

	pr_debug("iq cntxt_id %d\n", srq->iq.cntxt_id);
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(srq->iq.cntxt_id);
	c.fl0id = htons(srq->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(srq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: %s mbox command failed with %d\n",
		       pci_name(dev->rdev.lldi.pdev), __func__, ret);
		return;
	}
	dma_free_coherent(&pdev->dev, srq->iq.memsize, srq->iq.desc,
			  srq->iq.dma_addr);
	dma_free_coherent(&pdev->dev, srq->fl.memsize, srq->fl.desc,
			  srq->fl.dma_addr);
}

static int alloc_raw_srq(struct c4iw_dev *dev, struct c4iw_raw_srq *srq)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	u16 rid = dev->rdev.lldi.ciq_ids[cxgb4_port_idx(srq->netdev)];
	struct t4_iq *iq = &srq->iq;
	struct t4_fl *fl = &srq->fl;
	struct pci_dev *pdev = dev->rdev.lldi.pdev;
	unsigned int chip_ver;

	chip_ver = CHELSIO_CHIP_VERSION(dev->rdev.lldi.adapter_type);
	iq->desc = alloc_ring(dev, iq->memsize, &iq->dma_addr, &iq->phys_addr,
			      0);
	if (!iq->desc)
		return -ENOMEM;

	fl->size = roundup(fl->size, 8);
	fl->desc = alloc_ring(dev, fl->memsize, &fl->dma_addr, &fl->phys_addr,
			      0);
	if (!fl->desc) {
 		ret = -ENOMEM;
 		goto err;
 	}
	flsz = fl->size / 8 + dev->rdev.hw_queue.t4_eq_status_entries;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->rdev.lldi.pf) |
			    V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 (sizeof(c) / 16));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(0) |
		V_FW_IQ_CMD_VIID(cxgb4_port_viid(srq->netdev)) |
		V_FW_IQ_CMD_IQANUS(X_UPDATESCHEDULING_TIMER) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANDST(X_INTERRUPTDESTINATION_IQ) |
		V_FW_IQ_CMD_IQANDSTINDEX(rid));
	c.iqdroprss_to_iqesize = htons(
		V_FW_IQ_CMD_IQPCIECH(cxgb4_port_chan(srq->netdev)) |
		F_FW_IQ_CMD_IQO |
		V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
		V_FW_IQ_CMD_IQESIZE(ilog2(T4_IQE_LEN) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->dma_addr);

	c.iqns_to_fl0congen =
		htonl(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		      F_FW_IQ_CMD_FL0CONGEN |
		      V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_NIC) |
		      F_FW_IQ_CMD_FL0CONGCIF |
		      V_FW_IQ_CMD_FL0FETCHRO(dev->rdev.lldi.relaxed_ordering) |
		      V_FW_IQ_CMD_FL0DATARO(dev->rdev.lldi.relaxed_ordering) |
		      (fl->packed ? F_FW_IQ_CMD_FL0PACKEN : 0)|
		      F_FW_IQ_CMD_FL0PADEN);
	c.fl0dcaen_to_fl0cidxfthresh =
		htons(V_FW_IQ_CMD_FL0FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5 ?
		      X_FETCHBURSTMAX_512B : X_FETCHBURSTMAX_256B));
	c.fl0size = htons(flsz);
	c.fl0addr = cpu_to_be64(fl->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(srq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s mbox error %d\n", __func__, ret);
		goto err;
	}

	iq->cntxt_id = ntohs(c.iqid);
	iq->size--;			/* subtract status entry */

	fl->cntxt_id = ntohs(c.fl0id);
	fl->avail = fl->pend_cred = 0;
	fl->pidx = fl->cidx = 0;
	fl->db = dev->rdev.lldi.db_reg;

	/* 
	 * Set the congestion management context to enable congestion control
	 * signals from SGE back to TP. This allows TP to drop on ingress when
	 * no FL bufs are available.  Otherwise the SGE can get stuck...
	 */
	if (!is_t4(dev->rdev.lldi.adapter_type)) {
		u32 v, conm;

		v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		    V_FW_PARAMS_PARAM_YZ(iq->cntxt_id);
		conm = 1 << 19; /* CngTPMode 1 */
		rtnl_lock();
		ret = cxgb4_set_params(srq->netdev, 1, &v, &conm);
		rtnl_unlock();
		if (ret) {
			pr_err("%s set conm ctx error %d\n", __func__,
			       ret);
			free_raw_srq(dev, srq);
			return ret;
		}
	}

	pr_debug("fl cntxt_id %d, size %d memsize %d, "
	     "iq cntxt_id %d size %d memsize %d packed %u\n", fl->cntxt_id,
	     fl->size, fl->memsize, iq->cntxt_id, iq->size, iq->memsize, fl->packed);
	return 0;
err:
	if (iq->desc)
		dma_free_coherent(&pdev->dev, iq->memsize, iq->desc,
				  iq->dma_addr);
	if (fl && fl->desc)
		dma_free_coherent(&pdev->dev, fl->memsize, fl->desc,
				  fl->dma_addr);
	return ret;
}

static int free_rc_queues(struct c4iw_rdev *rdev, struct t4_wq *wq,
		      struct c4iw_dev_ucontext *uctx, int has_rq)
{
	/*
	 * uP clears EQ contexts when the connection exits rdma mode,
	 * so no need to post a RESET WR for these EQs.
	 */
	if (has_rq)
		dma_free_coherent(&(rdev->lldi.pdev->dev),
				  wq->rq.memsize, wq->rq.queue,
				  dma_unmap_addr(&wq->rq, mapping));
	dealloc_sq(rdev, &wq->sq);
	if (has_rq) {
		c4iw_rqtpool_free(rdev, wq->rq.rqt_hwaddr, wq->rq.rqt_size);
		kfree(wq->rq.sw_rq);
	}
	kfree(wq->sq.sw_sq);
	if (has_rq)
		c4iw_put_qpid(rdev, wq->rq.qid, uctx);
	c4iw_put_qpid(rdev, wq->sq.qid, uctx);
	return 0;
}

/*
 * Determine the BAR2 virtual address and qid. If pbar2_pa is not NULL,
 * then this is a user mapping so compute the page-aligned physical address
 * for mapping.
 */
void __iomem *c4iw_bar2_addrs(struct c4iw_rdev *rdev, unsigned int qid,
			      enum t4_bar2_qtype qtype,
			      unsigned int *pbar2_qid, u64 *pbar2_pa)
{
	u64 bar2_qoffset;
	int ret;

	ret = cxgb4_bar2_sge_qregs(rdev->lldi.ports[0], qid, qtype,
				   pbar2_pa ? 1 : 0,
				   &bar2_qoffset, pbar2_qid);
	if (ret)
		return NULL;

	if (pbar2_pa)
		*pbar2_pa = (rdev->bar2_pa + bar2_qoffset) & PAGE_MASK;

	if (is_t4(rdev->lldi.adapter_type))
		return NULL;

	return rdev->bar2_kva + bar2_qoffset;
}

static int alloc_rc_queues(struct c4iw_rdev *rdev, struct t4_wq *wq,
			   struct t4_cq *rcq, struct t4_cq *scq,
			   struct c4iw_dev_ucontext *uctx, int need_rq,
			   struct c4iw_wr_wait *wr_waitp)
{
	int user = (uctx != &rdev->uctx);
	struct fw_ri_res_wr *res_wr;
	struct fw_ri_res *res;
	int wr_len;
	struct sk_buff *skb;
	int ret;
	int eqsize;

	wq->sq.qid = c4iw_get_qpid(rdev, uctx);
	if (!wq->sq.qid)
		return -ENOMEM;

	if (need_rq) {
		wq->rq.qid = c4iw_get_qpid(rdev, uctx);
		if (!wq->rq.qid)
			goto err1;
	}

	if (!user) {
		wq->sq.sw_sq = kzalloc(wq->sq.size * sizeof *wq->sq.sw_sq,
				 GFP_KERNEL);
		if (!wq->sq.sw_sq)
			goto err2;

		if (need_rq) {
			wq->rq.sw_rq = kzalloc(wq->rq.size * sizeof *wq->rq.sw_rq,
					 GFP_KERNEL);
			if (!wq->rq.sw_rq)
				goto err3;
		}
	}

	if (need_rq) {

		/*
		 * RQT must be a power of 2 and at least 16 deep.
		 */
		wq->rq.rqt_size = roundup_pow_of_two(max_t(u16, wq->rq.size, 16));
		wq->rq.rqt_hwaddr = c4iw_rqtpool_alloc(rdev, wq->rq.rqt_size);
		if (!wq->rq.rqt_hwaddr)
			goto err4;
	}

	if (user) {
		if (alloc_oc_sq(rdev, &wq->sq) && alloc_host_sq(rdev, &wq->sq))
			goto err5;
	} else
		if (alloc_host_sq(rdev, &wq->sq))
			goto err5;
	memset(wq->sq.queue, 0, wq->sq.memsize);

	if (need_rq) {
		wq->rq.queue = dma_alloc_coherent(&(rdev->lldi.pdev->dev),
						  wq->rq.memsize, &(wq->rq.dma_addr),
						  GFP_KERNEL);
		if (!wq->rq.queue)
			goto err6;
		dma_unmap_addr_set(&wq->rq, mapping, wq->rq.dma_addr);
	}
	wq->db = rdev->lldi.db_reg;

	wq->sq.bar2_va = c4iw_bar2_addrs(rdev, wq->sq.qid, T4_BAR2_QTYPE_EGRESS,
					 &wq->sq.bar2_qid, 
					 user ? &wq->sq.bar2_pa : NULL);
	if (need_rq)
		wq->rq.bar2_va = c4iw_bar2_addrs(rdev, wq->rq.qid, T4_BAR2_QTYPE_EGRESS,
						 &wq->rq.bar2_qid,
						 user ? &wq->rq.bar2_pa : NULL);

	pr_debug("sq base va 0x%p pa 0x%llx rq base va 0x%p pa 0x%llx\n",
		wq->sq.queue, (u64)virt_to_phys(wq->sq.queue),
		wq->rq.queue, need_rq ? (u64)virt_to_phys(wq->rq.queue) : 0);

	/*
	 * User mode must have bar2 access.
	 */
	if (user && (!wq->sq.bar2_pa || (need_rq && !wq->rq.bar2_pa))) {
		pr_warn("%s: sqid %u or rqid %u not in BAR2 range.\n",
			pci_name(rdev->lldi.pdev), wq->sq.qid, wq->rq.qid);
		goto err7;
	}

	wq->rdev = rdev;
	wq->rq.msn = 1;

	/* build fw_ri_res_wr */
	wr_len = sizeof *res_wr + sizeof *res;
	if (need_rq)
		wr_len += sizeof *res;

	skb = alloc_skb(wr_len, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto err7;
	}
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, NCHAN);

	res_wr = (struct fw_ri_res_wr *)__skb_put(skb, wr_len);
	memset(res_wr, 0, wr_len);
	res_wr->op_nres = cpu_to_be32(
			V_FW_WR_OP(FW_RI_RES_WR) |
			V_FW_RI_RES_WR_NRES(need_rq ? 2 : 1) |
			F_FW_WR_COMPL);
	res_wr->len16_pkd = cpu_to_be32(DIV_ROUND_UP(wr_len, 16));
	res_wr->cookie = (uintptr_t)wr_waitp;
	res = res_wr->res;
	res->u.sqrq.restype = FW_RI_RES_TYPE_SQ;
	res->u.sqrq.op = FW_RI_RES_OP_WRITE;

	/*
	 * eqsize is the number of 64B entries plus the status page size.
	 */
	eqsize = wq->sq.size * T4_SQ_NUM_SLOTS +
		rdev->hw_queue.t4_eq_status_entries;

	res->u.sqrq.fetchszm_to_iqid = cpu_to_be32(
		V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
		V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
		V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
		t4_sq_onchip(&wq->sq) ? F_FW_RI_RES_WR_ONCHIP : 0 |
		V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering) | 
		V_FW_RI_RES_WR_IQID(scq->cqid));
	res->u.sqrq.dcaen_to_eqsize = cpu_to_be32(
		V_FW_RI_RES_WR_DCAEN(0) |
		V_FW_RI_RES_WR_DCACPU(0) |
		V_FW_RI_RES_WR_FBMIN(2) |
		(t4_sq_onchip(&wq->sq) ? V_FW_RI_RES_WR_FBMAX(2) : V_FW_RI_RES_WR_FBMAX(3)) |
		V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
		V_FW_RI_RES_WR_CIDXFTHRESH(0) |
		V_FW_RI_RES_WR_EQSIZE(eqsize));
	res->u.sqrq.eqid = cpu_to_be32(wq->sq.qid);
	res->u.sqrq.eqaddr = cpu_to_be64(wq->sq.dma_addr);
	if (need_rq) {
		res++;
		res->u.sqrq.restype = FW_RI_RES_TYPE_RQ;
		res->u.sqrq.op = FW_RI_RES_OP_WRITE;

		/*
		 * eqsize is the number of 64B entries plus the status page size.
		 */
		eqsize = wq->rq.size * T4_RQ_NUM_SLOTS +
			rdev->hw_queue.t4_eq_status_entries;
		res->u.sqrq.fetchszm_to_iqid = cpu_to_be32(
			V_FW_RI_RES_WR_HOSTFCMODE(0) |	/* no host cidx updates */
			V_FW_RI_RES_WR_CPRIO(0) |	/* don't keep in chip cache */
			V_FW_RI_RES_WR_PCIECHN(0) |	/* set by uP at ri_init time */
			V_FW_RI_RES_WR_FETCHRO(rdev->lldi.relaxed_ordering) | 
			V_FW_RI_RES_WR_IQID(rcq->cqid));
		res->u.sqrq.dcaen_to_eqsize = cpu_to_be32(
			V_FW_RI_RES_WR_DCAEN(0) |
			V_FW_RI_RES_WR_DCACPU(0) |
			V_FW_RI_RES_WR_FBMIN(2) |
			V_FW_RI_RES_WR_FBMAX(3) |
			V_FW_RI_RES_WR_CIDXFTHRESHO(0) |
			V_FW_RI_RES_WR_CIDXFTHRESH(0) |
			V_FW_RI_RES_WR_EQSIZE(eqsize));
		res->u.sqrq.eqid = cpu_to_be32(wq->rq.qid);
		res->u.sqrq.eqaddr = cpu_to_be64(wq->rq.dma_addr);
	}

	c4iw_init_wr_wait(wr_waitp);

	ret = c4iw_ref_send_wait(rdev, skb, wr_waitp, 0, wq->sq.qid, __func__);
	if (ret)
		goto err7;

	pr_debug("sqid 0x%x rqid 0x%x kdb 0x%p sq_bar2_addr %p rq_bar2_addr %p\n",
	     wq->sq.qid, wq->rq.qid, wq->db,
	     wq->sq.bar2_va, wq->rq.bar2_va);

	return 0;
err7:
	if (need_rq)
		dma_free_coherent(&(rdev->lldi.pdev->dev),
				  wq->rq.memsize, wq->rq.queue,
				  dma_unmap_addr(&wq->rq, mapping));
err6:
	dealloc_sq(rdev, &wq->sq);
err5:
	if (need_rq)
		c4iw_rqtpool_free(rdev, wq->rq.rqt_hwaddr, wq->rq.rqt_size);
err4:
	if (need_rq)
		kfree(wq->rq.sw_rq);
err3:
	kfree(wq->sq.sw_sq);
err2:
	if (need_rq)
		c4iw_put_qpid(rdev, wq->rq.qid, uctx);
err1:
	c4iw_put_qpid(rdev, wq->sq.qid, uctx);
	return -ENOMEM;
}

void c4iw_copy_wr_to_srq(struct t4_srq *srq, union t4_recv_wr *wqe, u8 len16)
{
	u64 *src, *dst;

	src = (u64 *)wqe;
	dst = (u64 *)((u8 *)srq->queue + srq->wq_pidx * T4_EQ_ENTRY_SIZE);
	while (len16) {
		*dst++ = *src++;
		if (dst >= (u64 *)&srq->queue[srq->size])
			dst = (u64 *)srq->queue;
		*dst++ = *src++;
		if (dst >= (u64 *)&srq->queue[srq->size])
			dst = (u64 *)srq->queue;
		len16--;
	}
}

static int build_immd(struct t4_sq *sq, struct fw_ri_immd *immdp,
		      const struct ib_send_wr *wr, int max, u32 *plenp)
{
	u8 *dstp, *srcp;
	u32 plen = 0;
	int i;
	int rem, len;

	dstp = (u8 *)immdp->data;
	for (i = 0; i < wr->num_sge; i++) {
		if ((plen + wr->sg_list[i].length) > max)
			return -EMSGSIZE;
		srcp = (u8 *)(unsigned long)wr->sg_list[i].addr;
		plen += wr->sg_list[i].length;
		rem = wr->sg_list[i].length;
		while (rem) {
			if (dstp == (u8 *)&sq->queue[sq->size])
				dstp = (u8 *)sq->queue;
			if (rem <= (u8 *)&sq->queue[sq->size] - dstp)
				len = rem;
			else
				len = (u8 *)&sq->queue[sq->size] - dstp;
			memcpy(dstp, srcp, len);
			dstp += len;
			srcp += len;
			rem -= len;
		}
	}
	len = roundup(plen + sizeof *immdp, 16) - (plen + sizeof *immdp);
	if (len)
		memset(dstp, 0, len);
	immdp->op = FW_RI_DATA_IMMD;
	immdp->r1 = 0;
	immdp->r2 = 0;
	immdp->immdlen = cpu_to_be32(plen);
	*plenp = plen;
	return 0;
}

static int build_isgl(__be64 *queue_start, __be64 *queue_end,
		      struct fw_ri_isgl *isglp, struct ib_sge *sg_list,
		      int num_sge, u32 *plenp)

{
	int i;
	u32 plen = 0;
	__be64 *flitp;

	if ((__be64 *)isglp == queue_end)
		isglp = (struct fw_ri_isgl *)queue_start;

	flitp = (__be64 *)isglp->sge;

	for (i = 0; i < num_sge; i++) {
		if ((plen + sg_list[i].length) < plen)
			return -EMSGSIZE;
		plen += sg_list[i].length;
		*flitp = cpu_to_be64(((u64)sg_list[i].lkey << 32) |
				     sg_list[i].length);
		if (++flitp == queue_end)
			flitp = queue_start;
		*flitp = cpu_to_be64(sg_list[i].addr);
		if (++flitp == queue_end)
			flitp = queue_start;
	}
	*flitp = (__force __be64)0;
	isglp->op = FW_RI_DATA_ISGL;
	isglp->r1 = 0;
	isglp->nsge = cpu_to_be16(num_sge);
	isglp->r2 = 0;
	if (plenp)
		*plenp = plen;
	return 0;
}

static int build_rdma_send(struct t4_sq *sq, union t4_wr *wqe,
			   const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	switch (wr->opcode) {
	case IB_WR_SEND:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE));
		else
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND));
		wqe->send.stag_inv = 0;
		break;
	case IB_WR_SEND_WITH_INV:
		if (wr->send_flags & IB_SEND_SOLICITED)
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_SE_INV));
		else
			wqe->send.sendop_pkd = cpu_to_be32(
				V_FW_RI_SEND_WR_SENDOP(FW_RI_SEND_WITH_INV));
		wqe->send.stag_inv = cpu_to_be32(wr->ex.invalidate_rkey);
		break;

	default:
		return -EINVAL;
	}
	wqe->send.r3 = 0;
	wqe->send.r4 = 0;

	plen = 0;
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->send.u.immd_src, wr,
					 T4_MAX_SEND_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->send + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->send.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->send + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->send.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->send.u.immd_src[0].r1 = 0;
		wqe->send.u.immd_src[0].r2 = 0;
		wqe->send.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->send + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->send.plen = cpu_to_be32(plen);
	return 0;
}

static int build_rdma_write(struct t4_sq *sq, union t4_wr *wqe,
			    const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;
	int ret;

	if (wr->num_sge > T4_MAX_SEND_SGE)
		return -EINVAL;
	if (wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM)
		wqe->write.immd_data = wr->ex.imm_data;
	else
		wqe->write.immd_data = 0;
	wqe->write.stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wqe->write.to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->num_sge) {
		if (wr->send_flags & IB_SEND_INLINE) {
			ret = build_immd(sq, wqe->write.u.immd_src, wr,
					 T4_MAX_WRITE_INLINE, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->write + sizeof(struct fw_ri_immd) +
			       plen;
		} else {
			ret = build_isgl((__be64 *)sq->queue,
					 (__be64 *)&sq->queue[sq->size],
					 wqe->write.u.isgl_src,
					 wr->sg_list, wr->num_sge, &plen);
			if (ret)
				return ret;
			size = sizeof wqe->write + sizeof(struct fw_ri_isgl) +
			       wr->num_sge * sizeof(struct fw_ri_sge);
		}
	} else {
		wqe->write.u.immd_src[0].op = FW_RI_DATA_IMMD;
		wqe->write.u.immd_src[0].r1 = 0;
		wqe->write.u.immd_src[0].r2 = 0;
		wqe->write.u.immd_src[0].immdlen = 0;
		size = sizeof wqe->write + sizeof(struct fw_ri_immd);
		plen = 0;
	}
	*len16 = DIV_ROUND_UP(size, 16);
	wqe->write.plen = cpu_to_be32(plen);
	return 0;
}

static void build_immd_cmpl(struct t4_sq *sq, struct fw_ri_immd_cmpl *immdp,
			   const struct ib_send_wr *wr)
{
	memcpy((u8 *)immdp->data, (u8 *)(uintptr_t)wr->sg_list->addr, 16);
	memset(immdp->r1, 0, 6);
	immdp->op = FW_RI_DATA_IMMD;
	immdp->immdlen = 16;
	return;
}

static void build_rdma_write_cmpl(struct t4_sq *sq,
				  struct fw_ri_rdma_write_cmpl_wr *wcwr,
				  const struct ib_send_wr *wr, u8 *len16)
{
	u32 plen;
	int size;

	/*
	 * This code assumes the struct fields preceeding the write isgl
	 * fit in one 64B WR slot.  This is because the WQE is built
	 * directly in the dma queue, and wrapping is only handled
	 * by the code buildling sgls.  IE the "fixed part" of the wr
	 * structs must all fit in 64B.  The WQE build code should probably be
	 * redesigned to avoid this restriction, but for now just add
	 * the BUILD_BUG_ON() to catch if this WQE struct gets too big.
	 */
	BUILD_BUG_ON(offsetof(struct fw_ri_rdma_write_cmpl_wr, u) > 64);

	wcwr->stag_sink = cpu_to_be32(rdma_wr(wr)->rkey);
	wcwr->to_sink = cpu_to_be64(rdma_wr(wr)->remote_addr);
	if (wr->next->opcode == IB_WR_SEND)
		wcwr->stag_inv = 0;
	else
		wcwr->stag_inv = cpu_to_be32(wr->next->ex.invalidate_rkey);
	wcwr->r2 = 0;
	wcwr->r3 = 0;

 	/* SEND_INV SGL */
	if (wr->next->send_flags & IB_SEND_INLINE)
		build_immd_cmpl(sq, &wcwr->u_cmpl.immd_src, wr->next);
	else
		build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
			   &wcwr->u_cmpl.isgl_src, wr->next->sg_list, 1, NULL);

	/* WRITE SGL */
	build_isgl((__be64 *)sq->queue, (__be64 *)&sq->queue[sq->size],
		   wcwr->u.isgl_src, wr->sg_list, wr->num_sge, &plen);

	size = sizeof *wcwr + sizeof(struct fw_ri_isgl) +
	       wr->num_sge * sizeof(struct fw_ri_sge);
	wcwr->plen = cpu_to_be32(plen);
	*len16 = DIV_ROUND_UP(size, 16);

	return;
}

static int build_rdma_read(union t4_wr *wqe, const struct ib_send_wr *wr, u8 *len16)
{
	if (wr->num_sge > 1)
		return -EINVAL;
	if (wr->num_sge && wr->sg_list[0].length) {
		wqe->read.stag_src = cpu_to_be32(rdma_wr(wr)->rkey);
		wqe->read.to_src_hi = cpu_to_be32((u32)(rdma_wr(wr)->remote_addr
							>> 32));
		wqe->read.to_src_lo = cpu_to_be32((u32)rdma_wr(wr)->remote_addr);
		wqe->read.stag_sink = cpu_to_be32(wr->sg_list[0].lkey);
		wqe->read.plen = cpu_to_be32(wr->sg_list[0].length);
		wqe->read.to_sink_hi = cpu_to_be32((u32)(wr->sg_list[0].addr
							 >> 32));
		wqe->read.to_sink_lo = cpu_to_be32((u32)(wr->sg_list[0].addr));
	} else {
		wqe->read.stag_src = cpu_to_be32(2);
		wqe->read.to_src_hi = 0;
		wqe->read.to_src_lo = 0;
		wqe->read.stag_sink = cpu_to_be32(2);
		wqe->read.plen = 0;
		wqe->read.to_sink_hi = 0;
		wqe->read.to_sink_lo = 0;
	}
	wqe->read.r2 = 0;
	wqe->read.r5 = 0;
	*len16 = DIV_ROUND_UP(sizeof wqe->read, 16);
	return 0;
}

static int build_rdma_recv(struct t4_wq *wq, union t4_recv_wr *wqe,
			   const struct ib_recv_wr *wr, u8 *len16)
{
	int ret;

	ret = build_isgl((__be64 *)wq->rq.queue,
			 (__be64 *)&wq->rq.queue[wq->rq.size],
			 &wqe->recv.isgl, wr->sg_list, wr->num_sge, NULL);
	if (ret)
		return ret;
	*len16 = DIV_ROUND_UP(sizeof wqe->recv +
			      wr->num_sge * sizeof(struct fw_ri_sge), 16);
	return 0;
}

static int build_srq_recv(union t4_recv_wr *wqe, const struct ib_recv_wr *wr,
			  u8 *len16)
{
	int ret;

	ret = build_isgl((__be64 *)wqe, (__be64 *)(wqe + 1),
			 &wqe->recv.isgl, wr->sg_list, wr->num_sge, NULL);
	if (ret)
		return ret;
	*len16 = DIV_ROUND_UP(sizeof wqe->recv +
			      wr->num_sge * sizeof(struct fw_ri_sge), 16);
	return 0;
}

static int build_tpte_memreg(struct fw_ri_fr_nsmr_tpte_wr *fr,
			     const struct ib_reg_wr *wr, struct c4iw_mr *mhp,
			     u8 *len16)
{
	__be64 *p = (__be64 *)fr->pbl;

	if (wr->mr->page_size > T6_MAX_PAGE_SIZE)
		return -EINVAL;
	fr->r2 = cpu_to_be32(0);
	fr->stag = cpu_to_be32(mhp->ibmr.rkey);

	fr->tpte.valid_to_pdid = cpu_to_be32(F_FW_RI_TPTE_VALID |
		V_FW_RI_TPTE_STAGKEY((mhp->ibmr.rkey & M_FW_RI_TPTE_STAGKEY)) |
		V_FW_RI_TPTE_STAGSTATE(1) |
		V_FW_RI_TPTE_STAGTYPE(FW_RI_STAG_NSMR) |
		V_FW_RI_TPTE_PDID(mhp->attr.pdid));
	fr->tpte.locread_to_qpid = cpu_to_be32(
		V_FW_RI_TPTE_PERM(c4iw_ib_to_tpt_access(wr->access)) |
		V_FW_RI_TPTE_ADDRTYPE(FW_RI_VA_BASED_TO) |
		V_FW_RI_TPTE_PS(ilog2(wr->mr->page_size) - 12));
	fr->tpte.nosnoop_pbladdr = cpu_to_be32(V_FW_RI_TPTE_PBLADDR(
		PBL_OFF(&mhp->rhp->rdev, mhp->attr.pbl_addr)>>3));
	fr->tpte.dca_mwbcnt_pstag = cpu_to_be32(0);
	fr->tpte.len_hi = cpu_to_be32(mhp->ibmr.length >> 32);
	fr->tpte.len_lo = cpu_to_be32(mhp->ibmr.length & 0xffffffff);
	fr->tpte.va_hi = cpu_to_be32(mhp->ibmr.iova >> 32);
	fr->tpte.va_lo_fbo = cpu_to_be32(mhp->ibmr.iova & 0xffffffff);

	p[0] = cpu_to_be64((u64)mhp->mpl[0]);
	p[1] = cpu_to_be64((u64)mhp->mpl[1]);

	*len16 = DIV_ROUND_UP(sizeof(*fr), 16);
	return 0;
}

static int build_memreg(struct t4_sq *sq, union t4_wr *wqe,
			const struct ib_reg_wr *wr, struct c4iw_mr *mhp,
			u8 *len16, bool dsgl_supported)
{
	struct fw_ri_immd *imdp;
	__be64 *p;
	int i;
	int pbllen = roundup(mhp->mpl_len * sizeof(u64), 32);
	int rem;

	if (mhp->mpl_len > t4_max_fr_depth(use_dsgl && dsgl_supported))
		return -EINVAL;
	if (wr->mr->page_size > T6_MAX_PAGE_SIZE)
		return -EINVAL;

	wqe->fr.qpbinde_to_dcacpu = 0;
	wqe->fr.pgsz_shift = ilog2(wr->mr->page_size) - 12;
	wqe->fr.addr_type = FW_RI_VA_BASED_TO;
	wqe->fr.mem_perms = c4iw_ib_to_tpt_access(wr->access);
	wqe->fr.len_hi = cpu_to_be32(mhp->ibmr.length >> 32);
	wqe->fr.len_lo = cpu_to_be32(mhp->ibmr.length & 0xffffffff);
	wqe->fr.stag = cpu_to_be32(wr->key);
	wqe->fr.va_hi = cpu_to_be32(mhp->ibmr.iova >> 32);
	wqe->fr.va_lo_fbo = cpu_to_be32(mhp->ibmr.iova &
					0xffffffff);

	if (dsgl_supported && use_dsgl && (pbllen > max_fr_immd)) {
		struct fw_ri_dsgl *sglp;

		for (i = 0; i < mhp->mpl_len; i++)
			mhp->mpl[i] = (__force u64)cpu_to_be64((u64)mhp->mpl[i]);

		sglp = (struct fw_ri_dsgl *)(&wqe->fr + 1);
		sglp->op = FW_RI_DATA_DSGL;
		sglp->r1 = 0;
		sglp->nsge = cpu_to_be16(1);
		sglp->addr0 = cpu_to_be64(mhp->mpl_addr);
		sglp->len0 = cpu_to_be32(pbllen);

		*len16 = DIV_ROUND_UP(sizeof(wqe->fr) + sizeof(*sglp), 16);
	} else {
		imdp = (struct fw_ri_immd *)(&wqe->fr + 1);
		imdp->op = FW_RI_DATA_IMMD;
		imdp->r1 = 0;
		imdp->r2 = 0;
		imdp->immdlen = cpu_to_be32(pbllen);
		p = (__be64 *)(imdp + 1);
		rem = pbllen;
		for (i = 0; i < mhp->mpl_len; i++) {
			*p = cpu_to_be64((u64)mhp->mpl[i]);
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		while (rem) {
			*p = 0;
			rem -= sizeof(*p);
			if (++p == (__be64 *)&sq->queue[sq->size])
				p = (__be64 *)sq->queue;
		}
		*len16 = DIV_ROUND_UP(sizeof(wqe->fr) + sizeof(*imdp)
				      + pbllen, 16);
	}
	return 0;
}

static int build_inv_stag(union t4_wr *wqe, const struct ib_send_wr *wr,
			  u8 *len16)
{
	wqe->inv.stag_inv = cpu_to_be32(wr->ex.invalidate_rkey);
	wqe->inv.r2 = 0;
	*len16 = DIV_ROUND_UP(sizeof wqe->inv, 16);
	return 0;
}

void c4iw_qp_add_ref(struct ib_qp *qp)
{
	pr_debug("ib_qp %p\n", qp);
	switch (qp->qp_type) {
	case IB_QPT_RC:
		refcount_inc(&to_c4iw_qp(qp)->qp_refcnt);
		break;
	case IB_QPT_RAW_ETH:
		atomic_inc(&(to_c4iw_raw_qp(qp)->refcnt));
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", qp->qp_type);
	}
}

void c4iw_qp_rem_ref(struct ib_qp *qp)
{
	pr_debug("ib_qp %p\n", qp);
	switch (qp->qp_type) {
	case IB_QPT_RC:
		if (refcount_dec_and_test(&to_c4iw_qp(qp)->qp_refcnt))
			complete(&to_c4iw_qp(qp)->qp_rel_comp);
		break;
	case IB_QPT_RAW_ETH:
		if (atomic_dec_and_test(&(to_c4iw_raw_qp(qp)->refcnt)))
			wake_up(&(to_c4iw_raw_qp(qp)->wait));
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", qp->qp_type);
	}
}

static void add_to_fc_list(struct list_head *head, struct list_head *entry)
{
	if (list_empty(entry))
		list_add_tail(entry, head);
}

static int ring_kernel_txq_db(struct c4iw_raw_qp *rqp, u16 inc)
{
	unsigned long flags;

	spin_lock_irqsave(&rqp->dev->lock, flags);
	if (rqp->dev->db_state == NORMAL)
		writel(V_QID(rqp->txq.cntxt_id) | V_PIDX(inc),
		       rqp->dev->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&rqp->dev->db_fc_list, &rqp->fcl.db_fc_entry);
		rqp->txq.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&rqp->dev->lock, flags);
	return 0;
}

static int ring_kernel_sq_db(struct c4iw_qp *qhp, u16 inc)
{
	unsigned long flags;

	xa_lock_irqsave(&qhp->rhp->qps, flags);
	spin_lock(&qhp->lock);
	if (qhp->rhp->db_state == NORMAL)
		t4_ring_sq_db(&qhp->wq, inc, NULL);
	else {
		add_to_fc_list(&qhp->rhp->db_fc_list, &qhp->fcl.db_fc_entry);
		qhp->wq.sq.wq_pidx_inc += inc;
	}
	spin_unlock(&qhp->lock);
	xa_unlock_irqrestore(&qhp->rhp->qps, flags);
	return 0;
}

static int ring_kernel_fl_db(struct c4iw_raw_qp *rqp, u16 inc)
{
	unsigned long flags;
	u32 val = 0;

	switch (CHELSIO_CHIP_VERSION(rqp->dev->rdev.lldi.adapter_type)) {
	case CHELSIO_T4:
		val = V_PIDX(inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		/* Fall through */
	case CHELSIO_T6:
	default:
		val |= V_PIDX_T5(inc);
		break;
	}

	spin_lock_irqsave(&rqp->dev->lock, flags);
	if (rqp->dev->db_state == NORMAL)
		writel(V_QID(rqp->fl.cntxt_id) | val,
		       rqp->dev->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&rqp->dev->db_fc_list, &rqp->fcl.db_fc_entry);
		rqp->fl.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&rqp->dev->lock, flags);
	return 0;
}

static int ring_kernel_srq_db(struct c4iw_raw_srq *srq, u16 inc)
{
	unsigned long flags;
	u32 val = 0;

	switch (CHELSIO_CHIP_VERSION(srq->dev->rdev.lldi.adapter_type)) {
	case CHELSIO_T4:
		val = V_PIDX(inc) | F_DBPRIO;
		break;
	case CHELSIO_T5:
		val = F_DBPRIO;
		/* Fall through */
	case CHELSIO_T6:
	default:
		val |= V_PIDX_T5(inc);
		break;
	}

	spin_lock_irqsave(&srq->dev->lock, flags);
	if (srq->dev->db_state == NORMAL)
		writel(V_QID(srq->fl.cntxt_id) | val,
		       srq->dev->rdev.lldi.db_reg);
	else {
		add_to_fc_list(&srq->dev->db_fc_list, &srq->fcl.db_fc_entry);
		srq->fl.pidx_inc += inc;
	}
	spin_unlock_irqrestore(&srq->dev->lock, flags);
	return 0;
}

static int ring_kernel_rq_db(struct c4iw_qp *qhp, u16 inc)
{
	unsigned long flags;

	xa_lock_irqsave(&qhp->rhp->qps, flags);
	spin_lock(&qhp->lock);
	if (qhp->rhp->db_state == NORMAL)
		t4_ring_rq_db(&qhp->wq, inc, NULL);
	else {
		add_to_fc_list(&qhp->rhp->db_fc_list, &qhp->fcl.db_fc_entry);
		qhp->wq.rq.wq_pidx_inc += inc;
	}
	spin_unlock(&qhp->lock);
	xa_unlock_irqrestore(&qhp->rhp->qps, flags);
	return 0;
}

static int ib_to_fw_opcode(int ib_opcode)
{
	int opcode;

	switch (ib_opcode) {
	case IB_WR_SEND_WITH_INV:
		opcode = FW_RI_SEND_WITH_INV;
		break;
	case IB_WR_SEND:
		opcode = FW_RI_SEND;
		break;
	case IB_WR_RDMA_WRITE:
		opcode = FW_RI_RDMA_WRITE;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		opcode = FW_RI_WRITE_IMMEDIATE;
		break;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_READ_WITH_INV:
		opcode = FW_RI_READ_REQ;
		break;
	case IB_WR_REG_MR:
		opcode = FW_RI_FAST_REGISTER;
		break;
	case IB_WR_LOCAL_INV:
		opcode = FW_RI_LOCAL_INV;
		break;
	default:
		opcode = -EINVAL;
	}
	return opcode;
}

static int complete_sq_drain_wr(struct c4iw_qp *qhp,
				const struct ib_send_wr *wr)
{
	struct t4_cqe cqe = {};
	struct c4iw_cq *schp;
	unsigned long flag;
	struct t4_cq *cq;
	int opcode;

	schp = to_c4iw_cq(qhp->ibqp.send_cq);
	cq = &schp->cq;

	opcode = ib_to_fw_opcode(wr->opcode);
	if (opcode < 0)
		return opcode;

	pr_debug("drain sq id %u\n", qhp->wq.sq.qid);
	cqe.u.drain_cookie = wr->wr_id;
	cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
				 V_CQE_OPCODE(opcode) |
				 V_CQE_TYPE(1) |
				 V_CQE_SWCQE(1) |
				 V_CQE_DRAIN(1) |
				 V_CQE_QPID(qhp->wq.sq.qid));

	spin_lock_irqsave(&schp->lock, flag);
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	spin_unlock_irqrestore(&schp->lock, flag);

	if (t4_clear_cq_armed(&schp->cq, qhp->ibqp.uobject)) {
		spin_lock_irqsave(&schp->comp_handler_lock, flag);
		(*schp->ibcq.comp_handler)(&schp->ibcq,
					   schp->ibcq.cq_context);
		spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
	}
	return 0;
}

static int complete_sq_drain_wrs(struct c4iw_qp *qhp, const struct ib_send_wr *wr,
				 const struct ib_send_wr **bad_wr)
{
	int ret = 0;

	while (wr) {
		ret = complete_sq_drain_wr(qhp, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}
	return ret;
}

static void complete_rq_drain_wr(struct c4iw_qp *qhp,
				 const struct ib_recv_wr *wr)
{
	struct t4_cqe cqe = {};
	struct c4iw_cq *rchp;
	unsigned long flag;
	struct t4_cq *cq;

	rchp = to_c4iw_cq(qhp->ibqp.recv_cq);
	cq = &rchp->cq;

	pr_debug("drain rq id %u\n", qhp->wq.sq.qid);
	cqe.u.drain_cookie = wr->wr_id;
	cqe.header = cpu_to_be32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
				 V_CQE_OPCODE(FW_RI_SEND) |
				 V_CQE_TYPE(0) |
				 V_CQE_SWCQE(1) |
				 V_CQE_DRAIN(1) |
				 V_CQE_QPID(qhp->wq.sq.qid));

	spin_lock_irqsave(&rchp->lock, flag);
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	spin_unlock_irqrestore(&rchp->lock, flag);

	if (t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject)) {
		spin_lock_irqsave(&rchp->comp_handler_lock, flag);
		(*rchp->ibcq.comp_handler)(&rchp->ibcq,
					   rchp->ibcq.cq_context);
		spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
	}
}

static void complete_rq_drain_wrs(struct c4iw_qp *qhp,
				  const struct ib_recv_wr *wr)
{
	while (wr) {
		complete_rq_drain_wr(qhp, wr);
		wr = wr->next;
	}
}

static void post_write_cmpl(struct c4iw_qp *qhp, const struct ib_send_wr *wr)
{
	bool send_signaled = (wr->next->send_flags & IB_SEND_SIGNALED) ||
			     qhp->sq_sig_all;
	bool write_signaled = (wr->send_flags & IB_SEND_SIGNALED) ||
			      qhp->sq_sig_all;
	struct t4_swsqe *swsqe;
	union t4_wr *wqe;
	u16 write_wrid;
	u8 len16;
	u16 idx;

	/*
	 * The sw_sq entries still look like a WRITE and a SEND and consume
	 * 2 slots. The FW WR, however, will be a single uber-WR.
	 */
	wqe = (union t4_wr *)((u8 *)qhp->wq.sq.queue +
	      qhp->wq.sq.wq_pidx * T4_EQ_ENTRY_SIZE);
	build_rdma_write_cmpl(&qhp->wq.sq, &wqe->write_cmpl, wr, &len16);

	/* WRITE swsqe */
	swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
	swsqe->opcode = FW_RI_RDMA_WRITE;
	swsqe->idx = qhp->wq.sq.pidx;
	swsqe->complete = 0;
	swsqe->signaled = write_signaled;
	swsqe->flushed = 0;
	swsqe->wr_id = wr->wr_id;
	if (c4iw_wr_log) {
		swsqe->sge_ts =
			cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
		swsqe->host_time = ktime_get();
	}

	write_wrid = qhp->wq.sq.pidx;

	/* just bump the sw_sq */
	qhp->wq.sq.in_use++;
	if (++qhp->wq.sq.pidx == qhp->wq.sq.size)
		qhp->wq.sq.pidx = 0;

	/* SEND_WITH_INV swsqe */
	swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
	if (wr->next->opcode == IB_WR_SEND)
		swsqe->opcode = FW_RI_SEND;
	else
		swsqe->opcode = FW_RI_SEND_WITH_INV;
	swsqe->idx = qhp->wq.sq.pidx;
	swsqe->complete = 0;
	swsqe->signaled = send_signaled;
	swsqe->flushed = 0;
	swsqe->wr_id = wr->next->wr_id;
	if (c4iw_wr_log) {
		swsqe->sge_ts =
			cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
		swsqe->host_time = ktime_get();
	}

	wqe->write_cmpl.flags_send = send_signaled ? FW_RI_COMPLETION_FLAG : 0;
	wqe->write_cmpl.wrid_send = qhp->wq.sq.pidx;

	init_wr_hdr(wqe, write_wrid, FW_RI_RDMA_WRITE_CMPL_WR,
		    write_signaled ? FW_RI_COMPLETION_FLAG : 0, len16);
	t4_sq_produce(&qhp->wq, len16);
	idx = DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);

	t4_ring_sq_db(&qhp->wq, idx, wqe);
	return;
}

static int post_rc_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			const struct ib_send_wr **bad_wr)
{
	int err = 0;
	u8 len16 = 0;
	enum fw_wr_opcodes fw_opcode = 0;
	enum fw_ri_wr_flags fw_flags;
	struct c4iw_qp *qhp;
	union t4_wr *wqe = NULL;
	u32 num_wrs;
	struct t4_swsqe *swsqe;
	unsigned long flag;
	u16 idx = 0;

	qhp = to_c4iw_qp(ibqp);
	spin_lock_irqsave(&qhp->lock, flag);

	/*
	 * If the qp has been flushed, then just insert a special
	 * drain cqe.
	 */
	if (qhp->wq.flushed) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		err = complete_sq_drain_wrs(qhp, wr, bad_wr);
		return err;
	}
	num_wrs = t4_sq_avail(&qhp->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		*bad_wr = wr;
		return -ENOMEM;
	}

	/*
	 * Fastpath for NVMe-oF target WRITE + SEND_WITH_INV wr chain which is
	 * the response for small NVMEe-oF READ requests.  If the chain is
	 * exactly a WRITE->SEND_WITH_INV or a WRITE->SEND and the sgl depths 
	 * and lengths meet the requirements of the fw_ri_write_cmpl_wr work 
	 * request, then build and post the write_cmpl WR. If any of the tests 
	 * below are not true, then we continue on with the tradtional WRITE
	 * and SEND WRs.
	 */
	if (qhp->rhp->rdev.lldi.write_cmpl_support &&
	    CHELSIO_CHIP_VERSION(qhp->rhp->rdev.lldi.adapter_type) >=
	    CHELSIO_T5 &&
	    wr && wr->next && !wr->next->next &&
	    wr->opcode == IB_WR_RDMA_WRITE &&
	    wr->sg_list[0].length && wr->num_sge <= T4_WRITE_CMPL_MAX_SGL &&
	    (wr->next->opcode == IB_WR_SEND ||
	    wr->next->opcode == IB_WR_SEND_WITH_INV) &&
	    wr->next->num_sge == 1 && num_wrs >= 2) {
		post_write_cmpl(qhp, wr);
		spin_unlock_irqrestore(&qhp->lock, flag);
		return 0;
	}

	while (wr) {
		if (num_wrs == 0) {
			err = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		wqe = (union t4_wr *)((u8 *)qhp->wq.sq.queue +
		      qhp->wq.sq.wq_pidx * T4_EQ_ENTRY_SIZE);

		fw_flags = 0;
		if (wr->send_flags & IB_SEND_SOLICITED)
			fw_flags |= FW_RI_SOLICITED_EVENT_FLAG;
		if (wr->send_flags & IB_SEND_SIGNALED || qhp->sq_sig_all)
			fw_flags |= FW_RI_COMPLETION_FLAG;
		swsqe = &qhp->wq.sq.sw_sq[qhp->wq.sq.pidx];
		switch (wr->opcode) {
		case IB_WR_SEND_WITH_INV:
		case IB_WR_SEND:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_READ_FENCE_FLAG;
			fw_opcode = FW_RI_SEND_WR;
			if (wr->opcode == IB_WR_SEND)
				swsqe->opcode = FW_RI_SEND;
			else
				swsqe->opcode = FW_RI_SEND_WITH_INV;
			err = build_rdma_send(&qhp->wq.sq, wqe, wr, &len16);
			break;
		case IB_WR_RDMA_WRITE_WITH_IMM:
			if (unlikely(!qhp->rhp->rdev.lldi.write_w_imm_support)) {
				err = -ENOSYS;
				break;
			}
			fw_flags |= FW_RI_RDMA_WRITE_WITH_IMMEDIATE;
			/*FALLTHROUGH*/
		case IB_WR_RDMA_WRITE:
			fw_opcode = FW_RI_RDMA_WRITE_WR;
			swsqe->opcode = FW_RI_RDMA_WRITE;
			err = build_rdma_write(&qhp->wq.sq, wqe, wr, &len16);
			break;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_READ_WITH_INV:
			fw_opcode = FW_RI_RDMA_READ_WR;
			swsqe->opcode = FW_RI_READ_REQ;
			if (wr->opcode == IB_WR_RDMA_READ_WITH_INV) {
				c4iw_invalidate_mr(qhp->rhp,
						   wr->sg_list[0].lkey);
				fw_flags = FW_RI_RDMA_READ_INVALIDATE;
			} else {
				fw_flags = 0;
			}
			err = build_rdma_read(wqe, wr, &len16);
			if (err)
				break;
			swsqe->read_len = wr->sg_list[0].length;
			if (!qhp->wq.sq.oldest_read)
				qhp->wq.sq.oldest_read = swsqe;
			break;
		case IB_WR_REG_MR: {
			struct c4iw_mr *mhp = to_c4iw_mr(reg_wr(wr)->mr);

			swsqe->opcode = FW_RI_FAST_REGISTER;
			if (qhp->rhp->rdev.lldi.fr_nsmr_tpte_wr_support &&
			    !mhp->attr.state && mhp->mpl_len <= 2) {
				fw_opcode = FW_RI_FR_NSMR_TPTE_WR;
				err = build_tpte_memreg(&wqe->fr_tpte, reg_wr(wr),
							mhp, &len16);
			} else {
				fw_opcode = FW_RI_FR_NSMR_WR;
				err = build_memreg(&qhp->wq.sq, wqe, reg_wr(wr),
				       mhp, &len16,
				       qhp->rhp->rdev.lldi.ulptx_memwrite_dsgl);
			}
			if (err)
				break;
			mhp->attr.state = 1;
			break;
		}
		case IB_WR_LOCAL_INV:
			if (wr->send_flags & IB_SEND_FENCE)
				fw_flags |= FW_RI_LOCAL_FENCE_FLAG;
			fw_opcode = FW_RI_INV_LSTAG_WR;
			swsqe->opcode = FW_RI_LOCAL_INV;
			err = build_inv_stag(wqe, wr, &len16);
			c4iw_invalidate_mr(qhp->rhp, wr->ex.invalidate_rkey);
			break;
		default:
			pr_debug("post of type=%d TBD!\n",
			     wr->opcode);
			err = -EINVAL;
		}
		if (err) {
			*bad_wr = wr;
			break;
		}
		swsqe->idx = qhp->wq.sq.pidx;
		swsqe->complete = 0;
		swsqe->signaled = (wr->send_flags & IB_SEND_SIGNALED) ||
				  qhp->sq_sig_all;
		swsqe->flushed = 0;
		swsqe->wr_id = wr->wr_id;
		if (c4iw_wr_log) {
			swsqe->sge_ts =
				cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
			swsqe->host_time = ktime_get();
		}

		init_wr_hdr(wqe, qhp->wq.sq.pidx, fw_opcode, fw_flags, len16);

		pr_debug("cookie 0x%llx pidx 0x%x opcode 0x%x read_len %u\n",
		     (unsigned long long)wr->wr_id, qhp->wq.sq.pidx,
		     swsqe->opcode, swsqe->read_len);
		wr = wr->next;
		num_wrs--;
		t4_sq_produce(&qhp->wq, len16);
		idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
	}
	if (!qhp->rhp->rdev.status_page->db_off) {
		t4_ring_sq_db(&qhp->wq, idx, wqe);
		spin_unlock_irqrestore(&qhp->lock, flag);
	} else {
		spin_unlock_irqrestore(&qhp->lock, flag);
		ring_kernel_sq_db(qhp, idx);
	}
	return err;
}

int c4iw_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		   const struct ib_send_wr **bad_wr)
{
	int ret = 0;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
		ret = post_rc_send(ibqp, wr, bad_wr);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static int post_rc_receive(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct c4iw_qp *qhp;
	union t4_recv_wr *wqe = NULL;
	u32 num_wrs;
	u8 len16 = 0;
	unsigned long flag;
	u16 idx = 0;

	qhp = to_c4iw_qp(ibqp);
	spin_lock_irqsave(&qhp->lock, flag);

	/*
	 * If the qp has been flushed, then just insert a special
	 * drain cqe.
	 */
	if (qhp->wq.flushed) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		complete_rq_drain_wrs(qhp, wr);
		return err;
	}
	num_wrs = t4_rq_avail(&qhp->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&qhp->lock, flag);
		*bad_wr = wr;
		return -ENOMEM;
	}
	while (wr) {
		if (wr->num_sge > T4_MAX_RECV_SGE) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}
		wqe = (union t4_recv_wr *)((u8 *)qhp->wq.rq.queue +
					   qhp->wq.rq.wq_pidx *
					   T4_EQ_ENTRY_SIZE);
		if (num_wrs)
			err = build_rdma_recv(&qhp->wq, wqe, wr, &len16);
		else
			err = -ENOMEM;
		if (err) {
			*bad_wr = wr;
			break;
		}

		qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].wr_id = wr->wr_id;
		if (c4iw_wr_log) {
			qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].sge_ts =
				cxgb4_read_sge_timestamp(qhp->rhp->rdev.lldi.ports[0]);
			qhp->wq.rq.sw_rq[qhp->wq.rq.pidx].host_time = ktime_get();
		}

		wqe->recv.opcode = FW_RI_RECV_WR;
		wqe->recv.r1 = 0;
		wqe->recv.wrid = qhp->wq.rq.pidx;
		wqe->recv.r2[0] = 0;
		wqe->recv.r2[1] = 0;
		wqe->recv.r2[2] = 0;
		wqe->recv.len16 = len16;
		pr_debug("cookie 0x%llx pidx %u\n",
		     (unsigned long long) wr->wr_id, qhp->wq.rq.pidx);
		t4_rq_produce(&qhp->wq, len16);
		idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
		wr = wr->next;
		num_wrs--;
	}
	if (!qhp->rhp->rdev.status_page->db_off) {
		t4_ring_rq_db(&qhp->wq, idx, wqe);
		spin_unlock_irqrestore(&qhp->lock, flag);
	} else {
		spin_unlock_irqrestore(&qhp->lock, flag);
		ring_kernel_rq_db(qhp, idx);
	}
	return err;
}

int c4iw_post_receive(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	int ret = 0;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
		ret = post_rc_receive(ibqp, wr, bad_wr);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static void defer_srq_wr(struct t4_srq *srq, union t4_recv_wr *wqe,
			 uint64_t wr_id, u8 len16)
{
	struct t4_srq_pending_wr *pwr = &srq->pending_wrs[srq->pending_pidx];

	pr_debug("cidx %u pidx %u wq_pidx %u in_use %u ooo_count %u wr_id "
		"0x%llx pending_cidx %u pending_pidx %u pending_in_use %u\n",
		srq->cidx, srq->pidx, srq->wq_pidx,
		srq->in_use, srq->ooo_count, (unsigned long long)wr_id,
		srq->pending_cidx, srq->pending_pidx, srq->pending_in_use);
	pwr->wr_id = wr_id;
	pwr->len16 = len16;
	memcpy(&pwr->wqe, wqe, len16*16);
	t4_srq_produce_pending_wr(srq);
}

int c4iw_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct c4iw_srq *srq;
	union t4_recv_wr *wqe, lwqe;
	u32 num_wrs;
	u8 len16 = 0;
	u16 idx = 0;
	unsigned long flag;

	srq = to_c4iw_srq(ibsrq);
	spin_lock_irqsave(&srq->lock, flag);
	num_wrs = t4_srq_avail(&srq->wq);
	if (num_wrs == 0) {
		spin_unlock_irqrestore(&srq->lock, flag);
		return -ENOMEM;
	}
	while (wr) {
		if (wr->num_sge > T4_MAX_RECV_SGE) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}
		wqe = &lwqe;
		if (num_wrs)
			err = build_srq_recv(wqe, wr, &len16);
		else
			err = -ENOMEM;
		if (err) {
			*bad_wr = wr;
			break;
		}

		wqe->recv.opcode = FW_RI_RECV_WR;
		wqe->recv.r1 = 0;
		wqe->recv.wrid = srq->wq.pidx;
		wqe->recv.r2[0] = 0;
		wqe->recv.r2[1] = 0;
		wqe->recv.r2[2] = 0;
		wqe->recv.len16 = len16;

		if (srq->wq.ooo_count || srq->wq.pending_in_use || srq->wq.sw_rq[srq->wq.pidx].valid)
			defer_srq_wr(&srq->wq, wqe, wr->wr_id, len16);
		else {
			srq->wq.sw_rq[srq->wq.pidx].wr_id = wr->wr_id;
			srq->wq.sw_rq[srq->wq.pidx].valid = 1;
			c4iw_copy_wr_to_srq(&srq->wq, wqe, len16);
			pr_debug("cidx %u pidx %u wq_pidx %u in_use %u "
				"wr_id 0x%llx \n", srq->wq.cidx,
				srq->wq.pidx, srq->wq.wq_pidx, srq->wq.in_use,
				(unsigned long long)wr->wr_id);
			t4_srq_produce(&srq->wq, len16);
			idx += DIV_ROUND_UP(len16*16, T4_EQ_ENTRY_SIZE);
		}
		wr = wr->next;
		num_wrs--;
	}
	if (idx)
		t4_ring_srq_db(&srq->wq, idx, len16, wqe);
	spin_unlock_irqrestore(&srq->lock, flag);
	return err;
}

static inline void build_term_codes(struct t4_cqe *err_cqe, u8 *layer_type,
				    u8 *ecode)
{
	int status;
	int tagged;
	int opcode;
	int rqtype;
	int send_inv;

	if (!err_cqe) {
		*layer_type = LAYER_RDMAP|DDP_LOCAL_CATA;
		*ecode = 0;
		return;
	}

	status = CQE_STATUS(err_cqe);
	opcode = CQE_OPCODE(err_cqe);
	rqtype = RQ_TYPE(err_cqe);
	send_inv = (opcode == FW_RI_SEND_WITH_INV) ||
		   (opcode == FW_RI_SEND_WITH_SE_INV);
	tagged = (opcode == FW_RI_RDMA_WRITE) ||
		 (rqtype && (opcode == FW_RI_READ_RESP));

	switch (status) {
	case T4_ERR_STAG:
		if (send_inv) {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
			*ecode = RDMAP_CANT_INV_STAG;
		} else {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
			*ecode = RDMAP_INV_STAG;
		}
		break;
	case T4_ERR_PDID:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		if ((opcode == FW_RI_SEND_WITH_INV) ||
		    (opcode == FW_RI_SEND_WITH_SE_INV))
			*ecode = RDMAP_CANT_INV_STAG;
		else
			*ecode = RDMAP_STAG_NOT_ASSOC;
		break;
	case T4_ERR_QPID:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_STAG_NOT_ASSOC;
		break;
	case T4_ERR_ACCESS:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_ACC_VIOL;
		break;
	case T4_ERR_WRAP:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
		*ecode = RDMAP_TO_WRAP;
		break;
	case T4_ERR_BOUND:
		if (tagged) {
			*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
			*ecode = DDPT_BASE_BOUNDS;
		} else {
			*layer_type = LAYER_RDMAP|RDMAP_REMOTE_PROT;
			*ecode = RDMAP_BASE_BOUNDS;
		}
		break;
	case T4_ERR_INVALIDATE_SHARED_MR:
	case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_CANT_INV_STAG;
		break;
	case T4_ERR_ECC:
	case T4_ERR_ECC_PSTAG:
	case T4_ERR_INTERNAL_ERR:
		*layer_type = LAYER_RDMAP|RDMAP_LOCAL_CATA;
		*ecode = 0;
		break;
	case T4_ERR_OUT_OF_RQE:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MSN_NOBUF;
		break;
	case T4_ERR_PBL_ADDR_BOUND:
		*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
		*ecode = DDPT_BASE_BOUNDS;
		break;
	case T4_ERR_CRC:
		*layer_type = LAYER_MPA|DDP_LLP;
		*ecode = MPA_CRC_ERR;
		break;
	case T4_ERR_MARKER:
		*layer_type = LAYER_MPA|DDP_LLP;
		*ecode = MPA_MARKER_ERR;
		break;
	case T4_ERR_PDU_LEN_ERR:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_MSG_TOOBIG;
		break;
	case T4_ERR_DDP_VERSION:
		if (tagged) {
			*layer_type = LAYER_DDP|DDP_TAGGED_ERR;
			*ecode = DDPT_INV_VERS;
		} else {
			*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
			*ecode = DDPU_INV_VERS;
		}
		break;
	case T4_ERR_RDMA_VERSION:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_INV_VERS;
		break;
	case T4_ERR_OPCODE:
		*layer_type = LAYER_RDMAP|RDMAP_REMOTE_OP;
		*ecode = RDMAP_INV_OPCODE;
		break;
	case T4_ERR_DDP_QUEUE_NUM:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_QN;
		break;
	case T4_ERR_MSN:
	case T4_ERR_MSN_GAP:
	case T4_ERR_MSN_RANGE:
	case T4_ERR_IRD_OVERFLOW:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MSN_RANGE;
		break;
	case T4_ERR_TBIT:
		*layer_type = LAYER_DDP|DDP_LOCAL_CATA;
		*ecode = 0;
		break;
	case T4_ERR_MO:
		*layer_type = LAYER_DDP|DDP_UNTAGGED_ERR;
		*ecode = DDPU_INV_MO;
		break;
	default:
		*layer_type = LAYER_RDMAP|DDP_LOCAL_CATA;
		*ecode = 0;
		break;
	}
}

static void post_terminate(struct c4iw_qp *qhp, struct t4_cqe *err_cqe,
			   gfp_t gfp)
{
	struct fw_ri_wr *wqe;
	struct sk_buff *skb;
	struct terminate_message *term;

	pr_debug("qhp %p qid 0x%x tid %u\n", qhp, qhp->wq.sq.qid,
	     qhp->ep->hwtid);

	skb = skb_dequeue(&qhp->ep->com.ep_skb_list);

	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->ep->txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(V_FW_WR_OP(FW_RI_WR));
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(qhp->ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));

	wqe->u.terminate.type = FW_RI_TYPE_TERMINATE;
	wqe->u.terminate.immdlen = cpu_to_be32(sizeof *term);
	term = (struct terminate_message *)wqe->u.terminate.termmsg;
	if (qhp->attr.layer_etype == (LAYER_MPA|DDP_LLP)) {
		term->layer_etype = qhp->attr.layer_etype;
		term->ecode = qhp->attr.ecode;
	} else
		build_term_codes(err_cqe, &term->layer_etype, &term->ecode);
	c4iw_ofld_send(&qhp->rhp->rdev, skb);
}

static void flush_raw_qp(struct c4iw_raw_qp *rqp)
{
	pr_debug("\n");
	return;
}

static int raw_init(struct c4iw_raw_qp *rqp)
{
	pr_debug("\n");
	return 0;
}

static int raw_fini(struct c4iw_raw_qp *rqp)
{
	pr_debug("\n");
	return 0;
}

static int modify_raw_qp(struct c4iw_raw_qp *rqp,
			 enum c4iw_qp_attr_mask mask,
			 struct c4iw_qp_attributes *attrs)
{
	int ret = 0;

	mutex_lock(&rqp->mutex);

	if (mask & C4IW_QP_ATTR_SQ_DB) {
		ret = ring_kernel_txq_db(rqp, attrs->sq_db_inc);
		goto out;
	}
	if (mask & C4IW_QP_ATTR_RQ_DB) {
		ret = ring_kernel_fl_db(rqp, attrs->rq_db_inc);
		goto out;
	}

	if (!(mask & C4IW_QP_ATTR_NEXT_STATE))
		goto out;
	if (rqp->state == attrs->next_state)
		goto out;

	switch (rqp->state) {
	case C4IW_QP_STATE_IDLE:
		switch (attrs->next_state) {
		case C4IW_QP_STATE_RTS:
			rqp->state = C4IW_QP_STATE_RTS;
			raw_init(rqp);
			break;
		case C4IW_QP_STATE_ERROR:
			flush_raw_qp(rqp);
			rqp->state = C4IW_QP_STATE_ERROR;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case C4IW_QP_STATE_RTS:
		switch (attrs->next_state) {
		case C4IW_QP_STATE_ERROR:
			raw_fini(rqp);
			flush_raw_qp(rqp);
			rqp->state = C4IW_QP_STATE_ERROR;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case C4IW_QP_STATE_ERROR:
		switch (attrs->next_state) {
		case C4IW_QP_STATE_IDLE:
			rqp->state = C4IW_QP_STATE_IDLE;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	default:
		pr_err("%s in a bad state %d\n",
		       __func__, rqp->state);
		ret = -EINVAL;
		goto out;
	}
out:
	mutex_unlock(&rqp->mutex);
	return ret;
}

/*
 * Assumes qhp lock is held.
 */
static void __flush_qp(struct c4iw_qp *qhp, struct c4iw_cq *rchp,
		       struct c4iw_cq *schp)
{
	int count;
	int rq_flushed = 0;
	int sq_flushed = 0;
	unsigned long flag;

	pr_debug("qhp %p rchp %p schp %p\n", qhp, rchp, schp);

	/* locking heirarchy: cqs lock first, then qp lock. */
	spin_lock_irqsave(&rchp->lock, flag);
	if (schp != rchp)
		 spin_lock(&schp->lock);
	spin_lock(&qhp->lock);
	
	if (qhp->wq.flushed) {
		spin_unlock(&qhp->lock);
		if (schp != rchp)
			spin_unlock(&schp->lock);
		spin_unlock_irqrestore(&rchp->lock, flag);
		return;
	}
	qhp->wq.flushed = 1;
	t4_set_wq_in_error(&qhp->wq, 0);

	c4iw_flush_hw_cq(rchp, qhp);
	if (!qhp->srq) {
		c4iw_count_rcqes(&rchp->cq, &qhp->wq, &count);
		rq_flushed = c4iw_flush_rq(&qhp->wq, &rchp->cq, count);
	}
	if (schp != rchp)
		c4iw_flush_hw_cq(schp, qhp);
	sq_flushed = c4iw_flush_sq(qhp);

	spin_unlock(&qhp->lock);
	if (schp != rchp)
		spin_unlock(&schp->lock);
	spin_unlock_irqrestore(&rchp->lock, flag);
	if (schp == rchp) {
		if ((rq_flushed || sq_flushed) &&
		    t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject) &&
		    rchp->ibcq.comp_handler) {
			spin_lock_irqsave(&rchp->comp_handler_lock, flag);
			(*rchp->ibcq.comp_handler)(&rchp->ibcq,
						   rchp->ibcq.cq_context);
			spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		}
	} else {
		if (rq_flushed && t4_clear_cq_armed(&rchp->cq, qhp->ibqp.uobject) &&
		    rchp->ibcq.comp_handler) {
			spin_lock_irqsave(&rchp->comp_handler_lock, flag);
			(*rchp->ibcq.comp_handler)(&rchp->ibcq,
						   rchp->ibcq.cq_context);
			spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		}
		if (sq_flushed && t4_clear_cq_armed(&schp->cq, qhp->ibqp.uobject) &&
		    schp->ibcq.comp_handler) {
			spin_lock_irqsave(&schp->comp_handler_lock, flag);
			(*schp->ibcq.comp_handler)(&schp->ibcq,
						   schp->ibcq.cq_context);
			spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
		}
	}
}

static void flush_qp(struct c4iw_qp *qhp)
{
	struct c4iw_cq *rchp, *schp;
	unsigned long flag;

	rchp = to_c4iw_cq(qhp->ibqp.recv_cq);
	schp = to_c4iw_cq(qhp->ibqp.send_cq);

	if (qhp->ibqp.uobject) {

		/* qhp->wq.flush is protected by qhp->mutex */
		if (qhp->wq.flushed)
			return;

		qhp->wq.flushed = 1;
		t4_set_wq_in_error(&qhp->wq, 0);
		t4_set_cq_in_error(&rchp->cq);
		spin_lock_irqsave(&rchp->comp_handler_lock, flag);
		(*rchp->ibcq.comp_handler)(&rchp->ibcq, rchp->ibcq.cq_context);
		spin_unlock_irqrestore(&rchp->comp_handler_lock, flag);
		if (schp != rchp) {
			t4_set_cq_in_error(&schp->cq);
			spin_lock_irqsave(&schp->comp_handler_lock, flag);
			(*schp->ibcq.comp_handler)(&schp->ibcq,
						   schp->ibcq.cq_context);
			spin_unlock_irqrestore(&schp->comp_handler_lock, flag);
		}
		return;
	}
	__flush_qp(qhp, rchp, schp);
}

static int rdma_fini(struct c4iw_dev *rhp, struct c4iw_qp *qhp,
		     struct c4iw_ep *ep)
{
	struct fw_ri_wr *wqe;
	int ret;
	struct sk_buff *skb;

	pr_debug("qhp %p qid 0x%x tid %u\n", qhp, qhp->wq.sq.qid,
	     ep->hwtid);

	skb = skb_dequeue(&ep->com.ep_skb_list);

	set_wr_txq(skb, CPL_PRIORITY_DATA, ep->txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(
		V_FW_WR_OP(FW_RI_WR) |
		F_FW_WR_COMPL);
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));
	wqe->cookie = (uintptr_t)ep->com.wr_waitp;

	wqe->u.fini.type = FW_RI_TYPE_FINI;
	ret = c4iw_ref_send_wait(&rhp->rdev, skb, ep->com.wr_waitp,
				 qhp->ep->hwtid, qhp->wq.sq.qid, __func__);
	
	pr_debug("ret %d\n", ret);
	return ret;
}

static void build_rtr_msg(u8 p2p_type, struct fw_ri_init *init)
{
	pr_debug("p2p_type = %d\n", p2p_type);
	memset(&init->u, 0, sizeof init->u);
	switch (p2p_type) {
	case FW_RI_INIT_P2PTYPE_RDMA_WRITE:
		init->u.write.opcode = FW_RI_RDMA_WRITE_WR;
		init->u.write.stag_sink = cpu_to_be32(1);
		init->u.write.to_sink = cpu_to_be64(1);
		init->u.write.u.immd_src[0].op = FW_RI_DATA_IMMD;
		init->u.write.len16 = DIV_ROUND_UP(sizeof init->u.write +
						   sizeof(struct fw_ri_immd),
						   16);
		break;
	case FW_RI_INIT_P2PTYPE_READ_REQ:
		init->u.write.opcode = FW_RI_RDMA_READ_WR;
		init->u.read.stag_src = cpu_to_be32(1);
		init->u.read.to_src_lo = cpu_to_be32(1);
		init->u.read.stag_sink = cpu_to_be32(1);
		init->u.read.to_sink_lo = cpu_to_be32(1);
		init->u.read.len16 = DIV_ROUND_UP(sizeof init->u.read, 16);
		break;
	}
}

static int rdma_init(struct c4iw_dev *rhp, struct c4iw_qp *qhp)
{
	struct fw_ri_wr *wqe;
	int ret;
	struct sk_buff *skb;

	pr_debug("qhp %p qid 0x%x tid %u ird %u ord %u\n", qhp,
	     qhp->wq.sq.qid, qhp->ep->hwtid, qhp->ep->ird, qhp->ep->ord);

	skb = alloc_skb(sizeof *wqe, GFP_KERNEL | __GFP_NOFAIL);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = alloc_ird(rhp, qhp->attr.max_ird);
	if (ret) {
		qhp->attr.max_ird = 0;
		kfree_skb(skb);
		goto out;
	}
	set_wr_txq(skb, CPL_PRIORITY_DATA, qhp->ep->txq_idx);

	wqe = (struct fw_ri_wr *)__skb_put(skb, sizeof(*wqe));
	memset(wqe, 0, sizeof *wqe);
	wqe->op_compl = cpu_to_be32(
		V_FW_WR_OP(FW_RI_WR) |
		F_FW_WR_COMPL);
	wqe->flowid_len16 = cpu_to_be32(
		V_FW_WR_FLOWID(qhp->ep->hwtid) |
		V_FW_WR_LEN16(DIV_ROUND_UP(sizeof *wqe, 16)));
	wqe->cookie = (uintptr_t)qhp->ep->com.wr_waitp;

	wqe->u.init.type = FW_RI_TYPE_INIT;
	wqe->u.init.mpareqbit_p2ptype =
		V_FW_RI_WR_MPAREQBIT(qhp->attr.mpa_attr.initiator) |
		V_FW_RI_WR_P2PTYPE(qhp->attr.mpa_attr.p2p_type);
	wqe->u.init.mpa_attrs = FW_RI_MPA_IETF_ENABLE;
	if (qhp->attr.mpa_attr.recv_marker_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_RX_MARKER_ENABLE;
	if (qhp->attr.mpa_attr.xmit_marker_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_TX_MARKER_ENABLE;
	if (qhp->attr.mpa_attr.crc_enabled)
		wqe->u.init.mpa_attrs |= FW_RI_MPA_CRC_ENABLE;

	wqe->u.init.qp_caps = FW_RI_QP_RDMA_READ_ENABLE |
			    FW_RI_QP_RDMA_WRITE_ENABLE |
			    FW_RI_QP_BIND_ENABLE;
	if (!qhp->ibqp.uobject)
		wqe->u.init.qp_caps |= FW_RI_QP_FAST_REGISTER_ENABLE |
				     FW_RI_QP_STAG0_ENABLE;
	wqe->u.init.nrqe = cpu_to_be16(t4_rqes_posted(&qhp->wq));
	wqe->u.init.pdid = cpu_to_be32(qhp->attr.pd);
	wqe->u.init.qpid = cpu_to_be32(qhp->wq.sq.qid);
	wqe->u.init.sq_eqid = cpu_to_be32(qhp->wq.sq.qid);
	if (qhp->srq)
		wqe->u.init.rq_eqid = cpu_to_be32(FW_RI_INIT_RQEQID_SRQ |
						  qhp->srq->idx);
	else {
		wqe->u.init.rq_eqid = cpu_to_be32(qhp->wq.rq.qid);
		wqe->u.init.hwrqsize = cpu_to_be32(qhp->wq.rq.rqt_size);
		wqe->u.init.hwrqaddr = cpu_to_be32(qhp->wq.rq.rqt_hwaddr -
						   rhp->rdev.lldi.vr->rq.start);
	}
	wqe->u.init.scqid = cpu_to_be32(qhp->attr.scq);
	wqe->u.init.rcqid = cpu_to_be32(qhp->attr.rcq);
	wqe->u.init.ord_max = cpu_to_be32(qhp->attr.max_ord);
	wqe->u.init.ird_max = cpu_to_be32(qhp->attr.max_ird);
	wqe->u.init.iss = cpu_to_be32(qhp->ep->snd_seq);
	wqe->u.init.irs = cpu_to_be32(qhp->ep->rcv_seq);
	if (qhp->attr.mpa_attr.initiator)
		build_rtr_msg(qhp->attr.mpa_attr.p2p_type, &wqe->u.init);

	ret = c4iw_ref_send_wait(&rhp->rdev, skb, qhp->ep->com.wr_waitp,
				 qhp->ep->hwtid, qhp->wq.sq.qid, __func__);

	if (!ret)
		goto out;

	free_ird(rhp, qhp->attr.max_ird);
out:
	pr_debug("ret %d\n", ret);
	return ret;
}

int c4iw_modify_rc_qp(struct c4iw_qp *qhp, enum c4iw_qp_attr_mask mask,
		      struct c4iw_qp_attributes *attrs, int internal)
{
	int ret = 0;
	struct c4iw_qp_attributes newattr = qhp->attr;
	int disconnect = 0;
	int terminate = 0;
	int abort = 0;
	int free = 0;
	struct c4iw_ep *ep = NULL;
	struct c4iw_dev *rhp = qhp->rhp;

	pr_debug("qhp %p sqid 0x%x rqid 0x%x ep %p state %d -> %d\n",
	     qhp, qhp->wq.sq.qid, qhp->wq.rq.qid, qhp->ep, qhp->attr.state,
	     (mask & C4IW_QP_ATTR_NEXT_STATE) ? attrs->next_state : -1);

	mutex_lock(&qhp->mutex);

	/* Process attr changes if in IDLE */
	if (mask & C4IW_QP_ATTR_VALID_MODIFY) {
		if (qhp->attr.state != C4IW_QP_STATE_IDLE) {
			ret = -EIO;
			goto out;
		}
		if (mask & C4IW_QP_ATTR_ENABLE_RDMA_READ)
			newattr.enable_rdma_read = attrs->enable_rdma_read;
		if (mask & C4IW_QP_ATTR_ENABLE_RDMA_WRITE)
			newattr.enable_rdma_write = attrs->enable_rdma_write;
		if (mask & C4IW_QP_ATTR_ENABLE_RDMA_BIND)
			newattr.enable_bind = attrs->enable_bind;
		if (mask & C4IW_QP_ATTR_MAX_ORD) {
			if (attrs->max_ord > c4iw_max_read_depth) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ord = attrs->max_ord;
		}
		if (mask & C4IW_QP_ATTR_MAX_IRD) {
			if (attrs->max_ird > cur_max_read_depth(rhp)) {
				ret = -EINVAL;
				goto out;
			}
			newattr.max_ird = attrs->max_ird;
		}
		qhp->attr = newattr;
	}

	if (mask & C4IW_QP_ATTR_SQ_DB) {
		ret = ring_kernel_sq_db(qhp, attrs->sq_db_inc);
		goto out;
	}
	if (mask & C4IW_QP_ATTR_RQ_DB) {
		ret = ring_kernel_rq_db(qhp, attrs->rq_db_inc);
		goto out;
	}

	if (!(mask & C4IW_QP_ATTR_NEXT_STATE))
		goto out;
	if (qhp->attr.state == attrs->next_state)
		goto out;

	switch (qhp->attr.state) {
	case C4IW_QP_STATE_IDLE:
		switch (attrs->next_state) {
		case C4IW_QP_STATE_RTS:
			if (!(mask & C4IW_QP_ATTR_LLP_STREAM_HANDLE)) {
				ret = -EINVAL;
				goto out;
			}
			if (!(mask & C4IW_QP_ATTR_MPA_ATTR)) {
				ret = -EINVAL;
				goto out;
			}
			qhp->attr.mpa_attr = attrs->mpa_attr;
			qhp->attr.llp_stream_handle = attrs->llp_stream_handle;
			qhp->ep = qhp->attr.llp_stream_handle;
			set_state(qhp, C4IW_QP_STATE_RTS);

			/*
			 * Ref the endpoint here and deref when we
			 * disassociate the endpoint from the QP.  This
			 * happens in CLOSING->IDLE transition or *->ERROR
			 * transition.
			 */
			c4iw_get_ep(&qhp->ep->com);
			ret = rdma_init(rhp, qhp);
			if (ret)
				goto err;
			break;
		case C4IW_QP_STATE_ERROR:
			set_state(qhp, C4IW_QP_STATE_ERROR);
			flush_qp(qhp);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case C4IW_QP_STATE_RTS:
		switch (attrs->next_state) {
		case C4IW_QP_STATE_CLOSING:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, C4IW_QP_STATE_CLOSING);
			ep = qhp->ep;
			if (!internal) {
				abort = 0;
				disconnect = 1;
				c4iw_get_ep(&qhp->ep->com);
			}
			ret = rdma_fini(rhp, qhp, ep);
			if (ret)
				goto err;
			break;
		case C4IW_QP_STATE_TERMINATE:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, C4IW_QP_STATE_TERMINATE);
			qhp->attr.layer_etype = attrs->layer_etype;
			qhp->attr.ecode = attrs->ecode;
			ep = qhp->ep;
			if (!internal) {
				c4iw_get_ep(&qhp->ep->com);
				terminate = 1;
				disconnect = 1;
			} else {
				terminate = qhp->attr.send_term;
				ret = rdma_fini(rhp, qhp, ep);
				if (ret)
					goto err;
			}
			break;
		case C4IW_QP_STATE_ERROR:
			t4_set_wq_in_error(&qhp->wq, 0);
			set_state(qhp, C4IW_QP_STATE_ERROR);
			if (!internal) {
				abort = 1;
				disconnect = 1;
				ep = qhp->ep;
				c4iw_get_ep(&qhp->ep->com);
			}
			goto err;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		break;
	case C4IW_QP_STATE_CLOSING:

		/*
		 * Allow kernel users to move to ERROR for qp draining.
		 */
		if (!internal && (qhp->ibqp.uobject || attrs->next_state !=
				  C4IW_QP_STATE_ERROR)) {
			ret = -EINVAL;
			goto out;
		}
		switch (attrs->next_state) {
		case C4IW_QP_STATE_IDLE:
			flush_qp(qhp);
			set_state(qhp, C4IW_QP_STATE_IDLE);
			qhp->attr.llp_stream_handle = NULL;
			c4iw_put_ep(&qhp->ep->com);
			qhp->ep = NULL;
			wake_up(&qhp->wait);
			break;
		case C4IW_QP_STATE_ERROR:
			goto err;
		default:
			ret = -EINVAL;
			goto err;
		}
		break;
	case C4IW_QP_STATE_ERROR:
		if (attrs->next_state != C4IW_QP_STATE_IDLE) {
			ret = -EINVAL;
			goto out;
		}
		if (!t4_sq_empty(&qhp->wq) || !t4_rq_empty(&qhp->wq)) {
			ret = -EINVAL;
			goto out;
		}
		set_state(qhp, C4IW_QP_STATE_IDLE);
		break;
	case C4IW_QP_STATE_TERMINATE:
		if (!internal) {
			ret = -EINVAL;
			goto out;
		}
		goto err;
		break;
	default:
		pr_err("%s in a bad state %d\n", __func__, qhp->attr.state);
		ret = -EINVAL;
		goto err;
		break;
	}
	goto out;
err:
	pr_debug("disassociating ep %p qpid 0x%x\n", qhp->ep,
	     qhp->wq.sq.qid);

	/* disassociate the LLP connection */
	qhp->attr.llp_stream_handle = NULL;
	if (!ep)
		ep = qhp->ep;
	qhp->ep = NULL;
	set_state(qhp, C4IW_QP_STATE_ERROR);
	free = 1;
	abort = 1;
	flush_qp(qhp);
	wake_up(&qhp->wait);
out:
	mutex_unlock(&qhp->mutex);

	if (terminate)
		post_terminate(qhp, NULL, internal ? GFP_ATOMIC : GFP_KERNEL);

	/*
	 * If disconnect is 1, then we need to initiate a disconnect
	 * on the EP.  This can be a normal close (RTS->CLOSING) or
	 * an abnormal close (RTS/CLOSING->ERROR).
	 */
	if (disconnect) {
		c4iw_ep_disconnect(ep, abort, internal ? GFP_ATOMIC :
							 GFP_KERNEL);
		c4iw_put_ep(&ep->com);
	}

	/*
	 * If free is 1, then we've disassociated the EP from the QP
	 * and we need to dereference the EP.
	 */
	if (free)
		c4iw_put_ep(&ep->com);
	pr_debug("exit state %d\n", qhp->attr.state);
	return ret;
}

static void destroy_raw_qp(struct ib_qp *ib_qp)
{
	struct c4iw_dev *rhp;
	struct c4iw_raw_qp *rqp;
	struct c4iw_qp_attributes attrs;

	rqp = to_c4iw_raw_qp(ib_qp);
	rhp = rqp->dev;

	pr_debug("qpid %d\n", ib_qp->qp_num);
	attrs.next_state = C4IW_QP_STATE_ERROR;
	modify_raw_qp(rqp, C4IW_QP_ATTR_NEXT_STATE, &attrs);

	if (!ib_qp->srq)
		xa_erase_irq(&rhp->rawiqs, rqp->iq.cntxt_id);
	xa_erase_irq(&rhp->rawqps, rqp->txq.cntxt_id);
	xa_erase_irq(&rhp->fids, rqp->fid);

	atomic_dec(&rqp->refcnt);
	wait_event(rqp->wait, !atomic_read(&rqp->refcnt));

	spin_lock_irq(&rhp->lock);
	if (!list_empty(&rqp->fcl.db_fc_entry)) {
		list_del_init(&rqp->fcl.db_fc_entry);
	}
	spin_unlock_irq(&rhp->lock);

	free_raw_txq(rhp, rqp);

	/*
	 * Stop rxq in order to start it draining.
	 */
	if (!ib_qp->srq)
		stop_raw_rxq(rhp, rqp);

	/*
	 * Delete the filter.
	 */
	put_fid(rqp);

	/*
	 * free the rxq.
	 */
	if (!ib_qp->srq)
		free_raw_rxq(rhp, rqp);

	kfree(rqp);

	return;
}

static void destroy_rc_qp(struct ib_qp *ib_qp)
{
	struct c4iw_dev *rhp;
	struct c4iw_qp *qhp;
	struct c4iw_ucontext *ucontext;
	struct c4iw_qp_attributes attrs;

	qhp = to_c4iw_qp(ib_qp);
	rhp = qhp->rhp;
	ucontext = qhp->ucontext;

	attrs.next_state = C4IW_QP_STATE_ERROR;
	if (qhp->attr.state == C4IW_QP_STATE_TERMINATE)
		c4iw_modify_rc_qp(qhp, C4IW_QP_ATTR_NEXT_STATE, &attrs, 1);
	else	
		c4iw_modify_rc_qp(qhp, C4IW_QP_ATTR_NEXT_STATE, &attrs, 0);
	wait_event(qhp->wait, !qhp->ep);


	xa_lock_irq(&rhp->qps);
	__xa_erase(&rhp->qps, qhp->wq.sq.qid);
	if (!list_empty(&qhp->fcl.db_fc_entry)) {
		list_del_init(&qhp->fcl.db_fc_entry);
	}
	xa_unlock_irq(&rhp->qps);
	free_ird(rhp, qhp->attr.max_ird);

	c4iw_qp_rem_ref(ib_qp);

	wait_for_completion(&qhp->qp_rel_comp);

	pr_debug("ib_qp %p qpid 0x%0x\n", ib_qp, qhp->wq.sq.qid);
	pr_debug("qhp %p ucontext %p\n", qhp, ucontext);

	free_rc_queues(&rhp->rdev, &qhp->wq, ucontext ?
		       &ucontext->uctx : &rhp->rdev.uctx, !qhp->srq);

	c4iw_put_wr_wait(qhp->wr_waitp);

	kfree(qhp);
	return;
}

int c4iw_destroy_qp(struct ib_qp *ib_qp, struct ib_udata *udata)
{
	pr_debug("qpid %d\n", ib_qp->qp_num);
	switch (ib_qp->qp_type) {
	case IB_QPT_RC:
		destroy_rc_qp(ib_qp);
		break;
	case IB_QPT_RAW_ETH:
		destroy_raw_qp(ib_qp);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ib_qp->qp_type);
		break;
	}
	return 0;
}

static struct ib_qp *create_rc_qp(struct ib_pd *pd,
				  struct ib_qp_init_attr *attrs,
				  struct ib_udata *udata)
{
	struct c4iw_dev *rhp;
	struct c4iw_qp *qhp;
	struct c4iw_pd *php;
	struct c4iw_cq *schp;
	struct c4iw_cq *rchp;
	struct c4iw_create_qp_resp uresp = {0};
	int sqsize, rqsize = 0;
	struct c4iw_ucontext *ucontext = rdma_udata_to_drv_context(
			udata, struct c4iw_ucontext, ibucontext);
	int ret;
	struct c4iw_mm_entry *sq_key_mm, *rq_key_mm = NULL, *sq_db_key_mm;
	struct c4iw_mm_entry *rq_db_key_mm = NULL, *ma_sync_key_mm = NULL;

	pr_debug("ib_pd %p\n", pd);

	php = to_c4iw_pd(pd);
	rhp = php->rhp;
	schp = get_chp(rhp, ((struct c4iw_cq *)attrs->send_cq)->cq.cqid);
	rchp = get_chp(rhp, ((struct c4iw_cq *)attrs->recv_cq)->cq.cqid);
	if (!schp || !rchp)
		return ERR_PTR(-EINVAL);

	if (attrs->cap.max_inline_data > T4_MAX_SEND_INLINE)
		return ERR_PTR(-EINVAL);

	if (!attrs->srq) {
		if (attrs->cap.max_recv_wr > rhp->rdev.hw_queue.t4_max_rq_size)
			return ERR_PTR(-E2BIG);
		rqsize = attrs->cap.max_recv_wr + 1;
		if (rqsize < 8)
			rqsize = 8;
	}

	if (attrs->cap.max_send_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return ERR_PTR(-E2BIG);

	/* 
	 * Temporary workaround for iSER. iSER needs relatively large SQ for iw_cxgb4.
	 * Therefore we factor max_send_wr with 3 based on unique SQ size of iSER
	 */
	if (!ucontext && (attrs->cap.max_send_wr == ISER_SQ_SIZE))
		sqsize = min_t(int, 3 * attrs->cap.max_send_wr + 1,
			     rhp->rdev.hw_queue.t4_max_sq_size);
	else
		sqsize = attrs->cap.max_send_wr + 1;

	if (sqsize < 8)
		sqsize = 8;

	qhp = kzalloc(sizeof(*qhp), GFP_KERNEL);
	if (!qhp)
		return ERR_PTR(-ENOMEM);
	qhp->wr_waitp = c4iw_alloc_wr_wait(GFP_KERNEL);
	if (!qhp->wr_waitp) {
		ret = -ENOMEM;
		goto err_free_qhp;
	}

	qhp->wq.sq.size = sqsize;
	qhp->wq.sq.memsize =
		(sqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
		sizeof *qhp->wq.sq.queue + 16*sizeof(__be64);
	qhp->wq.sq.flush_cidx = -1;
	if (!attrs->srq) {
		qhp->wq.rq.size = rqsize;
		qhp->wq.rq.memsize =
			(rqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
			sizeof *qhp->wq.rq.queue;
	}
	if (ucontext) {
		qhp->wq.sq.memsize = roundup(qhp->wq.sq.memsize, PAGE_SIZE);
		if (!attrs->srq)
			qhp->wq.rq.memsize = roundup(qhp->wq.rq.memsize, PAGE_SIZE);
	}


	ret = alloc_rc_queues(&rhp->rdev, &qhp->wq, &schp->cq, &rchp->cq,
			      ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
			      !attrs->srq, qhp->wr_waitp);
	if (ret)
		goto err_free_wr_wait;

	attrs->cap.max_recv_wr = rqsize - 1;
	attrs->cap.max_send_wr = sqsize - 1;
	attrs->cap.max_inline_data = T4_MAX_SEND_INLINE;

	qhp->rhp = rhp;
	qhp->attr.pd = php->pdid;
	qhp->attr.scq = ((struct c4iw_cq *) attrs->send_cq)->cq.cqid;
	qhp->attr.rcq = ((struct c4iw_cq *) attrs->recv_cq)->cq.cqid;
	qhp->attr.sq_num_entries = attrs->cap.max_send_wr;
	qhp->attr.sq_max_sges = attrs->cap.max_send_sge;
	qhp->attr.sq_max_sges_rdma_write = attrs->cap.max_send_sge;
	if (!attrs->srq) {
		qhp->attr.rq_num_entries = attrs->cap.max_recv_wr;
		qhp->attr.rq_max_sges = attrs->cap.max_recv_sge;
	}
	qhp->attr.state = C4IW_QP_STATE_IDLE;
	qhp->attr.next_state = C4IW_QP_STATE_IDLE;
	qhp->attr.enable_rdma_read = 1;
	qhp->attr.enable_rdma_write = 1;
	qhp->attr.enable_bind = 1;
	qhp->attr.max_ord = 0;
	qhp->attr.max_ird = 0;
	qhp->sq_sig_all = attrs->sq_sig_type == IB_SIGNAL_ALL_WR;
	spin_lock_init(&qhp->lock);
	mutex_init(&qhp->mutex);
	init_waitqueue_head(&qhp->wait);
	init_completion(&qhp->qp_rel_comp);
	refcount_set(&qhp->qp_refcnt, 1);

	ret = xa_insert_irq(&rhp->qps, qhp->wq.sq.qid, qhp, GFP_KERNEL);
	if (ret)
		goto err_destroy_qp;

	if (udata) {
		sq_key_mm = kmalloc(sizeof *sq_key_mm, GFP_KERNEL);
		if (!sq_key_mm) {
			ret = -ENOMEM;
			goto err_remove_handle;
		}
		if (!attrs->srq) {
			rq_key_mm = kmalloc(sizeof *rq_key_mm, GFP_KERNEL);
			if (!rq_key_mm) {
				ret = -ENOMEM;
				goto err_free_sq_key;
			}
		}
		sq_db_key_mm = kmalloc(sizeof *sq_db_key_mm, GFP_KERNEL);
		if (!sq_db_key_mm) {
			ret = -ENOMEM;
			goto err_free_rq_key;
		}
		if (!attrs->srq) {
			rq_db_key_mm = kmalloc(sizeof *rq_db_key_mm, GFP_KERNEL);
			if (!rq_db_key_mm) {
				ret = -ENOMEM;
				goto err_free_sq_db_key;
			}
		}
		if (t4_sq_onchip(&qhp->wq.sq)) {
			ma_sync_key_mm = kmalloc(sizeof *ma_sync_key_mm,
						 GFP_KERNEL);
			if (!ma_sync_key_mm) {
				ret = -ENOMEM;
				goto err_free_rq_db_key;
			}
			uresp.flags = C4IW_QPF_ONCHIP;
		} else
			uresp.flags = 0;
		if (rhp->rdev.lldi.write_w_imm_support)
			uresp.flags |= C4IW_QPF_WRITE_W_IMM;
		uresp.qid_mask = rhp->rdev.qpmask;
		uresp.sqid = qhp->wq.sq.qid;
		uresp.sq_size = qhp->wq.sq.size;
		uresp.sq_memsize = qhp->wq.sq.memsize;
		if (!attrs->srq) {
			uresp.rqid = qhp->wq.rq.qid;
			uresp.rq_size = qhp->wq.rq.size;
			uresp.rq_memsize = qhp->wq.rq.memsize;
		}
		spin_lock(&ucontext->mmap_lock);
		if (ma_sync_key_mm) {
			uresp.ma_sync_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		uresp.sq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		if (!attrs->srq) {
			uresp.rq_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		uresp.sq_db_gts_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		if (!attrs->srq) {
			uresp.rq_db_gts_key = ucontext->key;
			ucontext->key += PAGE_SIZE;
		}
		spin_unlock(&ucontext->mmap_lock);
		ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (ret)
			goto err_free_ma_sync_key;
		sq_key_mm->key = uresp.sq_key;
		sq_key_mm->addr = qhp->wq.sq.phys_addr;
		sq_key_mm->len = PAGE_ALIGN(qhp->wq.sq.memsize);
		insert_mmap(ucontext, sq_key_mm);
		if (!attrs->srq) {
			rq_key_mm->key = uresp.rq_key;
			rq_key_mm->addr = virt_to_phys(qhp->wq.rq.queue);
			rq_key_mm->len = PAGE_ALIGN(qhp->wq.rq.memsize);
			insert_mmap(ucontext, rq_key_mm);
		}
		sq_db_key_mm->key = uresp.sq_db_gts_key;
		sq_db_key_mm->addr = (u64)(unsigned long)qhp->wq.sq.bar2_pa;
		sq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, sq_db_key_mm);
		if (!attrs->srq) {
			rq_db_key_mm->key = uresp.rq_db_gts_key;
			rq_db_key_mm->addr = (u64)(unsigned long)qhp->wq.rq.bar2_pa;
			rq_db_key_mm->len = PAGE_SIZE;
			insert_mmap(ucontext, rq_db_key_mm);
		}
		if (ma_sync_key_mm) {
			ma_sync_key_mm->key = uresp.ma_sync_key;
			ma_sync_key_mm->addr =
				(pci_resource_start(rhp->rdev.lldi.pdev, 0) +
				A_PCIE_MA_SYNC) & PAGE_MASK;
			ma_sync_key_mm->len = PAGE_SIZE;
			insert_mmap(ucontext, ma_sync_key_mm);
		}

		qhp->ucontext = ucontext;
	}
	if (!attrs->srq)
		qhp->wq.qp_errp = &qhp->wq.rq.queue[qhp->wq.rq.size].status.qp_err;
	else {
		qhp->wq.qp_errp = &qhp->wq.sq.queue[qhp->wq.sq.size].status.qp_err;
		qhp->wq.srqidxp = &qhp->wq.sq.queue[qhp->wq.sq.size].status.srqidx;
	}
	qhp->ibqp.qp_num = qhp->wq.sq.qid;
	if (attrs->srq)
		qhp->srq = to_c4iw_srq(attrs->srq);
	INIT_LIST_HEAD(&qhp->fcl.db_fc_entry);
	qhp->fcl.type = RC_QP;

	pr_debug("sq id %u size %u memsize %lu num_entries %u "
	     "rq id %u size %u memsize %lu num_entries %u\n",
	     qhp->wq.sq.qid, qhp->wq.sq.size, (unsigned long)qhp->wq.sq.memsize,
	     attrs->cap.max_send_wr, qhp->wq.rq.qid, qhp->wq.rq.size,
	     (unsigned long)qhp->wq.rq.memsize, attrs->cap.max_recv_wr);

	return &qhp->ibqp;
err_free_ma_sync_key:
	if (ma_sync_key_mm)
		kfree(ma_sync_key_mm);
err_free_rq_db_key:
	if (!attrs->srq)
		kfree(rq_db_key_mm);
err_free_sq_db_key:
	kfree(sq_db_key_mm);
err_free_rq_key:
	if (!attrs->srq)
		kfree(rq_key_mm);
err_free_sq_key:
	kfree(sq_key_mm);
err_remove_handle:
	xa_erase_irq(&rhp->qps, qhp->wq.sq.qid);
err_destroy_qp:
	free_rc_queues(&rhp->rdev, &qhp->wq,
		   ucontext ? &ucontext->uctx : &rhp->rdev.uctx, !attrs->srq);
err_free_wr_wait:
	c4iw_put_wr_wait(qhp->wr_waitp);
err_free_qhp:
	kfree(qhp);
	return ERR_PTR(ret);
}

static struct ib_qp *create_raw_qp(struct ib_pd *pd,
				  struct ib_qp_init_attr *attrs,
				  struct ib_udata *udata)
{
	struct c4iw_dev *rhp;
	struct c4iw_raw_qp *rqp;
	struct c4iw_pd *php;
	struct c4iw_cq *schp;
	struct c4iw_cq *rchp;
	struct c4iw_create_raw_qp_req ureq;
	struct c4iw_create_raw_qp_resp uresp;
	int sqsize, flsize, iqsize;
	struct c4iw_ucontext *ucontext;
	int ret;
	struct c4iw_mm_entry *fl_key_mm = NULL, *iq_key_mm = NULL;
	struct c4iw_mm_entry *kdb_key_mm = NULL, *ocq_key_mm = NULL;
	struct c4iw_mm_entry *txq_key_mm = NULL, *txq_db_key_mm = NULL;
	struct c4iw_mm_entry *fl_db_key_mm = NULL, *iq_db_key_mm = NULL;
	static int warned;

	pr_debug("ib_pd %p\n", pd);

	if (!(pd->uobject))
		return ERR_PTR(-EINVAL);

	if (!allow_nonroot_rawqps && !capable(CAP_NET_RAW))
		return ERR_PTR(-EPERM);

	php = to_c4iw_pd(pd);
	rhp = php->rhp;

	if (udata->inlen != sizeof ureq ||
	    udata->outlen < sizeof uresp) {
		if (!warned) {
			warned = 1;
			pr_warn("WARNING: downlevel libcxgb4. "
				"WD queues cannot be supported. Please update "
				"libcxgb4.\n");
		}
		return ERR_PTR(-EINVAL);
	} 

	ret = ib_copy_from_udata(&ureq, udata, sizeof ureq);
	if (ret)
		return ERR_PTR(-EFAULT);

	if (ureq.port == 0 || ureq.port > rhp->rdev.lldi.nports)
		return ERR_PTR(-EINVAL);
	if (ureq.nfids == 0)
		return ERR_PTR(-EINVAL);
	ureq.port--;
	schp = get_chp(rhp, ((struct c4iw_cq *)attrs->send_cq)->cq.cqid);
	rchp = get_chp(rhp, ((struct c4iw_cq *)attrs->recv_cq)->cq.cqid);
	if (!schp || !rchp)
		return ERR_PTR(-EINVAL);

	if (attrs->cap.max_inline_data > T4_MAX_TXQ_INLINE)
		return ERR_PTR(-EINVAL);

	if (attrs->cap.max_send_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return ERR_PTR(-E2BIG);
	sqsize = attrs->cap.max_send_wr + 1;
	if (sqsize < 8)
		sqsize = 8;

	if (attrs->cap.max_recv_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return ERR_PTR(-E2BIG);
	if (attrs->srq) {
		flsize = 0;
		iqsize = 0;
	} else {
		flsize = attrs->cap.max_recv_wr + 1;
		if (flsize < 8)
			flsize = 8;
		iqsize = rchp->cq.size + 1;
	}

	ucontext = rdma_udata_to_drv_context(udata, struct c4iw_ucontext,
					     ibucontext);

	rqp = kzalloc(sizeof(*rqp), GFP_KERNEL);
	if (!rqp)
		return ERR_PTR(-ENOMEM);

	rqp->rcq = rchp;
	rqp->scq = schp;
	rqp->fl.size = flsize;
	rqp->fl.packed = !!(ureq.flags & FL_PACKED_MODE);
	rqp->fl.cong_drop = !!(ureq.flags & FL_CONG_DROP_MODE);
	rqp->iq.size = iqsize;
	rqp->txq.size = sqsize;
	rqp->netdev = rhp->rdev.lldi.ports[ureq.port];
	rqp->vlan_pri = ureq.vlan_pri;
	rqp->nfids = ureq.nfids;
	rqp->dev = rhp;
	rqp->txq_idx = cxgb4_port_idx(rqp->netdev) * rhp->rdev.lldi.ntxq /
						     rhp->rdev.lldi.nchan;

	rqp->iq.memsize = PAGE_ALIGN(rqp->iq.size * T4_IQE_LEN);
	rqp->fl.memsize = PAGE_ALIGN(rqp->fl.size * sizeof(__be64) +
				     rhp->rdev.hw_queue.t4_stat_len);
	rqp->txq.memsize = PAGE_ALIGN(rqp->txq.size * sizeof *rqp->txq.desc +
				      rhp->rdev.hw_queue.t4_stat_len +
				      16*sizeof(__be64));
	rqp->state = C4IW_QP_STATE_IDLE;
	mutex_init(&rqp->mutex);
	init_waitqueue_head(&rqp->wait);
	atomic_set(&rqp->refcnt, 1);

	if (!attrs->srq) {
		ret = alloc_raw_rxq(rhp, rqp);
		if (ret)
			goto err1;
	}
	ret = alloc_raw_txq(rhp, rqp);
	if (ret)
		goto err2;

	rqp->fid = get_fid(rhp, rqp->nfids);
	if (rqp->fid < 0) {
		pr_err("%s no fids available\n", __func__);
		ret = -ENOMEM;
		goto err2a;
	}

	attrs->cap.max_recv_wr = rqp->fl.size ? rqp->fl.size - 1 : 0;
	attrs->cap.max_send_wr = rqp->txq.size - 1;
	attrs->cap.max_inline_data = T4_MAX_SEND_INLINE;

	if (!attrs->srq) {
		ret = xa_insert_irq(&rhp->rawiqs, rqp->iq.cntxt_id, &rqp->fcl, GFP_KERNEL);
		if (ret)
			goto err3;
		fl_key_mm = kmalloc(sizeof *fl_key_mm, GFP_KERNEL);
		if (!fl_key_mm) {
			ret = -ENOMEM;
			goto err4;
		}
		iq_key_mm = kmalloc(sizeof *iq_key_mm, GFP_KERNEL);
		if (!iq_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	} else {
		fl_key_mm = iq_key_mm = NULL;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm = kmalloc(sizeof *kdb_key_mm, GFP_KERNEL);
		if (!kdb_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	}
	txq_key_mm = kmalloc(sizeof *txq_key_mm, GFP_KERNEL);
	if (!txq_key_mm) {
		ret = -ENOMEM;
		goto err5;
	}
	memset(&uresp, 0, sizeof uresp);
	uresp.flags = 0;
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		ocq_key_mm = kmalloc(sizeof *ocq_key_mm, GFP_KERNEL);
		if (!ocq_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		uresp.flags = C4IW_QPF_ONCHIP;
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		txq_db_key_mm = kmalloc(sizeof *txq_db_key_mm, GFP_KERNEL);
		if (!txq_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		fl_db_key_mm = kmalloc(sizeof *fl_db_key_mm, GFP_KERNEL);
		if (!fl_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
		iq_db_key_mm = kmalloc(sizeof *iq_db_key_mm, GFP_KERNEL);
		if (!iq_db_key_mm) {
			ret = -ENOMEM;
			goto err5;
		}
	}
	uresp.fl_id = rqp->fl.cntxt_id;
	uresp.iq_id = rqp->iq.cntxt_id;
	uresp.txq_id = rqp->txq.cntxt_id;
	uresp.fl_size = rqp->fl.size;
	uresp.iq_size = rqp->iq.size;
	uresp.txq_size = rqp->txq.size;
	uresp.fl_memsize = rqp->fl.memsize;
	uresp.iq_memsize = rqp->iq.memsize;
	uresp.txq_memsize = rqp->txq.memsize;
	uresp.tx_chan = cxgb4_port_chan(rqp->netdev);
	uresp.pf = rhp->rdev.lldi.pf;
	uresp.fid = rqp->fid;
	spin_lock(&ucontext->mmap_lock);
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		uresp.ma_sync_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.txq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.fl_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	if (!attrs->srq) {
		uresp.fl_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.db_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	uresp.txq_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	spin_unlock(&ucontext->mmap_lock);
	ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
	if (ret)
		goto err5;
	if (!attrs->srq) {
		fl_key_mm->key = uresp.fl_key;
		fl_key_mm->addr = rqp->fl.phys_addr;
		fl_key_mm->len = uresp.fl_memsize;
		insert_mmap(ucontext, fl_key_mm);
		iq_key_mm->key = uresp.iq_key;
		iq_key_mm->addr = rqp->iq.phys_addr;
		iq_key_mm->len = uresp.iq_memsize;
		insert_mmap(ucontext, iq_key_mm);
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm->key = uresp.db_key;
		kdb_key_mm->addr = (pci_resource_start(rhp->rdev.lldi.pdev, 0)
			     + MYPF_REG(A_SGE_PF_KDOORBELL)) & PAGE_MASK;
		kdb_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, kdb_key_mm);
	}
	txq_key_mm->key = uresp.txq_key;
	txq_key_mm->addr = rqp->txq.phys_addr;
	txq_key_mm->len = uresp.txq_memsize;
	insert_mmap(ucontext, txq_key_mm);
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		ocq_key_mm->key = uresp.ma_sync_key;
		ocq_key_mm->addr = (pci_resource_start(rhp->rdev.lldi.pdev, 0)
			    + A_PCIE_MA_SYNC) & PAGE_MASK;
		ocq_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, ocq_key_mm);
	} else if (!is_t4(rhp->rdev.lldi.adapter_type)) {
		u32 bar2_qid;
		u64 bar2_pa;
		void __iomem *va;

		va = c4iw_bar2_addrs(&rhp->rdev, rqp->txq.cntxt_id,
				     T4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err6;
		txq_db_key_mm->key = uresp.txq_bar2_key;
		txq_db_key_mm->addr = bar2_pa;
		txq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, txq_db_key_mm);

		va = c4iw_bar2_addrs(&rhp->rdev, rqp->fl.cntxt_id,
				     T4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err7;
		fl_db_key_mm->key = uresp.fl_bar2_key;
		fl_db_key_mm->addr = bar2_pa;
		fl_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, fl_db_key_mm);

		va = c4iw_bar2_addrs(&rhp->rdev, rqp->iq.cntxt_id,
				     T4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err8;
		iq_db_key_mm->key = uresp.iq_bar2_key;
		iq_db_key_mm->addr = bar2_pa;
		iq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, iq_db_key_mm);
	}
	rqp->ibqp.qp_num = rqp->txq.cntxt_id;

	ret = xa_insert_irq(&rhp->rawqps, rqp->txq.cntxt_id, rqp, GFP_KERNEL);
	if (ret)
		goto err8;
	ret = xa_insert_irq(&rhp->fids, rqp->fid, rchp, GFP_KERNEL);
	if (ret)
		goto err9;

	INIT_LIST_HEAD(&rqp->fcl.db_fc_entry);
	rqp->fcl.type = RAW_QP;

	pr_debug("txq id %u size %u memsize %u num_entries %u "
	     "fl id %u size %u memsize %u num_entries %u "
	     "iq id %u size %u memsize %u num_entries %u\n",
	     rqp->txq.cntxt_id, rqp->txq.size, rqp->txq.memsize,
	     attrs->cap.max_send_wr, rqp->fl.cntxt_id, rqp->fl.size,
	     rqp->fl.memsize, attrs->cap.max_recv_wr, rqp->iq.cntxt_id,
	     rqp->iq.size, rqp->iq.memsize, rqp->iq.size - 1);

	return &rqp->ibqp;
err9:
	xa_erase_irq(&rhp->rawqps, rqp->txq.cntxt_id);
err8:
	if (!is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, fl_db_key_mm->key, fl_db_key_mm->len);
err7:
	if (!is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, txq_db_key_mm->key, txq_db_key_mm->len);
err6:
	if (rqp->txq.flags & T4_SQ_ONCHIP) {
		remove_mmap(ucontext, ocq_key_mm->key, ocq_key_mm->len);
	}
	remove_mmap(ucontext, txq_key_mm->key, txq_key_mm->len);
	if (is_t4(rhp->rdev.lldi.adapter_type))
		remove_mmap(ucontext, kdb_key_mm->key, kdb_key_mm->len);
	if (!attrs->srq) {
		remove_mmap(ucontext, iq_key_mm->key, iq_key_mm->len);
		remove_mmap(ucontext, fl_key_mm->key, fl_key_mm->len);
	}
err5:
	if (iq_db_key_mm)
		kfree(iq_db_key_mm);
	if (fl_db_key_mm)
		kfree(fl_db_key_mm);
	if (txq_db_key_mm)
		kfree(txq_db_key_mm);
	if (ocq_key_mm)
		kfree(ocq_key_mm);
	if (txq_key_mm)
		kfree(txq_key_mm);
	if (kdb_key_mm)
		kfree(kdb_key_mm);
	if (iq_key_mm)
		kfree(iq_key_mm);
	if (fl_key_mm)
		kfree(fl_key_mm);
err4:
	if (!attrs->srq)
		xa_erase_irq(&rhp->rawiqs, rqp->iq.cntxt_id);
err3:
	put_fid(rqp);
err2a:
	free_raw_txq(rhp, rqp);
err2:
	if (!attrs->srq)
		free_raw_rxq(rhp, rqp);
err1:
	kfree(rqp);
	return ERR_PTR(ret);
}

struct ib_qp *c4iw_create_qp(struct ib_pd *pd, struct ib_qp_init_attr *attrs,
			     struct ib_udata *udata)
{
	struct ib_qp *qp;

	switch (attrs->qp_type) {
	case IB_QPT_RC:
		qp = create_rc_qp(pd, attrs, udata);
		break;
	case IB_QPT_RAW_ETH:
		qp = create_raw_qp(pd, attrs, udata);
		break;
	default:
		qp = ERR_PTR(-EINVAL);
		break;
	}
	return qp;
}

int c4iw_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata)
{
	enum c4iw_qp_attr_mask mask = 0;
	struct c4iw_qp_attributes attrs;
	int ret = 0;

	pr_debug("ib_qp %p\n", ibqp);

	/* iwarp does not support the RTR state */
	if ((attr_mask & IB_QP_STATE) && (attr->qp_state == IB_QPS_RTR))
		attr_mask &= ~IB_QP_STATE;

	/* Make sure we still have something left to do */
	if (!attr_mask)
		return 0;

	memset(&attrs, 0, sizeof attrs);

	attrs.next_state = c4iw_convert_state(attr->qp_state);
	attrs.enable_rdma_read = (attr->qp_access_flags &
			       IB_ACCESS_REMOTE_READ) ?  1 : 0;
	attrs.enable_rdma_write = (attr->qp_access_flags &
				IB_ACCESS_REMOTE_WRITE) ? 1 : 0;
	attrs.enable_bind = (attr->qp_access_flags & IB_ACCESS_MW_BIND) ? 1 : 0;


	mask |= (attr_mask & IB_QP_STATE) ? C4IW_QP_ATTR_NEXT_STATE : 0;
	mask |= (attr_mask & IB_QP_ACCESS_FLAGS) ?
			(C4IW_QP_ATTR_ENABLE_RDMA_READ |
			 C4IW_QP_ATTR_ENABLE_RDMA_WRITE |
			 C4IW_QP_ATTR_ENABLE_RDMA_BIND) : 0;

	/*
	 * Use SQ_PSN and RQ_PSN to pass in IDX_INC values for 
	 * ringing the queue db when we're in DB_FULL mode.
	 * Only allow this on T4 devices.
	 */
	attrs.sq_db_inc = attr->sq_psn;
	attrs.rq_db_inc = attr->rq_psn;
	mask |= (attr_mask & IB_QP_SQ_PSN) ? C4IW_QP_ATTR_SQ_DB : 0;
	mask |= (attr_mask & IB_QP_RQ_PSN) ? C4IW_QP_ATTR_RQ_DB : 0;
	if (!is_t4(to_c4iw_qp(ibqp)->rhp->rdev.lldi.adapter_type) &&
	    (mask & (C4IW_QP_ATTR_SQ_DB|C4IW_QP_ATTR_RQ_DB)))
		return -EINVAL;

	switch (ibqp->qp_type) {
	case IB_QPT_RC:
		ret = c4iw_modify_rc_qp(to_c4iw_qp(ibqp), mask, &attrs, 0);
		break;
	case IB_QPT_RAW_ETH:
		ret = modify_raw_qp(to_c4iw_raw_qp(ibqp), mask, &attrs);
		break;
	default:
		WARN_ONCE(1, "unknown qp type %u\n", ibqp->qp_type);
	}
	return ret;
}

static int modify_raw_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask srq_attr_mask,
			  struct ib_udata *udata)
{
	u16 idx_inc;
	int ret;

	idx_inc = attr->max_sge >> 16;
	ret = ring_kernel_srq_db(to_c4iw_raw_srq(ib_srq), idx_inc);

	return ret;
}

void c4iw_dispatch_srq_limit_reached_event(struct c4iw_srq *srq)
{
	struct ib_event event = {0};

	event.device = &srq->rhp->ibdev;
	event.element.srq = &srq->ibsrq;
	event.event = IB_EVENT_SRQ_LIMIT_REACHED;
	ib_dispatch_event(&event);
}

static int modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		      enum ib_srq_attr_mask srq_attr_mask,
		      struct ib_udata *udata)
{
	struct c4iw_srq *srq = to_c4iw_srq(ib_srq);
	int ret = 0;

	/*
	 * XXX 0 mask == a SW interrupt for srq_limit reached...
	 */
	if (udata && !srq_attr_mask) {
		c4iw_dispatch_srq_limit_reached_event(srq);
		goto out;
	}

	/* no support for this yet */
	if (srq_attr_mask & IB_SRQ_MAX_WR) {
		ret = -ENOSYS;
		goto out;
	}

	if (!udata && (srq_attr_mask & IB_SRQ_LIMIT)) {
		srq->armed = true;
		srq->srq_limit = attr->srq_limit;
	}
out:
	return ret;
}

int c4iw_modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		    enum ib_srq_attr_mask srq_attr_mask,
		    struct ib_udata *udata)
{
	struct c4iw_srq *srq = to_c4iw_srq(ib_srq);

	if (srq->fcl.type == RAW_SRQ)
		return modify_raw_srq(ib_srq, attr, srq_attr_mask, udata);
	return modify_srq(ib_srq, attr, srq_attr_mask, udata);
}

struct ib_qp *c4iw_get_qp(struct ib_device *dev, int qpn)
{
	pr_debug("ib_dev %p qpn 0x%x\n", dev, qpn);
	return (struct ib_qp *)get_qhp(to_c4iw_dev(dev), qpn);
}

int c4iw_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);

	memset(attr, 0, sizeof *attr);
	memset(init_attr, 0, sizeof *init_attr);
	attr->qp_state = to_ib_qp_state(qhp->attr.state);
	init_attr->cap.max_send_wr = qhp->attr.sq_num_entries;
	init_attr->cap.max_recv_wr = qhp->attr.rq_num_entries;
	init_attr->cap.max_send_sge = qhp->attr.sq_max_sges;
	init_attr->cap.max_recv_sge = qhp->attr.rq_max_sges;
	init_attr->cap.max_inline_data = T4_MAX_SEND_INLINE;
	init_attr->sq_sig_type = qhp->sq_sig_all ? IB_SIGNAL_ALL_WR : 0;
	return 0;
}

static void destroy_raw_srq(struct ib_srq *ib_srq)
{
	struct c4iw_dev *rhp;
	struct c4iw_raw_srq *srq;

	srq = to_c4iw_raw_srq(ib_srq);
	rhp = srq->dev;

	pr_debug("iqid %d\n", srq->iq.cntxt_id);

	xa_erase_irq(&rhp->rawiqs, srq->iq.cntxt_id);
	spin_lock_irq(&rhp->lock);
	if (!list_empty(&srq->fcl.db_fc_entry))
		list_del_init(&srq->fcl.db_fc_entry);
	spin_unlock_irq(&rhp->lock);
	free_raw_srq(rhp, srq);
}

static void destroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata)
{
	struct c4iw_dev *rhp;
	struct c4iw_srq *srq;
	struct c4iw_ucontext *ucontext;

	srq = to_c4iw_srq(ib_srq);
	rhp = srq->rhp;

	pr_debug("id %d\n", srq->wq.qid);

	ucontext = rdma_udata_to_drv_context(udata, struct c4iw_ucontext,
					     ibucontext);
	free_srq_queue(srq, ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
		       srq->wr_waitp);
	c4iw_free_srq_idx(&rhp->rdev, srq->idx);
	c4iw_put_wr_wait(srq->wr_waitp);
}

static int create_raw_srq(struct ib_srq *ib_srq,
			  struct ib_srq_init_attr *attrs,
			  struct ib_udata *udata)
{
	struct c4iw_raw_srq *srq = to_c4iw_raw_srq(ib_srq);
	struct ib_pd *pd = ib_srq->pd;
	struct c4iw_dev *rhp;
	struct c4iw_pd *php;
	struct c4iw_create_raw_srq_req ureq;
	struct c4iw_create_raw_srq_resp uresp;
	int flsize, iqsize;
	struct c4iw_ucontext *ucontext;
	int ret;
	struct c4iw_mm_entry *fl_key_mm, *iq_key_mm, *kdb_key_mm = NULL;
	struct c4iw_mm_entry *fl_db_key_mm = NULL, *iq_db_key_mm = NULL;

	pr_debug("ib_pd %p\n", pd);

	if (!(pd->uobject))
		return -EINVAL;

	if (!allow_nonroot_rawqps && !capable(CAP_NET_RAW))
		return -EPERM;

	php = to_c4iw_pd(pd);
	rhp = php->rhp;

	ret = ib_copy_from_udata(&ureq, udata, sizeof ureq);
	if (ret)
		return -EFAULT;

	if (ureq.port == 0 || ureq.port > rhp->rdev.lldi.nports)
		return -EINVAL;

	ureq.port--;
	if (attrs->attr.max_wr > rhp->rdev.hw_queue.t4_max_sq_size)
		return -E2BIG;
	flsize = attrs->attr.max_wr + 1;

	iqsize = roundup(flsize * 4, 16);
	if (iqsize > rhp->rdev.hw_queue.t4_max_iq_size)
		iqsize = rhp->rdev.hw_queue.t4_max_iq_size;
	ucontext = rdma_udata_to_drv_context(udata, struct c4iw_ucontext,
					     ibucontext);

	srq->fl.size = flsize;
	srq->iq.size = iqsize;
	srq->netdev = rhp->rdev.lldi.ports[ureq.port];
	srq->dev = rhp;
	srq->iq.memsize = PAGE_ALIGN(srq->iq.size * T4_IQE_LEN);
	srq->fl.memsize = PAGE_ALIGN(srq->fl.size * sizeof(__be64) +
				     rhp->rdev.hw_queue.t4_stat_len);
	srq->fl.packed = !!(ureq.flags & FL_PACKED_MODE);
	ret = alloc_raw_srq(rhp, srq);
	if (ret)
		goto err1;
	attrs->attr.max_wr = srq->fl.size - 1;
	attrs->attr.max_sge = 4;

	ret = xa_insert_irq(&rhp->rawiqs, srq->iq.cntxt_id, &srq->fcl, GFP_KERNEL);
	if (ret)
		goto err3;

	fl_key_mm = kmalloc(sizeof *fl_key_mm, GFP_KERNEL);
	if (!fl_key_mm) {
		ret = -ENOMEM;
		goto err4;
	}
	iq_key_mm = kmalloc(sizeof *iq_key_mm, GFP_KERNEL);
	if (!iq_key_mm) {
		ret = -ENOMEM;
		goto err5;
	}
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm = kmalloc(sizeof *kdb_key_mm, GFP_KERNEL);
		if (!kdb_key_mm) {
			ret = -ENOMEM;
			goto err6;
		}
	} else {
		fl_db_key_mm = kmalloc(sizeof *fl_db_key_mm, GFP_KERNEL);
		if (!fl_db_key_mm) {
			ret = -ENOMEM;
			goto err7;
		}
		iq_db_key_mm = kmalloc(sizeof *iq_db_key_mm, GFP_KERNEL);
		if (!iq_db_key_mm) {
			ret = -ENOMEM;
			goto err8;
		}
	}

	memset(&uresp, 0, sizeof uresp);
	uresp.fl_id = srq->fl.cntxt_id;
	uresp.iq_id = srq->iq.cntxt_id;
	uresp.fl_size = srq->fl.size;
	uresp.iq_size = srq->iq.size;
	uresp.fl_memsize = srq->fl.memsize;
	uresp.iq_memsize = srq->iq.memsize;
	uresp.qid_mask = rhp->rdev.qpmask;

	spin_lock(&ucontext->mmap_lock);
	uresp.fl_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	uresp.iq_key = ucontext->key;
	ucontext->key += PAGE_SIZE;
	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		uresp.db_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	} else {
		uresp.fl_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.iq_bar2_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
	}
	spin_unlock(&ucontext->mmap_lock);

	ret = ib_copy_to_udata(udata, &uresp, sizeof uresp);
	if (ret)
		goto err9;

	fl_key_mm->key = uresp.fl_key;
	fl_key_mm->addr = srq->fl.phys_addr;
	fl_key_mm->len = uresp.fl_memsize;
	insert_mmap(ucontext, fl_key_mm);
	iq_key_mm->key = uresp.iq_key;
	iq_key_mm->addr = srq->iq.phys_addr;
	iq_key_mm->len = uresp.iq_memsize;
	insert_mmap(ucontext, iq_key_mm);

	if (is_t4(rhp->rdev.lldi.adapter_type)) {
		kdb_key_mm->key = uresp.db_key;
		kdb_key_mm->addr = (pci_resource_start(rhp->rdev.lldi.pdev, 0)
			     + MYPF_REG(A_SGE_PF_KDOORBELL)) & PAGE_MASK;
		kdb_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, kdb_key_mm);
	} else {
		u32 bar2_qid;
		u64 bar2_pa;
		void __iomem *va;

		va = c4iw_bar2_addrs(&rhp->rdev, srq->fl.cntxt_id,
				     T4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err10;
		fl_db_key_mm->key = uresp.fl_bar2_key;
		fl_db_key_mm->addr = bar2_pa;
		fl_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, fl_db_key_mm);

		va = c4iw_bar2_addrs(&rhp->rdev, srq->iq.cntxt_id,
				     T4_BAR2_QTYPE_EGRESS,
				     &bar2_qid, &bar2_pa);
		if (!va)
			goto err11;
		iq_db_key_mm->key = uresp.iq_bar2_key;
		iq_db_key_mm->addr = bar2_pa;
		iq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, iq_db_key_mm);
	}
	INIT_LIST_HEAD(&srq->fcl.db_fc_entry);
	srq->fcl.type = RAW_SRQ;
	pr_debug("fl id %u size %u memsize %u num_entries %u "
	     "iq id %u size %u memsize %u num_entries %u\n",
	     srq->fl.cntxt_id, srq->fl.size, srq->fl.memsize,
	     attrs->attr.max_wr, srq->iq.cntxt_id, srq->iq.size,
	     srq->iq.memsize, srq->iq.size - 1);
	return 0;
err11:
	remove_mmap(ucontext, fl_db_key_mm->key, fl_db_key_mm->len);
err10:
	remove_mmap(ucontext, iq_key_mm->key, iq_key_mm->len);
	remove_mmap(ucontext, fl_key_mm->key, fl_key_mm->len);
err9:
	if (iq_db_key_mm)
		kfree(iq_db_key_mm);
err8:
	if (fl_db_key_mm)
		kfree(fl_db_key_mm);
err7:
	if (kdb_key_mm)
		kfree(kdb_key_mm);
err6:
	if (iq_key_mm)
		kfree(iq_key_mm);
err5:
	if (fl_key_mm)
		kfree(fl_key_mm);
err4:
	xa_erase_irq(&rhp->rawiqs, srq->iq.cntxt_id);
err3:
	free_raw_srq(rhp, srq);
err1:
	return ret;
}

int create_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *attrs,
			       struct ib_udata *udata)
{
	struct ib_pd *pd = ib_srq->pd;
	struct c4iw_dev *rhp;
	struct c4iw_srq *srq = to_c4iw_srq(ib_srq);
	struct c4iw_pd *php;
	struct c4iw_create_srq_resp uresp;
	struct c4iw_ucontext *ucontext;
	struct c4iw_mm_entry *srq_key_mm, *srq_db_key_mm;
	int rqsize;
	int ret;
	int wr_len;

	pr_debug("%s ib_pd %p\n", __func__, pd);

	php = to_c4iw_pd(pd);
	rhp = php->rhp;

	if (!rhp->rdev.lldi.vr->srq.size)
		return -EINVAL;
	if (attrs->attr.max_wr > rhp->rdev.hw_queue.t4_max_rq_size)
		return -E2BIG;
	if (attrs->attr.max_sge > T4_MAX_RECV_SGE)
		return -E2BIG;

	/*
	 * SRQ RQT and RQ must be a power of 2 and at least 16 deep.
	 */
	rqsize = attrs->attr.max_wr + 1;
	rqsize = roundup_pow_of_two(max_t(u16, rqsize, 16));

	ucontext = rdma_udata_to_drv_context(udata, struct c4iw_ucontext,
					     ibucontext);

	srq->wr_waitp = c4iw_alloc_wr_wait(GFP_KERNEL);
	if (!srq->wr_waitp)
		return -ENOMEM;

	srq->idx = c4iw_alloc_srq_idx(&rhp->rdev);
	if (srq->idx < 0) {
		ret = -ENOMEM;
		goto err_free_wr_wait;
	}

	wr_len = sizeof(struct fw_ri_res_wr) + sizeof(struct fw_ri_res);
	srq->destroy_skb = alloc_skb(wr_len, GFP_KERNEL);
	if (!srq->destroy_skb) {
		ret = -ENOMEM;
		goto err_free_srq_idx;
	}

	srq->rhp = rhp;
	srq->pdid = php->pdid;

	srq->wq.size = rqsize;
	srq->wq.memsize =
		(rqsize + rhp->rdev.hw_queue.t4_eq_status_entries) *
		sizeof(*srq->wq.queue);
	if (ucontext)
		srq->wq.memsize = roundup(srq->wq.memsize, PAGE_SIZE);

	ret = alloc_srq_queue(srq, ucontext ? &ucontext->uctx :
			&rhp->rdev.uctx, srq->wr_waitp);
	if (ret)
		goto err_free_skb;
	attrs->attr.max_wr = rqsize - 1;

	if (CHELSIO_CHIP_VERSION(rhp->rdev.lldi.adapter_type) > CHELSIO_T6)
		srq->flags = T4_SRQ_LIMIT_SUPPORT;

	if (udata) {
		srq_key_mm = kmalloc(sizeof(*srq_key_mm), GFP_KERNEL);
		if (!srq_key_mm) {
			ret = -ENOMEM;
			goto err_free_queue;
		}
		srq_db_key_mm = kmalloc(sizeof(*srq_db_key_mm), GFP_KERNEL);
		if (!srq_db_key_mm) {
			ret = -ENOMEM;
			goto err_free_srq_key_mm;
		}
		memset(&uresp, 0, sizeof(uresp));
		uresp.flags = srq->flags;
		uresp.qid_mask = rhp->rdev.qpmask;
		uresp.srqid = srq->wq.qid;
		uresp.srq_size = srq->wq.size;
		uresp.srq_memsize = srq->wq.memsize;
		uresp.rqt_abs_idx = srq->wq.rqt_abs_idx;
		spin_lock(&ucontext->mmap_lock);
		uresp.srq_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.srq_db_gts_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		spin_unlock(&ucontext->mmap_lock);
		ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (ret)
			goto err_free_srq_db_key_mm;
		srq_key_mm->key = uresp.srq_key;
		srq_key_mm->addr = virt_to_phys(srq->wq.queue);
		srq_key_mm->len = PAGE_ALIGN(srq->wq.memsize);
		insert_mmap(ucontext, srq_key_mm);
		srq_db_key_mm->key = uresp.srq_db_gts_key;
		srq_db_key_mm->addr = (u64)(unsigned long)srq->wq.bar2_pa;
		srq_db_key_mm->len = PAGE_SIZE;
		insert_mmap(ucontext, srq_db_key_mm);
	}

	pr_debug("%s srq qid %u idx %u size %u memsize %lu num_entries %u\n",
		 __func__, srq->wq.qid, srq->idx, srq->wq.size,
			(unsigned long)srq->wq.memsize, attrs->attr.max_wr);

	spin_lock_init(&srq->lock);
	return 0;

err_free_srq_db_key_mm:
	kfree(srq_db_key_mm);
err_free_srq_key_mm:
	kfree(srq_key_mm);
err_free_queue:
	free_srq_queue(srq, ucontext ? &ucontext->uctx : &rhp->rdev.uctx,
		       srq->wr_waitp);
err_free_skb:
	kfree_skb(srq->destroy_skb);
err_free_srq_idx:
	c4iw_free_srq_idx(&rhp->rdev, srq->idx);
err_free_wr_wait:
	c4iw_put_wr_wait(srq->wr_waitp);
	return ret;
}

int c4iw_create_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *attrs,
			       struct ib_udata *udata)
{
	/*
	 * XXX attrs->attr.srq_limit[31:31] == 1 indicates a raw SRQ!
	 */
	if (((attrs->attr.srq_limit >> 31) & 1) == 1)
		return create_raw_srq(ib_srq, attrs, udata);
	return create_srq(ib_srq, attrs, udata);
}

int c4iw_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct c4iw_srq *srq = to_c4iw_srq(ibsrq);

	if (srq->fcl.type == RAW_SRQ)
		destroy_raw_srq(ibsrq);
	else
		destroy_srq(ibsrq, udata);

	return 0;
}
