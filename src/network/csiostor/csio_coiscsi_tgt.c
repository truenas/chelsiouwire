/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions for COiSCSI I/O handling
 *
 */
#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_snode.h>
#include <csio_lnode_coiscsi.h>
#include <csio_isns.h>
#include <csio_coiscsi_tgt.h>
#include <csio_foiscsi.h>
#include <csio_coiscsi_external.h>
#include <csio_ctrl_foiscsi.h>
#include <linux/bug.h>

extern struct uld_tgt_handler *chiscsi_handlers;

static inline struct coiscsi_dbuf *
coiscsi_get_dbuf(struct csio_coiscsi_tgtm *tgtm)
{
	struct coiscsi_dbuf *dbuf = NULL;
	unsigned long flags;

	csio_vdbg(tgtm->hw, "tgtm:%p, dbuf:%p, n_free_dbuf:%u\n",
			tgtm, dbuf, tgtm->stats.n_free_dbuf);
	csio_spin_lock_irqsave(tgtm->hw, &tgtm->dbuf_flist_lck, flags);
	csio_deq_from_head(&tgtm->dbuf_flist, &dbuf);

	if (dbuf) {
		CSIO_DEC_STATS(tgtm, n_free_dbuf);
		csio_elem_init(&dbuf->list);
	}
	csio_vdbg(tgtm->hw, "tgtm:%p, dbuf:%p, n_free_dbuf:%u\n",
			tgtm, dbuf, tgtm->stats.n_free_dbuf);

	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->dbuf_flist_lck, flags);


	return dbuf;
}

static inline void
coiscsi_put_dbuf(struct csio_coiscsi_tgtm *tgtm,
		struct coiscsi_dbuf *dbuf)
{
	unsigned long flags;

	csio_vdbg(tgtm->hw, "tgtm:%p, dbuf:%p, n_free_dbuf:%u\n",
			tgtm, dbuf, tgtm->stats.n_free_dbuf);

	csio_spin_lock_irqsave(tgtm->hw, &tgtm->dbuf_flist_lck, flags);
	csio_enq_at_tail(&tgtm->dbuf_flist, &dbuf->list);
	CSIO_INC_STATS(tgtm, n_free_dbuf);
	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->dbuf_flist_lck, flags);
	
	return;
}

static inline struct csio_coiscsi_rcvreq *
csio_coiscsi_get_rcvreq(struct csio_rnode_coiscsi *rnc)
{
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_hw *hw = NULL;
	unsigned long flags;
	
	CSIO_ASSERT(rnc);

	rn = rnc->rn;
	sn = csio_rnode_to_snode(rn);
	hw = sn->hwp;

	csio_vdbg(hw, "rn:%p sn:%p, hw:%p \n",
			rn, sn, hw);
	
	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_vdbg(hw, "tgtm:%p.\n", tgtm);

	csio_spin_lock_irqsave(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);
	csio_deq_from_head(&tgtm->rcvreq_flist, &rcvreq);

	if (rcvreq) {
		csio_elem_init(&rcvreq->list);
		csio_head_init(&rcvreq->bufhead);
		rcvreq->hw = hw;
		rcvreq->rnode = rn;
		CSIO_DEC_STATS(tgtm, n_free_rcvreq);
	}

	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);
	
	csio_vdbg(tgtm->hw, "tgtm:%p, rcvreq:%p, n_free_rcvreq:%u\n",
			tgtm, rcvreq, tgtm->stats.n_free_rcvreq);
	return rcvreq;

}

void csio_coiscsi_put_rcvreq(struct csio_coiscsi_rcvreq *rcvreq)
{
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct coiscsi_dbuf *dbuf = NULL;
	unsigned long flags;
	
	CSIO_ASSERT(rcvreq->hw);

	tgtm = csio_hw_to_coiscsi_tgtm(rcvreq->hw);

	csio_vdbg(tgtm->hw, "tgtm:%p, rcvreq:%p, n_free_rcvreq:%u\n",
			tgtm, rcvreq, tgtm->stats.n_free_rcvreq);

	csio_spin_lock_irqsave(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);
	while (!csio_list_empty(&rcvreq->bufhead)) {
		csio_deq_from_head(&rcvreq->bufhead, &dbuf);
		csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);
		csio_dma_pool_free(&dbuf->dmahdl, dbuf->addr);
		csio_spin_lock_irqsave(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);
		coiscsi_put_dbuf(tgtm, dbuf);
	}
	rcvreq->hw = NULL;
	csio_enq_at_tail(&tgtm->rcvreq_flist, &rcvreq->list);
	CSIO_INC_STATS(tgtm, n_free_rcvreq);
	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->rcvreq_flist_lck, flags);

	csio_vdbg(tgtm->hw, "tgtm:%p, rcvreq:%p, n_free_rcvreq:%u\n",
			tgtm, rcvreq, tgtm->stats.n_free_rcvreq);
}
EXPORT_SYMBOL(csio_coiscsi_put_rcvreq);

void coiscsi_init_cmpl_tgtreq(struct csio_coiscsi_tgtreq *treq)
{
	init_completion(&treq->cmpl_obj.cmpl);
	treq->wait_cmpl = 1;
}
EXPORT_SYMBOL(coiscsi_init_cmpl_tgtreq);

void coiscsi_wait_cmpl_tgtreq(struct csio_coiscsi_tgtreq *treq)
{
	wait_for_completion(&treq->cmpl_obj.cmpl);
}
EXPORT_SYMBOL(coiscsi_wait_cmpl_tgtreq);

void coiscsi_lock_tgtreq(struct csio_coiscsi_tgtreq *tgtreq)
{
	csio_spin_lock_irq(tgtreq->hw, &tgtreq->lock);
}
EXPORT_SYMBOL(coiscsi_lock_tgtreq);

void coiscsi_unlock_tgtreq(struct csio_coiscsi_tgtreq *tgtreq)
{
	csio_spin_unlock_irq(tgtreq->hw, &tgtreq->lock);
}
EXPORT_SYMBOL(coiscsi_unlock_tgtreq);

/* function to mark treq to be freed by cmpl handler */
void coiscsi_done_tgtreq(struct csio_coiscsi_tgtreq *tgtreq)
{
	csio_spin_lock_irq(tgtreq->hw, &tgtreq->lock);
	/* if tgtreq is waiting for cmpl mark it as free
	 * the cmpl handler will free it, if not put treq
	 */
	if (tgtreq->treq_wait) {
		csio_coiscsi_tgtreq_set_state(tgtreq,
				CSIO_COISCSI_TGTREQ_STATE_FREE);
		csio_spin_unlock_irq(tgtreq->hw, &tgtreq->lock);

		//DEBUG
		csio_warn(tgtreq->hw, "%s: marking treq:%p as free sc:%p \n",
				__func__, tgtreq, tgtreq->sc_cmd);
	} else  {
		csio_spin_unlock_irq(tgtreq->hw, &tgtreq->lock);
		coiscsi_put_tgtreq(tgtreq);
	}
}
EXPORT_SYMBOL(coiscsi_done_tgtreq);


void coiscsi_put_tgtreq(struct csio_coiscsi_tgtreq *tgtreq)
{
	struct csio_coiscsi_tgtm *tgtm = NULL;
	unsigned long flags;
	enum csio_coiscsi_tgtreq_state state;
	
	CSIO_ASSERT(tgtreq);
	CSIO_ASSERT(tgtreq->hw);

	tgtm = csio_hw_to_coiscsi_tgtm(tgtreq->hw);


	//DEBUG code
	if (tgtreq->treq_wait)
		csio_err(tgtm->hw, "tgt:%p freed before cmpl sc:%p \n",
				tgtreq, tgtreq->sc_cmd);
	
	csio_spin_lock_irqsave(tgtm->hw, &tgtm->freelist_lock, flags);
	state = csio_coiscsi_tgtrq_get_state(tgtreq);
	/* assert on double free */
	CSIO_ASSERT(state != CSIO_COISCSI_TGTREQ_STATE_UNINIT);
	tgtreq->rnode  = NULL;
	tgtreq->sc_cmd = NULL;
	tgtreq->flags  = 0;
	tgtreq->op     = 0;
	tgtreq->treq_wait = 0;

	csio_coiscsi_tgtreq_set_state(tgtreq,
			CSIO_COISCSI_TGTREQ_STATE_UNINIT);

	csio_enq_at_tail(&tgtm->tgtreq_freelist,
				&tgtreq->sm.sm_list);
	CSIO_INC_STATS(tgtm, n_free_tgtreq);
	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->freelist_lock, flags);

	csio_vdbg(tgtm->hw, "tgtm:%p, tgtreq:%p, n_free_tgtreq:%u\n",
			tgtm, tgtreq, tgtm->stats.n_free_tgtreq);
	return;
}
EXPORT_SYMBOL(coiscsi_put_tgtreq);

struct csio_coiscsi_tgtreq 
	*coiscsi_get_tgtreq(struct csio_rnode_coiscsi *rnc, void *sc)
{
	struct csio_coiscsi_tgtreq *tgtreq = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_hw *hw = NULL;
	unsigned long flags;
	
	CSIO_ASSERT(rnc);

	rn = rnc->rn;
	sn = csio_rnode_to_snode(rn);
	hw = sn->hwp;
	
	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_vdbg(hw, "tgtm:%p.\n", tgtm);


	csio_spin_lock_irqsave(tgtm->hw, &tgtm->freelist_lock, flags);
	csio_deq_from_head(&tgtm->tgtreq_freelist, &tgtreq);

	if (tgtreq) {
		csio_elem_init(&tgtreq->rlist);
		csio_elem_init(&tgtreq->tlist);
		tgtreq->rnode = rn;
		tgtreq->sc_cmd = sc;
		tgtreq->flags  = 0;
		tgtreq->op     = 0;
		tgtreq->def_treq = 0;
		csio_coiscsi_tgtreq_set_state(tgtreq,
			CSIO_COISCSI_TGTREQ_STATE_INUSE);
		CSIO_DEC_STATS(tgtm, n_free_tgtreq);
	}

	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->freelist_lock, flags);
	
	csio_vdbg(tgtm->hw, "tgtm:%p, tgtreq:%p, n_free_tgtreq:%u\n",
			tgtm, tgtreq, tgtm->stats.n_free_tgtreq);

	return tgtreq;
}
EXPORT_SYMBOL(coiscsi_get_tgtreq);

int coiscsi_get_treq_credit(struct csio_rnode_coiscsi *rnc)
{
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_hw *hw = NULL;
	uint32_t credit = 0, avail = 0, req_cnt = 0;
	unsigned long flags;

	CSIO_ASSERT(rnc);

	rn = rnc->rn;
	sn = csio_rnode_to_snode(rn);
	hw = sn->hwp;
	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_spin_lock_irqsave(tgtm->hw, &tgtm->tcredit_lock, flags);
	avail = CSIO_GET_STATS(tgtm, tcredit_avail);
	req_cnt = CSIO_GET_STATS(tgtm, tcredit_req_cnt);

	if (avail && (req_cnt < COISCSI_TREQ_NUM_REQS_MAX)) {
		if (req_cnt < COISCSI_TREQ_SLAB_HI_REQS)
			credit = COISCSI_TREQ_HI_CREDIT;
		else if (req_cnt < COISCSI_TREQ_SLAB_MI_REQS)
			credit = COISCSI_TREQ_MI_CREDIT;
		else
			credit = COISCSI_TREQ_LO_CREDIT;
		
		credit = CSIO_MIN(credit, avail);
		CSIO_DEC_STATS_BY(tgtm, tcredit_avail, credit);
		CSIO_INC_STATS(tgtm, tcredit_req_cnt);
		CSIO_ASSERT((credit == COISCSI_TREQ_HI_CREDIT) ||
				(credit == COISCSI_TREQ_MI_CREDIT) ||
				(credit == COISCSI_TREQ_LO_CREDIT));
	}

	avail = CSIO_GET_STATS(tgtm, tcredit_avail);
	req_cnt = CSIO_GET_STATS(tgtm, tcredit_req_cnt);
	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->tcredit_lock, flags);

	CSIO_ASSERT(req_cnt <= COISCSI_TREQ_NUM_REQS_MAX);
	csio_warn(hw, "%s: credits-get = %d avail:%u req_cnt:%u \n",
			__func__, credit, avail, req_cnt);
	return credit;
}
EXPORT_SYMBOL(coiscsi_get_treq_credit);

int coiscsi_put_treq_credit(struct csio_rnode_coiscsi *rnc, uint32_t credit)
{
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_hw *hw = NULL;
	unsigned long flags;

	CSIO_ASSERT(rnc);
	rn = rnc->rn;
	sn = csio_rnode_to_snode(rn);
	hw = sn->hwp;
	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	CSIO_ASSERT(tgtm->stats.tcredit_req_cnt && 
			((credit == COISCSI_TREQ_HI_CREDIT) ||
			(credit == COISCSI_TREQ_MI_CREDIT) ||
			(credit == COISCSI_TREQ_LO_CREDIT)));

	csio_spin_lock_irqsave(tgtm->hw, &tgtm->tcredit_lock, flags);
	CSIO_DEC_STATS(tgtm, tcredit_req_cnt);
	CSIO_INC_STATS_BY(tgtm, tcredit_avail, credit);
	csio_spin_unlock_irqrestore(tgtm->hw, &tgtm->tcredit_lock, flags);

	CSIO_ASSERT(tgtm->stats.tcredit_avail <= COISCSI_TREQ_CREDIT_LIMIT);
	csio_warn(hw, "%s: credit-put = %d avail = %u req_cnt = %u\n",
			__func__, credit, tgtm->stats.tcredit_avail,
			tgtm->stats.tcredit_req_cnt);
	return 0;
}
EXPORT_SYMBOL(coiscsi_put_treq_credit);

static inline struct csio_rnode *
coiscsi_rnode_ioid_lookup(struct csio_hw *hw, uint32_t ioid)
{
	struct csio_list *tmp, *tmp1, *nxt;
	struct coiscsi_snode *sn;
	struct csio_rnode *rn = NULL;
	struct csio_coiscsi_tgtm *tgtm;

	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_list_for_each(tmp, &tgtm->snhead) {

		sn = (struct coiscsi_snode *)tmp;

		if (test_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags))
			continue;

		csio_read_lock(hw, &sn->sn_rwlock);
		csio_list_for_each_safe(tmp1, nxt, &sn->rnhead) {

			rn = (struct csio_rnode *)tmp1;
			csio_vdbg(hw, "rn:%p, rn->flowid:0x%x\n", rn, rn->flowid);
			
			if (rn->flowid == ioid) {
				csio_read_unlock(hw, &sn->sn_rwlock);
				return rn;
			}
		}
		csio_read_unlock(hw, &sn->sn_rwlock);
	}

	return NULL;
}

int coiscsi_flb_to_dbuf(struct csio_coiscsi_rcvreq *rcvreq,
		struct csio_fl_dma_buf *flb, uint32_t offset,
		bool enq_at_head)
{
	int32_t rc = CSIO_SUCCESS;
	uint32_t tlen;
	struct csio_coiscsi_tgtm *tgtm;
	struct coiscsi_dbuf *dbuf;
	struct csio_dma_buf *buf;
	int32_t i = 0;
	
	tgtm = csio_hw_to_coiscsi_tgtm(rcvreq->hw);
	
	tlen = flb->totlen;
	buf = flb->flbufs;

	while (tlen) {
		csio_vdbg(tgtm->hw, "tlen [%u], buf->len [%u], buf [%p], "
				"offset:%u\n",
				tlen, buf->len, buf,
				i ? 0 : offset);

		dbuf = coiscsi_get_dbuf(tgtm);
		CSIO_ASSERT(dbuf);

		dbuf->addr = dbuf->raddr = buf->vaddr;
		dbuf->len = dbuf->rlen =  buf->len;
		csio_memcpy(&dbuf->dmahdl, &buf->dmahdl, sizeof(csio_dma_obj_t));
		
		if (!i && offset) {
			dbuf->raddr = buf->vaddr + offset;
			dbuf->rlen = buf->len - offset;
			i++;
		}

#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
		csio_dump_buffer(dbuf->raddr, dbuf->rlen);
#endif

		if (enq_at_head)
			csio_enq_at_head(&rcvreq->bufhead, &dbuf->list);
		else
			csio_enq_at_tail(&rcvreq->bufhead, &dbuf->list);

		tlen -= buf->len;
		if (enq_at_head && tlen) {
			csio_err(tgtm->hw, "ihdr, nbuf > 1, tlen %u\n", tlen);
			return CSIO_INVAL; /*TODO handle error*/
		}

		buf++;
	}

	return rc;
}

int coiscsi_process_iscsi_hdr(struct csio_hw *hw, void *cpl,
		struct csio_fl_dma_buf *flb)
{
	struct cpl_iscsi_hdr *ihdr = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_coiscsi *rnc = NULL;
	uint32_t rnio_id;
	int32_t rc = CSIO_SUCCESS;

	CSIO_ASSERT(flb && cpl && hw);

	ihdr = (struct cpl_iscsi_hdr *)
		((uint8_t *)flb->flbufs[0].vaddr + flb->offset);

	CSIO_ASSERT(ihdr);

	csio_vdbg(hw, "ihdr:%p\n", ihdr);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_buffer((uint8_t*)ihdr, sizeof(*ihdr));
#endif
	rnio_id = GET_TID(ihdr);

	csio_vdbg(hw, "rnio_id:0x%x", rnio_id);

	rn = coiscsi_rnode_ioid_lookup(hw, rnio_id);
	if (!rn) {
		csio_dbg(hw, "No rnode found for conn id [%u], bailing out.",
				rnio_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	rnc = csio_rnode_to_coiscsi(rn);
	if(!rnc->ch_conn) {
		csio_dbg(hw, "Connection to rnode %p closed\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	/* 
	 * Do not process any IO when rnode is in CLOSING state. rnode
	 * is marked CLOSING when target is stopped
	 */
	if(rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_dbg(hw, "Rnode %p found on closing state\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	rcvreq = csio_coiscsi_get_rcvreq(rnc);
	CSIO_ASSERT(rcvreq);

	csio_rnode_to_coiscsi(rn)->rcvreq = rcvreq;
	coiscsi_flb_to_dbuf(rcvreq, flb, sizeof(*ihdr), false);

out:
	return rc;
}

int coiscsi_process_iscsi_data(struct csio_hw *hw, void *cpl,
		struct csio_fl_dma_buf *flb)
{
	struct cpl_iscsi_data *idata = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_coiscsi *rnc = NULL;
	uint32_t rnio_id;
	int32_t rc = CSIO_SUCCESS;

	CSIO_ASSERT(flb && cpl && hw);

	idata = (struct cpl_iscsi_data *)
		((uint8_t *)flb->flbufs[0].vaddr + flb->offset);

	CSIO_ASSERT(idata);

	csio_vdbg(hw, "idata:%p\n", idata);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_buffer((uint8_t*)idata, sizeof(*idata));
#endif
	rnio_id = GET_TID(idata);

	csio_vdbg(hw, "rnio_id:0x%x", rnio_id);

	rn = coiscsi_rnode_ioid_lookup(hw, rnio_id);
	if (!rn) {
		csio_dbg(hw, "No rnode found for conn id [%u], bailing out.",
				rnio_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	rnc = csio_rnode_to_coiscsi(rn);
	if(!rnc->ch_conn) {
		csio_dbg(hw, "Connection to rnode %p closed\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	/* 
	 * Do not process any IO when rnode is in CLOSING state. rnode
	 * is marked CLOSING when target is stopped
	 */
	if(rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_dbg(hw, "Rnode %p found on closing state\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	rcvreq = csio_rnode_to_coiscsi(rn)->rcvreq;
	if (rcvreq) {
		coiscsi_flb_to_dbuf(rcvreq, flb, sizeof(*idata), false);
	} else {
		rcvreq = csio_coiscsi_get_rcvreq(rnc);
		CSIO_ASSERT(rcvreq);

		csio_rnode_to_coiscsi(rn)->rcvreq = rcvreq;
		coiscsi_flb_to_dbuf(rcvreq, flb, sizeof(*idata), false);
	}

out:
	return rc;
}

int coiscsi_process_iscsi_ddp(struct csio_hw *hw, void *cpl,
		struct csio_fl_dma_buf *flb)
{
	struct cpl_rx_iscsi_ddp *iddp = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_coiscsi *rnc = NULL;
	uint32_t rnio_id;
	int32_t rc = CSIO_SUCCESS;

	csio_vdbg(hw, "hw:%p, cpl:%p, flb:%p\n", hw,
			cpl, flb);

	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_vdbg(hw, "tgtm:%p.\n", tgtm);

	iddp = (struct cpl_rx_iscsi_ddp *)((uintptr_t)cpl + sizeof (__be64));

	csio_vdbg(hw, "iddp:%p\n", iddp);

#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_buffer((uint8_t*)iddp, sizeof(*iddp));
#endif

	rnio_id = GET_TID(iddp);

	csio_vdbg(hw, "rnio_id:0x%x", rnio_id);

	rn = coiscsi_rnode_ioid_lookup(hw, rnio_id);
	if (!rn) {
		csio_vdbg(hw, "No rnode found for conn id [%u], bailing out.\n",
				rnio_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	rnc = csio_rnode_to_coiscsi(rn);
	if(!rnc->ch_conn) {
		csio_dbg(hw, "Connection to rnode %p closed\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}


	/*
	 * Do not process any IO when rnode is in CLOSING state. rnode
	 * is marked CLOSING when target is stopped
	 */
	if(rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_dbg(hw, "Rnode %p found on closing state\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	rcvreq = csio_rnode_to_coiscsi(rn)->rcvreq;
	if (!rcvreq) {
		csio_err(hw, "No rcvreq found for conn id:0x%x, bailing out.\n",
				rnio_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	rcvreq->status = csio_be32_to_cpu(iddp->ddpvld);

	if (rcvreq->status & 0x7F68000) {
		CSIO_INC_STATS(tgtm, n_ddp_miss);
		csio_dbg(hw, "rcvreq->status 0x%x \n",rcvreq->status);
	}

	if (chiscsi_handlers && chiscsi_handlers->recv_data) {
		csio_vdbg(hw, "%s: calling recv_data() tgtreq:0x%p\n",
			__func__, rcvreq);
		chiscsi_handlers->recv_data(rcvreq);
		CSIO_INC_STATS(tgtm, n_ddp_pass);
	}

	csio_rnode_to_coiscsi(rn)->rcvreq = NULL;

out:
	return rc;
}

int coiscsi_process_iscsi_cmp(struct csio_hw *hw, void *cpl,
		struct csio_fl_dma_buf *flb)
{
	struct cpl_rx_iscsi_cmp *cmp = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_coiscsi *rnc = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	uint32_t rnio_id;
	int32_t rc = CSIO_SUCCESS;

	CSIO_ASSERT(flb && cpl && hw);

	tgtm = csio_hw_to_coiscsi_tgtm(hw);
	csio_vdbg(hw, "tgtm:%p.\n", tgtm);

	cmp = (struct cpl_rx_iscsi_cmp *)
		((uint8_t *)flb->flbufs[0].vaddr + flb->offset);

	CSIO_ASSERT(cmp);

	csio_vdbg(hw, "cmp:%p\n", cmp);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_buffer((uint8_t*)cmp, sizeof(*cmp));
#endif
	rnio_id = GET_TID(cmp);

	csio_vdbg(hw, "rnio_id:0x%x", rnio_id);

	rn = coiscsi_rnode_ioid_lookup(hw, rnio_id);
	if (!rn) {
		csio_dbg(hw, "No rnode found for conn id [%u], bailing out.",
				rnio_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	rnc = csio_rnode_to_coiscsi(rn);
	if(!rnc->ch_conn) {
		csio_dbg(hw, "Connection to rnode %p closed\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	/* 
	 * Do not process any IO when rnode is in CLOSING state. rnode
	 * is marked CLOSING when target is stopped
	 */
	if(rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_dbg(hw, "Rnode %p found on closing state\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	rcvreq = csio_rnode_to_coiscsi(rn)->rcvreq;
	if (rcvreq) {
		coiscsi_flb_to_dbuf(rcvreq, flb, sizeof(*cmp), true);
	} else {
		rcvreq = csio_coiscsi_get_rcvreq(rnc);
		CSIO_ASSERT(rcvreq);

		rcvreq->ddp_cmp = 1;
		coiscsi_flb_to_dbuf(rcvreq, flb, sizeof(*cmp), false);
	}

	rcvreq->status = csio_be32_to_cpu(cmp->ddpvld);

	if (rcvreq->status & 0x7F68000) {
		CSIO_INC_STATS(tgtm, n_ddp_miss);
		csio_err(hw, "rcvreq->status 0x%x \n", rcvreq->status);
	}

	if (chiscsi_handlers && chiscsi_handlers->recv_data) {
		csio_vdbg(hw, "%s: calling recv_data() tgtreq:0x%p\n",
			__func__, rcvreq);
		chiscsi_handlers->recv_data(rcvreq);
		CSIO_INC_STATS(tgtm, n_ddp_pass);
	}

	csio_rnode_to_coiscsi(rn)->rcvreq = NULL;
out:
	return rc;
}

int csio_coiscsi_cmpl_handler(struct csio_hw *hw, void *dp)
{
	struct fw_coiscsi_tgt_xmit_wr *wr = dp;
	struct csio_coiscsi_tgtreq *tr = 
		(struct csio_coiscsi_tgtreq *) csio_be64_to_cpu(wr->cookie);
	struct csio_rnode *rn = NULL;
	int32_t rc = CSIO_SUCCESS;
	unsigned long flags;

	CSIO_ASSERT(tr);
	csio_spin_lock_irqsave(hw, &tr->lock, flags);

	/* no upcall if treq is not in use */
	if (!csio_coiscsi_tgtreq_is_state(tr,
			CSIO_COISCSI_TGTREQ_STATE_INUSE)) {
		csio_warn(hw, "%s:cmpl for treq:%p not in use sc:%p state:%d\n",
				__func__, tr, tr->sc_cmd, tr->state);
		goto out;
	}

	/* get rn from tgt req */
	rn = tr->rnode;

	csio_vdbg(hw, "wr:%p tr:%p trn:%p &rn:%p priv:%p\n",
			wr, tr, tr->rnode, &tr->rnode, tr->wr_priv);

	if (!rn) {
		csio_warn(hw, "%s: Null RN. treq:%p wr:%p \n",
						__func__, tr, wr);
		goto out;
	}

	/* if RN is marked for closing drop cmpl */
	if (rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_warn(hw, "%s: wr:%p tr:%p rn:%p in closing state\n",
				__func__, wr, tr, rn);
		goto out;
	}
	
	tr->wr_status =
		G_FW_COISCSI_TGT_XMIT_WR_CMPL_STATUS(be32_to_cpu(wr->u.cs.cmpl_status_pkd));
	tr->pdu_ndsn  = csio_be32_to_cpu(wr->cu.datasn);

	if (chiscsi_handlers && 
			chiscsi_handlers->cmpl_handler) {
		chiscsi_handlers->cmpl_handler(wr, tr);
	}

out:
	/* if worker thread is waiting */
	if (tr->wait_cmpl) {
		complete(&tr->cmpl_obj.cmpl);
		tr->wait_cmpl = 0;
		//DEBUG
		csio_warn(hw, ":%s :abort treq:%p jiffies:%lu \n",
				__func__, tr, jiffies);
	}
	/* set treq wait to 0 */
	tr->treq_wait = 0;

	/* free treq if marked as free */
	if (csio_coiscsi_tgtreq_is_state(tr,
			CSIO_COISCSI_TGTREQ_STATE_FREE) ||
			tr->def_treq) {
		csio_dbg(hw, "%s:freeing marked treq:%p sc:%p def:%d\n",
				__func__, tr, tr->sc_cmd, tr->def_treq);
		csio_spin_unlock_irqrestore(hw, &tr->lock, flags);
		coiscsi_put_tgtreq(tr);
	} else {
		csio_spin_unlock_irqrestore(hw, &tr->lock, flags);
	}

	return rc;
}

int 
coiscsi_process_data(struct csio_hw *hw, void *cpl, struct csio_fl_dma_buf *flb)
{
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct cpl_rx_data rx_data;
	struct csio_dma_buf *buf = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_isns *rns = NULL;
	struct csio_list *tmp = NULL;
	uint8_t *tcp_pld;
	uint8_t *isns_rsp;
	uint16_t offset;
	uint32_t flow_id;
	uint32_t tlen;
	uint16_t rsp_len;
	int32_t rc = CSIO_SUCCESS;

	/* Right now CPL_RX_DATA is handled only for iSNS management */
	if (!isnsm->init_done) {
		csio_err(hw, "Unexpected CPL_RX_DATA received, ret: 0x%x\n",
				CSIO_EINVAL);
		return CSIO_EINVAL;
	}

	tlen = flb->totlen;
	buf  = flb->flbufs;
	csio_dbg(hw, "tlen %d buf %p\n", tlen, buf);

	tcp_pld = kzalloc(tlen, GFP_ATOMIC);
	if(!tcp_pld) {
		csio_err(hw, "kzalloc for tcp pld failed\n");
		return CSIO_ENOMEM;
	}

	/* Copy tcp payload from freelist buffer to local buffer */
	offset = 0;
	while(tlen) {
		csio_memcpy(tcp_pld + offset, buf->vaddr, buf->len);
		offset += buf->len;
		tlen -= buf->len;
		buf++;
	}

	memcpy((uint8_t *)&rx_data, tcp_pld, sizeof(struct cpl_rx_data));
	flow_id  = GET_TID(&rx_data);
	isns_rsp = tcp_pld + sizeof(struct cpl_rx_data);
	rsp_len  = flb->totlen - sizeof(struct cpl_rx_data);

	csio_dbg(hw, "flowid %d, isns_rsp %p, rsp_len %d cpl_rx_data size %d\n",
			flow_id, isns_rsp, rsp_len, (int)sizeof(struct cpl_rx_data));

	/* Search rn head in isnsm first */
	rn = csio_isns_rn_lookup(hw, &isnsm->rnhead, flow_id);
	if (!rn) {

		/* Search rn head in snode next */
		csio_list_for_each(tmp, &isnsm->snhead) {
			sn = (struct coiscsi_snode *)tmp;
			rn = csio_isns_rn_lookup(hw, &sn->rnhead, flow_id);
			if(rn)
				break;
		}	
	}

	if(!rn) {
		csio_err(hw, "No rnode found for conn id [%u], bailing out.\n",
				flow_id);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_err(hw, "rnode %p is closing, bailing out.\n",
				rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	rns = csio_rnode_to_isns(rn);
	if(!rns->ch_conn) {
		csio_err(hw, "Connection to rnode %p closed\n", rn);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (chiscsi_handlers && chiscsi_handlers->recv_isns_pdu) {
		rc = chiscsi_handlers->recv_isns_pdu(rsp_len, isns_rsp, 0, rns->ch_conn);
		if(rc) {
			csio_err(hw, "recv_isns_pdu failed\n");
			rc = CSIO_EINVAL;
			goto out;
		}
	}

out:
	if(tcp_pld)
		kfree(tcp_pld);

	return rc;
}

int coiscsi_process_xmit_wr(struct csio_hw *hw, struct fw_isns_xmit_wr *wr)
{
	isns_data *data = (isns_data *)wr->cookie;
	int rc = 0;

	csio_dbg(hw, "data %p data_wait_cmpl %d\n", data, data->data_wait_cmpl);
	if(data->data_wait_cmpl == 1) {
		complete(data->data_op_cmpl);
	} else {
		csio_err(hw, "isns_xmit_wr rcvd after data cmpl clear\n");
		rc = CSIO_EINVAL;
	}

	return rc;
}

int csio_coiscsi_tgt_isr(struct csio_hw *hw, void *cpl, uint32_t len,
		struct csio_fl_dma_buf *flb, void *priv)
{
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct cpl_fw6_msg *msg;
	uint8_t op, *wr;

	tgtm = csio_hw_to_coiscsi_tgtm(hw);

	op = ((struct rss_header *) cpl)->opcode;

	switch (op) {
	case CPL_ISCSI_HDR:
		coiscsi_process_iscsi_hdr(hw, cpl, flb);
		break;
	case CPL_ISCSI_DATA:
		coiscsi_process_iscsi_data(hw, cpl, flb);
		break;
	case CPL_RX_ISCSI_DDP:
		coiscsi_process_iscsi_ddp(hw, cpl, flb);
		break;
	case CPL_RX_ISCSI_CMP:
		coiscsi_process_iscsi_cmp(hw, cpl, flb);
		break;
	case CPL_RX_DATA:
		coiscsi_process_data(hw, cpl, flb);
		break;
	case CPL_FW6_MSG:
		msg = (struct cpl_fw6_msg *)((uintptr_t)cpl + sizeof(__be64));
		wr = (uint8_t *)(msg->data);
		if (*wr == FW_COISCSI_TGT_XMIT_WR) {
			csio_coiscsi_cmpl_handler(hw, (void*)wr);
			break;
		} else if(*wr == FW_ISNS_XMIT_WR) {
			coiscsi_process_xmit_wr(hw, (struct fw_isns_xmit_wr *)wr);
			break;
		}
		return 0;
	default:
		csio_dbg(hw, "Unhandled CPL op [0x%x]\n", op);
		return 0;
	}
	
	return 1;
}


static inline uint32_t
coiscsi_tgt_init_ultptx_dsgl(struct csio_hw *hw,
		struct csio_coiscsi_tgtreq *req, struct ulptx_sgl *sgl,
		uint32_t nsge)
{
	struct ulptx_sge_pair *sge_pair = NULL;
	struct data_sgl *sgel = req->tx_data.sgl;
	uint32_t i = 0;
	uint32_t len, totlen = 0;

	sgl->cmd_nsge = csio_htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			F_ULP_TX_SC_MORE |
			V_ULPTX_NSGE(nsge));

	for (i = 0; i < nsge; i++, sgel++) {
		if (i == 0) {
			/*csio_dbg(hw, "vaddr:%p, paddr:%p\n", sgel->addr, paddr);*/
			sgl->addr0 = csio_cpu_to_be64((uint64_t)csio_phys_addr(sgel->addr));
			len = sgel->len;
			sgl->len0 = csio_cpu_to_be32(len);
			totlen += len;
			sge_pair = (struct ulptx_sge_pair *)(sgl + 1);
			continue;
		}

		if ((i - 1) & 0x1) {
			/*csio_dbg(hw, "vaddr:%p, paddr:%p\n", sgel->addr, paddr);*/
			sge_pair->addr[1] = csio_cpu_to_be64((uint64_t)csio_phys_addr(sgel->addr));
			len = sgel->len;
			sge_pair->len[1] = csio_cpu_to_be32(len);
			totlen += len;
			sge_pair++;
		} else {
			/*csio_dbg(hw, "vaddr:%p, paddr:%p\n", sgel->addr, paddr);*/
			sge_pair->addr[0] = csio_cpu_to_be64((uint64_t)csio_phys_addr(sgel->addr));
			len = sgel->len;
			sge_pair->len[0] = csio_cpu_to_be32(len);
			totlen += len;
		}
	}

	return totlen;
}

static inline int
coiscsi_tgt_init_abort_wr(struct csio_hw *hw,
		struct csio_rnode *rn, struct csio_coiscsi_tgtreq *req,
		struct fw_coiscsi_tgt_xmit_wr *wr, uint32_t size)
{

	csio_memset(wr, 0, size);

	/* set only the needed fields for abort */
	wr->op_to_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_COISCSI_TGT_XMIT_WR) |
				(F_FW_COISCSI_TGT_XMIT_WR_ABORT) |
				(F_FW_WR_COMPL));

	wr->u.fllen.flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(rn->flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	wr->cookie = csio_cpu_to_be64((uint64_t)req);
	wr->iq_id = csio_cpu_to_be16(csio_q_physiqid(hw, rn->iq_idx));

	return 0;
}


static inline int
coiscsi_tgt_init_xmit_wr(struct csio_hw *hw,
		struct csio_rnode *rn, struct csio_coiscsi_tgtreq *req,
		struct fw_coiscsi_tgt_xmit_wr *wr, uint32_t size, uint32_t nsge)
{      
	struct csio_rnode_coiscsi *rnc;
	struct ulptx_sgl *sgl;
	uint32_t xfer_cnt;
	uint8_t *bhs;
	uint32_t inc_statsn = 0, statsn;

	rnc = csio_rnode_to_coiscsi(req->rnode);

	if (req->tx_data.bhs[0] == 0x25)
		req->tx_data.r2t_ddp = 0;

	if (rn->flags & CSIO_RNF_ADJ_PARAM) {
		statsn = csio_be32_to_cpu(*((uint32_t *)&req->tx_data.bhs[24]));
		if (statsn > rnc->statsn) {
			rnc->statsn = statsn;
			inc_statsn = 1;
		}
	}

	//csio_memset(wr, 0, sizeof(*wr));
	csio_memset(wr, 0, size);

	wr->op_to_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_COISCSI_TGT_XMIT_WR) |
		V_FW_COISCSI_TGT_XMIT_WR_HDGST(req->tx_data.hdigest_en) |
		V_FW_COISCSI_TGT_XMIT_WR_DDGST(req->tx_data.ddigest_en) |
		V_FW_COISCSI_TGT_XMIT_WR_FINAL(req->tx_data.final_req)  |
		V_FW_COISCSI_TGT_XMIT_WR_IMMDLEN(req->tx_data.imm_len)	|
		V_FW_COISCSI_TGT_XMIT_WR_PADLEN(req->tx_data.padlen)	|
		V_FW_COISCSI_TGT_XMIT_WR_DDP(req->tx_data.r2t_ddp)	|
		V_FW_COISCSI_TGT_XMIT_WR_INCSTATSN(inc_statsn)         | 
		V_FW_WR_COMPL(req->tx_data.cmpl_req));

	wr->u.fllen.flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(rn->flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	
	wr->cookie = csio_cpu_to_be64((uint64_t)req);
	
	wr->iq_id = csio_cpu_to_be16(csio_q_physiqid(hw, rn->iq_idx));


	wr->t_xfer_len = csio_cpu_to_be32(req->tx_data.totallen);
	wr->pz_off = csio_cpu_to_be32(req->tx_data.doffset);

	bhs = ((uint8_t *)wr + sizeof(struct fw_coiscsi_tgt_xmit_wr));

	csio_memcpy(bhs, req->tx_data.bhs, 48);

	/*  Move WR pointer past WR command */
	sgl = (struct ulptx_sgl *)((uintptr_t)(bhs) + 48);

	/*  Fill in the DSGL */
	xfer_cnt = coiscsi_tgt_init_ultptx_dsgl(hw, req, sgl, nsge);

	//DEBUG code
	if ((req->tx_data.bhs[0] == 0x25) && (xfer_cnt == 0)) {
		csio_err(hw, "ERROR: len:(%u == %u) cnt:(%u == %u) sgl:%p\n",
				xfer_cnt, req->tx_data.totallen, req->tx_data.sg_cnt, 
				nsge, sgl);
	}

	if (xfer_cnt < 0)
		return xfer_cnt;

	//wr->t_xfer_len = csio_cpu_to_be32(xfer_cnt);

	return 0;
}

static inline int32_t
coiscsi_calc_nsge_size(struct csio_coiscsi_tgtreq *req, uint32_t wrsz, uint32_t *nsge)
{
	int32_t size;

	*nsge = req->tx_data.sg_cnt;
	size = wrsz + 48 + sizeof(struct ulptx_sgl);

	if (csio_likely((*nsge) <= COISCSI_TGT_MAX_SGE)) {
		if (csio_unlikely((*nsge) > 1))
			size += (sizeof(struct ulptx_sge_pair) *
					(CSIO_ALIGN((*nsge - 1), 2) / 2));
	} else {
		size += (sizeof(struct ulptx_sge_pair) *
				(CSIO_ALIGN((COISCSI_TGT_MAX_SGE - 1), 2) / 2));
		*nsge = COISCSI_TGT_MAX_SGE;
	}

	size = CSIO_ALIGN(size, 16);

	return size;
}

/* no of times to retry wr for abort*/
#define WR_ABORT_RETRY_COUNT 10
int32_t coiscsi_abort_req(struct csio_coiscsi_tgtreq *req)
{
	struct csio_rnode_coiscsi *rnc = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_hw *hw = NULL;
	int32_t size, rc = CSIO_SUCCESS;
	uint32_t rcount = WR_ABORT_RETRY_COUNT;
	struct csio_wr_pair wrp;
	unsigned long flags;


	CSIO_ASSERT(req);

	rnc = csio_rnode_to_coiscsi(req->rnode);
	rn = rnc->rn;
	hw = req->hw;

	tgtm = csio_hw_to_coiscsi_tgtm(hw);
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_coiscsi_tgt_xmit_wr), 16);

wr_retry:
	rc = csio_wr_get(hw, rn->eq_idx, size, &wrp);

	if (csio_unlikely(rc != CSIO_SUCCESS)) {
		if (rcount--) {
			csio_warn(hw, "%s: wr_retry req:%p size:%d retry:%d\n",
					__func__, req, size, rcount); 
			goto wr_retry;
		} else {
			csio_warn(hw, "%s: wr get failed req:%p size:%d \n",
					__func__, req, size);
			goto out;
		}
	}

	req->op = COISCSI_TREQ_ABORT;

	if (wrp.size1 >= size) {
		/* initialize abort work request */
		coiscsi_tgt_init_abort_wr(hw, rn, req,
			(struct fw_coiscsi_tgt_xmit_wr*)wrp.addr1, size);

#ifdef __CSIO_DEBUG__
		csio_warn(hw, "%s: size:%u size1:%u \n",__func__, size, wrp.size1);
		csio_dump_wr_buffer((uint8_t *)wrp.addr1, size);
#endif
	} else {
		/* We don't need this block since we are ignoring the bhs
		 * when we send abort; if we include bhs then wr+bhs can
		 * exceed the min wr size and cause wrs to be wrapped.
		 * as for now preserving this block for future if we need
		 * to send anything more than 64bytes.
		 */ 
		uint8_t tmpwr[512];

		coiscsi_tgt_init_abort_wr(hw, rn, req,
			(struct fw_coiscsi_tgt_xmit_wr*)tmpwr, size);
		csio_memcpy(wrp.addr1, tmpwr, wrp.size1);
		csio_memcpy(wrp.addr2, tmpwr + wrp.size1, size - wrp.size1);

#ifdef __CSIO_DEBUG__
		csio_warn(hw, "%s: size:%u size1:%u \n",__func__, size, wrp.size1);
		csio_dump_wr_buffer((uint8_t *)tmpwr, size);
#endif
	}

	/* issue the wr */
	csio_wr_issue(hw, rn->eq_idx, CSIO_FALSE);
	
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	return rc;

}
EXPORT_SYMBOL(coiscsi_abort_req);

int32_t coiscsi_xmit_data(struct csio_coiscsi_tgtreq *req)
{
	struct csio_rnode_coiscsi *rnc = NULL;
	struct csio_coiscsi_tgtm *tgtm = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_hw *hw = NULL;
	int32_t size, rc = CSIO_SUCCESS;
	uint32_t nsge;
	uint32_t ddp_pgz = 4096;
	struct csio_wr_pair wrp;
	unsigned long flags;


	CSIO_ASSERT(req);

	rnc = csio_rnode_to_coiscsi(req->rnode);
	rn = rnc->rn;
	hw = req->hw;

	tgtm = csio_hw_to_coiscsi_tgtm(hw);
	
	csio_vdbg(hw, "req:%p, rn:%p, rnc:%p, hw:%p, sg_cnt:%u, "
			"hd:%u, dd:%u, tlen:%d\n",
			req, req->rnode, rnc, hw, req->tx_data.sg_cnt,
			req->tx_data.hdigest_en, req->tx_data.ddigest_en,
			req->tx_data.totallen);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_buffer(req->tx_data.bhs, 48);
#endif

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	if (rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_err(hw, "xmit on closed/closing conn rn:%p \n", rn);
		rc = CSIO_EIO;
		goto out;
	}

	size = coiscsi_calc_nsge_size(req, sizeof(struct fw_coiscsi_tgt_xmit_wr), &nsge);

	csio_vdbg(hw, "size:%u, nsge:%u\n", size, nsge);

	rc = csio_wr_get(hw, rn->eq_idx, size, &wrp);

	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	/* update stats for debugfs */
	if (req->tx_data.ddp_skip) {
		CSIO_INC_STATS(tgtm, n_ddp_skip);
		req->tx_data.ddp_skip = 0;
	}

	if (nsge && (req->tx_data.sgl[0].addr & (ddp_pgz -1))) {
		CSIO_INC_STATS(tgtm, n_poff_cnt);
	}

	if (wrp.size1 >= size) {
		rc = coiscsi_tgt_init_xmit_wr(hw, rn, req,
				(struct fw_coiscsi_tgt_xmit_wr*)wrp.addr1,
				size, nsge);
		if (rc)
			goto out;
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
		if (req->tx_data.bhs[0] == 0) {
		csio_dump_wr_buffer((uint8_t *)wrp.addr1, size);
		csio_dbg(hw, "1:xferlen:%d doff:%d size:%d nsge:%d dtag:%d\n",
				req->tx_data.totallen,
				req->tx_data.doffset, size, nsge,
				req->tx_data.r2t_ddp);
		}
#endif
	} else {
		uint8_t tmpwr[512];

		rc = coiscsi_tgt_init_xmit_wr(hw, rn, req,
				(struct fw_coiscsi_tgt_xmit_wr*)tmpwr,
				size, nsge);
		if (rc)
			goto out;
		csio_memcpy(wrp.addr1, tmpwr, wrp.size1);
		csio_memcpy(wrp.addr2, tmpwr + wrp.size1, size - wrp.size1);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
		if (req->tx_data.bhs[0] == 0) {
		csio_dump_wr_buffer((uint8_t *)tmpwr, size);
		csio_dbg(hw, "2:xferlen:%d doff:%d size:%d nsge:%d dtag:%d\n",
				req->tx_data.totallen,
				req->tx_data.doffset, size, nsge,
				req->tx_data.r2t_ddp);
		}
#endif
	}

	/* mark waiting for completion */
	if (req->tx_data.cmpl_req)
		req->treq_wait = 1;

	csio_wr_issue(hw, rn->eq_idx, CSIO_FALSE);
	
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	return rc;
}
EXPORT_SYMBOL(coiscsi_xmit_data);

csio_retval_t
csio_coiscsi_tgtm_init(struct csio_coiscsi_tgtm *tgtm, struct csio_hw *hw)
{
	int rc = CSIO_SUCCESS;
	int i;
	struct csio_coiscsi_tgtreq *tgtreq = NULL;
	struct csio_dma_buf *dmabuf = NULL;
	struct coiscsi_dbuf *dbuf = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	uint32_t tot_credits = 0;

	/* Lnode initilization */

	/* Target module initilization */

	tgtm->hw = hw;

	tgtm->proto_cmd_len = 48;
	tgtm->proto_rsp_len = 48;

	csio_head_init(&tgtm->drain_q);
	csio_head_init(&tgtm->unreg_cleanup_q);
	csio_head_init(&tgtm->sln_head);
	csio_head_init(&tgtm->snhead);

	csio_head_init(&tgtm->tgtreq_freelist);
	
	csio_spin_lock_init(&tgtm->freelist_lock);
	csio_spin_lock_init(&tgtm->dbuf_flist_lck);
	csio_spin_lock_init(&tgtm->rcvreq_flist_lck);
	csio_spin_lock_init(&tgtm->tcredit_lock);

	for (i = 0; i < CSIO_COISCSI_NUM_TGTRQS; i++) {

		tgtreq = csio_alloc(csio_md(hw, CSIO_COISCSI_TGTREQ_MD),
				sizeof(struct csio_coiscsi_tgtreq),
				CSIO_MNOWAIT);

		if (!tgtreq) {
			csio_err(hw, "tgtreq alloc failed for COiSCSI TGT"
					"module, Num allocated [%d]\n",
					tgtm->stats.n_free_tgtreq);
			goto err;
		}

		dmabuf = &tgtreq->dma_buf;
		dmabuf->vaddr = csio_dma_alloc(&dmabuf->dmahdl, hw->os_dev,
				tgtm->proto_rsp_len, 8, &dmabuf->paddr,
				CSIO_MNOWAIT);
		if (!dmabuf->vaddr) {
			csio_err(hw, "COiSCSI TGT resp DMA alloc falied.\n");
			csio_free(csio_md(hw, CSIO_COISCSI_TGTREQ_MD), tgtreq);
			goto err;
		}

		dmabuf->len = tgtm->proto_rsp_len;
		tgtreq->hw = hw;
		tgtreq->lnode = NULL;
		tgtreq->rnode = NULL;

		csio_spin_lock_init(&tgtreq->lock);

		csio_coiscsi_tgtreq_set_state(tgtreq,
				CSIO_COISCSI_TGTREQ_STATE_UNINIT);

		csio_enq_at_tail(&tgtm->tgtreq_freelist,
				&tgtreq->sm.sm_list);
		CSIO_INC_STATS(tgtm, n_free_tgtreq);
	}

	csio_dbg(hw, "&tgtm->rcvreq_flist:%p\n", &tgtm->rcvreq_flist);

	/* Allocate RCVREQ's */
	csio_head_init(&tgtm->rcvreq_flist);

	for (i = 0; i < CSIO_COISCSI_NUM_RCVRQS; i++) {
		
		rcvreq = csio_alloc(csio_md(hw, CSIO_COISCSI_RCVREQ_MD),
				sizeof(struct csio_coiscsi_rcvreq),
				CSIO_MNOWAIT);

		if (!rcvreq) {
			csio_err(hw, "coiscsi_rcvreq allocation failed for COiSCSI TGT "
					"module. Num allocated [%d]\n",
					tgtm->stats.n_free_rcvreq);
			goto err;
		}

		csio_enq_at_tail(&tgtm->rcvreq_flist, &rcvreq->list);
		CSIO_INC_STATS(tgtm, n_free_rcvreq);
	}

	csio_dbg(hw, "&tgtm->rcvreq_flist:%p\n", &tgtm->rcvreq_flist);


	/* Allocate DBUFS */
	csio_head_init(&tgtm->dbuf_flist);

	for (i = 0; i < COISCSI_NUM_DBUFS; i++) {
		
		dbuf = csio_alloc(csio_md(hw, CSIO_COISCSI_DBUF_MD),
				sizeof(struct coiscsi_dbuf),
				CSIO_MNOWAIT);

		/*csio_dbg(hw, "i:%d, dbuf:%p, dbuf_flist:%p, n_free_dbuf:%u\n",
				i, dbuf, &tgtm->dbuf_flist, tgtm->stats.n_free_dbuf);*/

		if (!dbuf) {
			csio_err(hw, "coiscsi_dbuf allocation failed for COiSCSI TGT "
					"module. Num allocated [%d]\n",
					tgtm->stats.n_free_dbuf);
			goto err;
		}

		csio_enq_at_tail(&tgtm->dbuf_flist, &dbuf->list);
		CSIO_INC_STATS(tgtm, n_free_dbuf);
	}
	
	/* initialize credits */
	tot_credits = COISCSI_TREQ_CREDIT_LIMIT +
		(uint32_t)BUILD_BUG_ON_ZERO(
			(COISCSI_TREQ_CREDIT_LIMIT > CSIO_COISCSI_NUM_TGTRQS));
	CSIO_SET_STATS(tgtm, tcredit_avail, tot_credits);
	CSIO_SET_STATS(tgtm, tcredit_req_max, COISCSI_TREQ_NUM_REQS_MAX);
	
	/* ioctl var inits */
	csio_mutex_init(&tgtm->ioctl_lock);
	tgtm->ioctl_pending = 0;


	csio_dbg(hw, "n_free_tgtreq:%u, n_free_dbuf:%u, n_free_rcvreq:%u\n",
			tgtm->stats.n_free_tgtreq,
			tgtm->stats.n_free_dbuf,
			tgtm->stats.n_free_rcvreq);
	return rc;

err:
	csio_coiscsi_tgtm_exit(tgtm);

	return CSIO_ENOMEM;
}

void csio_coiscsi_tgtm_exit(struct csio_coiscsi_tgtm *tgtm)
{
	struct csio_coiscsi_tgtreq *tgtreq = NULL;
	struct csio_dma_buf *dmabuf = NULL;
	struct coiscsi_dbuf *dbuf = NULL;
	struct csio_coiscsi_rcvreq *rcvreq = NULL;
	int i = 0;

	while (!csio_list_empty(&tgtm->tgtreq_freelist)) {
		csio_deq_from_head(&tgtm->tgtreq_freelist, &tgtreq);

		dmabuf = &tgtreq->dma_buf;
		CSIO_ASSERT(dmabuf->vaddr);
		csio_dma_free(&dmabuf->dmahdl, dmabuf->vaddr);
		csio_free(csio_md(tgtm->hw, CSIO_COISCSI_TGTREQ_MD), tgtreq);
		CSIO_DEC_STATS(tgtm, n_free_tgtreq);
	}


	while (!csio_list_empty(&tgtm->rcvreq_flist)) {

		csio_deq_from_head(&tgtm->rcvreq_flist, &rcvreq);
		csio_free(csio_md(tgtm->hw, CSIO_COISCSI_RCVREQ_MD), rcvreq);
		CSIO_DEC_STATS(tgtm, n_free_rcvreq);
		i++;
	}


	while (!csio_list_empty(&tgtm->dbuf_flist)) {

		csio_deq_from_head(&tgtm->dbuf_flist, &dbuf);
		csio_free(csio_md(tgtm->hw, CSIO_COISCSI_DBUF_MD), dbuf);
		CSIO_DEC_STATS(tgtm, n_free_dbuf);
	}

	csio_dbg(tgtm->hw, "n_free_tgtreq:%u, n_free_dbuf:%u, n_free_rcvreq:%u\n",
			tgtm->stats.n_free_tgtreq, tgtm->stats.n_free_dbuf,
			tgtm->stats.n_free_rcvreq);
	CSIO_DB_ASSERT(csio_list_empty(&tgtm->drain_q));
	CSIO_DB_ASSERT(csio_list_empty(&tgtm->unreg_cleanup_q));
	CSIO_ASSERT(!(tgtm->stats.n_free_tgtreq));
	CSIO_ASSERT(!(tgtm->stats.n_free_dbuf));
	CSIO_ASSERT(!(tgtm->stats.n_free_rcvreq));
	CSIO_ASSERT(!(tgtm->stats.tcredit_req_cnt));
	CSIO_ASSERT(tgtm->stats.tcredit_avail == COISCSI_TREQ_CREDIT_LIMIT);
}
