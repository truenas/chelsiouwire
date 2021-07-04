/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions to handle COiSCSI rnodes
 *
 */

#include <csio_os_init.h>
#include <csio_version.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_os_foiscsi.h>
#include <csio_lnode_coiscsi.h>
#include <csio_lnode.h>
#include <csio_snode.h>

#include <csio_trans_foiscsi.h>

#define MAC_ADDR_LEN                    6       /* in bytes */
#define IP_ADDR_LEN                     4       /* in bytes */

/**
 * csio_coiscsi_rn_lookup - Finds the rnode with the given flowid
 * @sn - snode
 * @flowid - flowid.
 * 
 * Does the rnode lookup on the given snode and flowid.If no matching entry
 * found, NULL is returned.
 */
struct csio_rnode *
csio_coiscsi_rn_lookup(struct coiscsi_snode *sn,
		uint32_t flowid)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &sn->rnhead;
	struct csio_list *tmp;
	struct csio_rnode *rn;

	if (csio_list_empty(&sn->rnhead)) {
		csio_dbg(sn->hwp, "RNODE list is empty\n");
		return NULL;
	}

	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		if (rn == NULL)
			return NULL;
		if (rn->flowid == flowid)
			return rn;
	}

	return NULL;
}

/**
 *  csio_get_rnt - Gets a free iSCSI rnode with the given flowid
 *  @ln - lnode
 */
struct csio_rnode_coiscsi *
csio_get_rnc(struct coiscsi_snode *sn, uint32_t flowid)
{
        struct csio_hw *hw = sn->hwp;
        struct csio_rnode *rn = NULL ;
        struct csio_rnode_coiscsi *rnc = NULL;

        rn = csio_coiscsi_rn_lookup(sn, flowid);
        csio_dbg(hw, "rn lookup [%p]\n", rn);
	/*CSIO_DB_ASSERT(!rn);*/
        if (!rn) {
		if (!csio_hw_to_ops(hw)->os_alloc_coiscsi_rnode)
			goto out;

		rn = csio_hw_to_ops(hw)->os_alloc_coiscsi_rnode(sn);
		if (!rn)
			goto out;

		rn->flowid = flowid;
		rnc = csio_rnode_to_coiscsi(rn);
		init_completion(&rnc->mod_cmplobj.cmpl);
		init_completion(&rnc->del_cmplobj.cmpl);

		/* take a ref to sn */
		coiscsi_snode_get_ref(sn);
		csio_dbg(hw, "taking sn:%p ref for rn:%p cnt:%d \n",
				sn, rn, sn->ref_cnt);
//		csio_post_event(&rnt->sm, CSIO_RNTE_INIT);

	} else {
		csio_err(hw, "Duplicate connection request for existing flowid [%d].\n",
				flowid);
		rn = NULL;
		goto out;
	}
	csio_dbg(hw, "%s: rn [%p],rnc [%p], ioid [%u].\n "
			, __FUNCTION__, rn, csio_rnode_to_coiscsi(rn),
			flowid);
out:
	return rnc;
}

void
csio_put_rnc(struct csio_rnode_coiscsi *rnc)
{
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_hw *hw = NULL;

	/* Nothing to free hence return */
	if (!rnc || !rnc->rn)
		return;

	rn = rnc->rn;
	sn = csio_rnode_to_snode(rn);
	hw = sn->hwp;

	//CSIO_DB_ASSERT(!!csio_rnism_in_uninit(rni));

        /* Free rnc */
        if (csio_hw_to_ops(hw)->os_free_coiscsi_rnode) {
                csio_hw_to_ops(hw)->os_free_coiscsi_rnode(rn);
		/* put ref on sn */
		coiscsi_snode_put_ref(sn);
		csio_dbg(hw, "releaesing sn:%p ref for rn:%p cnt:%d\n",
							sn, rn, sn->ref_cnt);
	}

        return;
}

csio_retval_t
csio_coiscsi_rnode_init(struct csio_rnode *rn, struct coiscsi_snode *sn)
{
	int rv = CSIO_SUCCESS;

	csio_rnode_to_lnode(rn) = NULL;
	csio_rnode_to_snode(rn) = sn;

	csio_rnode_to_coiscsi(rn)->rn = rn;
	/* TODO : nothing to init ? */
//	rv = csio_rni_init(csio_rnode_to_iscsi(rn));
	if (rv) {
		rv = CSIO_EINVAL;
		goto err;
	}
	/* Add rnode to list of sn backlog */
	csio_enq_at_tail(&sn->rn_backlog, rn);

	return CSIO_SUCCESS;
err:
	csio_rnode_to_lnode(rn) = NULL;
	csio_rnode_to_snode(rn) = NULL;
	return rv;
}


struct csio_rnode *
csio_coiscsi_alloc_rnode(struct coiscsi_snode *sn)
{
	struct csio_rnode *rn;
	struct csio_os_rnode *osrn =  csio_alloc(csio_md(sn->hwp,
		CSIO_COISCSI_RN_MD), sizeof(struct csio_os_rnode), CSIO_MNOWAIT);

	if (!osrn) {
		csio_dbg(sn->hwp, "%s: ERROR osrn:%p\n", __func__, osrn);
	        goto err;
	}

	memset(osrn, 0, sizeof(struct csio_os_rnode));
	rn = csio_osrn_to_rn(osrn);
	csio_rnode_to_os(rn) = osrn;

	if (csio_coiscsi_rnode_init(rn, sn)) {
		csio_dbg(sn->hwp, "%s: ERROR rnode_init failed:%p\n", __func__, rn);
                goto err_free;
	}
	
	//CSIO_INC_STATS(sn, n_rnode_alloc);
        return rn;

err_free:
        csio_free(csio_md(sn->hwp, CSIO_COISCSI_RN_MD), osrn);
err:
        //CSIO_INC_STATS(ln, n_rnode_nomem);
        return NULL;
}

static void
csio_coiscsi_rnode_exit(struct csio_rnode *rn)
{
	csio_deq_elem(rn);
}

void csio_coiscsi_free_rnode(struct csio_rnode *rn)
{
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);
	struct coiscsi_snode *sn = csio_rnode_to_snode(rn);

        csio_coiscsi_rnode_exit(rn);

	/* TODO : exit ?*/
//	csio_rni_exit(csio_rnode_to_coiscsi(rn));

	csio_rnode_to_os(rn) = NULL;
	csio_rnode_to_snode(rn) = NULL;
	//CSIO_INC_STATS(ln, n_rnode_free);
	csio_free(csio_md(sn->hwp, CSIO_COISCSI_RN_MD), osrn);

        return;
}

int csio_get_rnc_flowid(void *rnc_ptr)
{
	struct csio_rnode_coiscsi *rnc = rnc_ptr;
	if (rnc)
		return rnc->rn->flowid;
	else
		CSIO_ASSERT(0);
}
EXPORT_SYMBOL(csio_get_rnc_flowid);

void csio_tag_rnc_conn(void *rnc_ptr, void *conn_ptr, uint32_t *saddr)
{
	struct csio_rnode_coiscsi *rnc = rnc_ptr;
	if (rnc) {
		rnc->ch_conn = conn_ptr;
		if(saddr)
			memcpy(saddr, rnc->v_num, sizeof(rnc->v_num));
		csio_coiscsi_issue_tgt_conn_wr_reply(rnc->rn->snp->hwp, rnc->rn,
				&rnc->c_wr, FW_FOISCSI_WR_SUBOP_ADD);
	}
}
EXPORT_SYMBOL(csio_tag_rnc_conn);

void coiscsi_reject_conn(void *rnc_ptr)
{
	struct csio_rnode_coiscsi *rnc = rnc_ptr;
	struct csio_rnode *rn = rnc->rn;
	struct coiscsi_snode *sn = rn->snp;
	unsigned long flags;

	CSIO_ASSERT(rnc);
	CSIO_ASSERT(sn);

	csio_coiscsi_issue_tgt_conn_wr_reply(rnc->rn->snp->hwp, rn,
			&rnc->c_wr, FW_FOISCSI_WR_SUBOP_DEL);
	/* release connection */
	csio_write_lock_irqsave(sn->hwp, &sn->sn_rwlock, flags);
	csio_put_rnc(rnc);
	csio_write_unlock_irqrestore(sn->hwp, &sn->sn_rwlock, flags);
}
EXPORT_SYMBOL(coiscsi_reject_conn);

void *coiscsi_socket_accept(void *priv_data)
{
	struct csio_rnode *rn = NULL;
	struct csio_rnode_coiscsi *rnc = NULL;
	struct coiscsi_snode *sn = priv_data;
	unsigned long flags;

	CSIO_ASSERT(sn);

	csio_write_lock_irqsave(sn->hwp, &sn->sn_rwlock, flags);
	if(!csio_list_empty(&sn->rn_backlog)) 
		csio_deq_from_head(&sn->rn_backlog, &rn);

	if (rn)  {
		/* migrate this rn to the rnhead */
		csio_enq_at_tail(&sn->rnhead, rn);
		rnc = csio_rnode_to_coiscsi(rn);
	}
	csio_write_unlock_irqrestore(sn->hwp, &sn->sn_rwlock, flags);

	csio_dbg(sn->hwp, "%s BACKLOG DEQUE rnc:%p rn:%p sn:%p \n",
						__func__, rnc, rn, sn);
	return rnc;
}
EXPORT_SYMBOL(coiscsi_socket_accept);

void coiscsi_socket_close(void *snp)
{
	struct coiscsi_snode *sn = snp;

	/* mark the sn as closing */
	set_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags);
}
EXPORT_SYMBOL(coiscsi_socket_close);


