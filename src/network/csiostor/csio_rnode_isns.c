/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions to handle COiSCSI iSNS functions
 *
 */

#include <csio_os_init.h>
#include <csio_version.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_os_foiscsi.h>
#include <csio_foiscsi_persistent.h>
#include <csio_isns.h>
#include <csio_lnode_foiscsi.h>
#include <csio_lnode.h>
#include <csio_snode.h>

#include <csio_trans_foiscsi.h>

/**
 * csio_isns_rn_lookup - Finds the rnode with the given flowid in the given
 * rn list
 * @rnhd - rnode list
 * @flowid - flowid.
 * 
 * Does the flowid lookup on the given rnode list. If no matching entry
 * found, NULL is returned.
 */
struct csio_rnode *
csio_isns_rn_lookup(struct csio_hw *hw, struct csio_list *rnhd,	uint32_t flowid)
{
	struct csio_rnode *rnhead = (struct csio_rnode *)rnhd;
	struct csio_list *tmp;
	struct csio_rnode *rn;

	if (csio_list_empty(rnhd))
		return NULL;

	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		if (rn->flowid == flowid)
			return rn;
	}

	return NULL;
}

/**
 *  csio_get_rns - Gets a free iSNS rnode with the given flowid
 *  @ln - lnode
 */
struct csio_rnode_isns *
csio_get_rns(struct csio_hw *hw, struct csio_list *rnhead, uint32_t flowid)
{
        struct csio_rnode *rn = NULL ;
        struct csio_rnode_isns *rns = NULL;

        rn = csio_isns_rn_lookup(hw, rnhead, flowid);
	
        if (!rn) {
		if (!csio_hw_to_ops(hw)->os_alloc_isns_rnode)
			goto out;

		rn = csio_hw_to_ops(hw)->os_alloc_isns_rnode(hw, rnhead);
		if (!rn)
			goto out;

		rn->flowid = flowid;
		rns = csio_rnode_to_isns(rn);
		init_completion(&rns->mod_cmplobj.cmpl);
		init_completion(&rns->del_cmplobj.cmpl);
	} else {
		csio_err(hw, "Duplicate connection request for existing flowid [%d].\n",
				flowid);
		rn = NULL;
		goto out;
	}
	
	csio_dbg(hw, "rn [%p],rns [%p], ioid [%u]\n", rn, rns, flowid);
out:
	return rns;
}

/**
 *  csio_put_rns - Places the iSNS rnode to the rnode pool
 *  @rns - rnode
 */
void csio_put_rns(struct csio_rnode_isns *rns)
{
	struct csio_rnode *rn = NULL;
	struct csio_hw *hw = NULL;

	/* Nothing to free hence return */
	if (!rns || !rns->rn) {
		printk("%s: ERROR: rns or rn NULL\n", __func__);
		return;
	}

	rn = rns->rn;
	hw = rns->hwp;

        /* Free rns */
        if (csio_hw_to_ops(hw)->os_free_isns_rnode)
                csio_hw_to_ops(hw)->os_free_isns_rnode(hw, rn);

        return;
}

/**
 *  csio_isns_rnode_init - Init the provided rnode and queue it in rnhead
 *  @rns - rnode
 *  @rnhead - rnode list where the above rnode is queued
 */
csio_retval_t
csio_isns_rnode_init(struct csio_hw *hw, struct csio_rnode *rn, struct csio_list *rnhead)
{
	struct csio_rnode_isns *rns = csio_rnode_to_isns(rn);
	int rv = CSIO_SUCCESS;

	rns->rn = rn;
	rns->hwp = hw;
	csio_enq_at_tail(rnhead, rn);

	return rv;
}


/**
 *  csio_alloc_isns_rnode - Allocate an rnode and queue it to the 
 *  rnhead provided
 *  @hw - hw modules
 *  @rnhead - rnode list where the allocated rnode is queued
 */
struct csio_rnode *
csio_alloc_isns_rnode(struct csio_hw *hw, struct csio_list *rnhead)
{
	struct csio_rnode *rn;
	struct csio_os_rnode *osrn =  csio_alloc(csio_md(hw, 
					CSIO_ISNS_RN_MD),
					sizeof(struct csio_os_rnode),
					CSIO_MNOWAIT);

	if (!osrn) {
		printk("ERROR osrn:%p\n", osrn);
	        goto err;
	}

	memset(osrn, 0, sizeof(struct csio_os_rnode));
	rn = csio_osrn_to_rn(osrn);
	csio_rnode_to_os(rn) = osrn;

	if (csio_isns_rnode_init(hw, rn, rnhead)) {
		printk("ERROR rnode_init failed:%p\n", rn);
                goto err_free;
	}

        //CSIO_INC_STATS(&hw->isnsm, n_rnode_alloc);
        return rn;

err_free:
        csio_free(csio_md(hw, CSIO_ISNS_RN_MD), osrn);

err:
        //CSIO_INC_STATS(&hw->isnsm, n_rnode_nomem);
        return NULL;
}

/**
 *  csio_free_isns_rnode - Dequeue the rnode from the list and deallocate it 
 *  @hw - hw modules
 *  @rn - rnode to be dequeued and freed
 */
void csio_free_isns_rnode(struct csio_hw *hw, struct csio_rnode *rn)
{
	struct csio_os_rnode *osrn = csio_rnode_to_os(rn);

	csio_deq_elem(rn);
	csio_rnode_to_os(rn) = NULL;
	csio_rnode_to_snode(rn) = NULL;
	//CSIO_INC_STATS(&hw->isnsm, n_rnode_free);
	csio_free(csio_md(hw, CSIO_ISNS_RN_MD), osrn);
        return;
}

/**
 *  csio_tag_rns_conn - Tag rns and isns_connection 
 *  @rns_ptr - rns pointer
 *  @conn_ptr - isns_connection pointer
 *  @saddr - If not NULL, connection attributes are copied here
 */
void csio_tag_rns_conn(void *rns_ptr, void *conn_ptr, uint32_t *saddr)
{
	struct csio_rnode_isns *rns = rns_ptr;

	if(rns) {
		rns->ch_conn = conn_ptr;
		if(saddr)
			memcpy(saddr, rns->v_num, sizeof(rns->v_num));
		else
			csio_put_rns(rns);
	}
}
EXPORT_SYMBOL(csio_tag_rns_conn);
