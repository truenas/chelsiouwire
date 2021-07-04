/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions to handle iSNS connections and PDU's
 *
 */
#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_snode.h>
#include <csio_isns.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_isns.h>
#include <csio_foiscsi.h>

#include <csio_os_defs.h>
#include <csio_isns_ioctl.h>
#include <csio_coiscsi_external.h>
#include <csio_ctrl_devs.h>

extern struct uld_tgt_handler *chiscsi_handlers;

int coiscsi_issue_start_server_wr(struct coiscsi_snode *, uint32_t);
int coiscsi_issue_stop_server_wr(struct coiscsi_snode *);
void coiscsi_clean_closeq(struct coiscsi_snode *);
int coiscsi_snode_is_done(struct coiscsi_snode *);
int csio_coiscsi_issue_tgt_program_wr(struct csio_hw *, struct coiscsi_snode *,
     struct csio_rnode *, struct csio_target_props *, uint8_t , void *, uint8_t, uint32_t);

int csio_isns_conn_handle(void *pdu)
{
	isns_data *data = (isns_data *)pdu;
	return csio_coiscsi_issue_isns_wr(data);
}

int csio_isns_pdu_handle(void *pdu)
{
	isns_data *data = (isns_data *)pdu;
	return csio_coiscsi_issue_isns_xmit_wr(data);
}

void isns_connection_close(void *rns_object, uint8_t pclose) {
	struct csio_rnode_isns *rns = (struct csio_rnode_isns *)rns_object;
	struct csio_hw *hw = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	csio_spinlock_t *spinlock = NULL;
	unsigned long flags;

	CSIO_ASSERT(rns);

	hw = rns->hwp;
	rn = rns->rn;
	sn = csio_rnode_to_snode(rn);
	spinlock = (sn? &sn->sn_spinlock : &hw->isnsm.isns_spinlock);

	rn->flags |= CSIO_RNF_CLOSING_CONN;
	if(pclose) {
		coiscsi_issue_del_n_wait_for_mod(rn, rns, 0, &rns->mod_cmplobj.cmpl);
		coiscsi_ack_mod_n_wait_for_del(rn, rns, &rns->del_cmplobj.cmpl);
#ifdef __CSIO_ISNS_CONN_MOD__
	} else {
		isns_ack_mod_n_wait_for_del(rn, rns, &rns->del_cmplobj.cmpl);
#endif
	}
	rns->ch_conn = NULL;

	csio_spin_lock_irqsave(hw, spinlock, flags);
	csio_put_rns(rns);
	csio_spin_unlock_irqrestore(hw, spinlock, flags);

	csio_warn(hw, "CLOSE PUT: sn:%p rn:%p rns:%p flags:0x%x\n",
			sn, rn, rns, rn->flags);
}
EXPORT_SYMBOL(isns_connection_close);

static void isns_snode_tmo_handler(struct csio_oss_timer *t)
{
	struct coiscsi_snode *sn = csio_container_of(t, struct coiscsi_snode,
						     sn_timer);
	complete(&sn->cmplobj.cmpl);
}

struct coiscsi_snode *isns_snode_alloc(struct csio_isnsm *isnsm) 
{

	struct coiscsi_snode *sn = NULL;

	sn = csio_alloc(csio_md(isnsm->hw, CSIO_ISNS_SN_MD),
			sizeof(struct coiscsi_snode),
			CSIO_MNOWAIT);

	if (!sn) {
		csio_err(isnsm->hw, "sn allocation failed\n");
		goto err;
	}

	memset(sn, 0, sizeof(*sn));
	csio_head_init(&sn->rnhead);
	csio_head_init(&sn->rn_backlog);
	csio_mutex_init(&sn->sn_mtx);
	csio_spin_lock_init(&sn->sn_spinlock);
	csio_timer_init(&sn->sn_timer, isns_snode_tmo_handler, 0);
	//csio_work_init(&sn->sn_work, __coiscsi_snode_work,
	//		(void *)sn, (void*)NULL, NULL);
	sn->tgt_id = COISCSI_INVALID_TGT_ID;

err:
	return sn;
}

void isns_snode_free(struct coiscsi_snode *sn)
{
        CSIO_DB_ASSERT(sn);
        csio_timer_stop(&sn->sn_timer);
	//csio_work_cleanup(&sn->sn_work);
	csio_free(csio_md(sn->hwp, CSIO_ISNS_SN_MD), sn);
	return;
}

struct coiscsi_snode *isns_find_snode(struct csio_isnsm *isnsm, isns_info *isns)
{
	uint8_t exists = 0;
	struct csio_list *tmp = NULL;
	struct coiscsi_snode *sn = NULL, *rsn = NULL;
	
	csio_list_for_each(tmp, &isnsm->snhead) {

		sn = (struct coiscsi_snode *)tmp;	

		if(sn->lprt == isns->port) {
			if (isns->type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if(!memcmp(sn->lipv6, isns->addr.ip6, sizeof(sn->lipv6))) {
					exists = 1;
					rsn = sn;
					break;
				}
			} else if (isns->type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
				if (sn->lipv4 == isns->addr.ip4) {
					exists = 1;
					rsn = sn;
					break;
				}
			}
		}
	}

	if(exists)
		csio_dbg(sn->hwp, "sn %p found\n", rsn);

	return rsn;
}

void isns_release_snode(struct csio_isnsm *isnsm, struct coiscsi_snode *sn)
{
	struct csio_list *tmp;
	struct coiscsi_snode *tsn;
	int found = 0, rc = -CSIO_INVAL;

	/* search the snode in the snhead list */
	csio_list_for_each(tmp, &isnsm->snhead) {
		tsn = (struct coiscsi_snode *) tmp;
		if (tsn == sn) {
			set_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags);
			found = 1;
			rc = CSIO_SUCCESS;
			break;
		}
	}

	/* stop the server */
	if (found) {
		rc = coiscsi_issue_stop_server_wr(sn);
		csio_dbg(isnsm->hw, "%s :snode freed sn:%p wr_status:%d \n",
				__func__, sn, sn->wr_status);
		csio_deq_elem(sn);
		isns_snode_free(sn);
	} else {
		csio_dbg(isnsm->hw, "BUG: snode not found in isnsm \n");
		CSIO_ASSERT(0);
	}
}

int csio_coiscsi_issue_isns_wr(isns_data *data)
{	
	int rc = CSIO_SUCCESS;
	int size;
	uint16_t physiqid;
	unsigned long flags;
	isns_info *isns = (isns_info *)&data->isns_info;
	struct csio_hw *hw = (struct csio_hw *)data->pdata1;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct fw_isns_wr isns_wr;
	struct csio_wr_pair wrp;
	struct csio_ctrl_chnet *chnet_cdev = NULL;
	struct csio_chnet_iface *iface = NULL;
#ifdef __CSIO_ISNS_CONN_MOD__
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct csio_rnode_isns *rns = NULL;
	struct csio_rnode *rn = NULL;
#endif

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		return CSIO_EINVAL;
	}
	iface = &chnet_cdev->ifaces[hw->t4port[isns->ifid].portid];

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_isns_wr), 16);
	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&isns_wr, 0, sizeof(struct fw_isns_wr));

	/* Init FW_ISNS_WR */
	isns_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_ISNS_WR));
#ifdef __CSIO_PORT_EVTQ__
	isns_wr.op_compl |= csio_cpu_to_be32(V_FW_ISNS_WR_PORTID(
			    iface->tport->portid));
#endif
	if(data->op == FW_FOISCSI_WR_SUBOP_ADD) {
		isns_wr.flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(iface->if_id) |
				V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		isns_wr.vlanid = csio_cpu_to_be16(isns->vlanid);
		isns_wr.cookie = (u64)(uintptr_t)data;
	} else if(data->op == FW_FOISCSI_WR_SUBOP_DEL) {
		isns_wr.flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(isns->ofid) |
				V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		isns_wr.conn_attr.in_tid  = csio_cpu_to_be32(isns->ofid);
#ifdef __CSIO_ISNS_CONN_MOD__
		rn = csio_isns_rn_lookup(hw, &isnsm->rnhead, isns->ofid);
		if(!rn) {
			csio_err(hw, "rn with flowid 0x%x not found\n", isns->ofid);
			rc = CSIO_EINVAL;
			goto out;
		}
		rns = csio_rnode_to_isns(rn);
		isns_wr.cookie = (u64)(uintptr_t)rns;
#else
		isns_wr.cookie = (u64)(uintptr_t)data;
#endif
	}

	data->iq_idx = oshw->sqset[CSIO_SQS_CLNT_TRGT][CSIO_ISNS_IQ_IDX_CPU].iq_idx;
	physiqid = csio_q_physiqid(hw, data->iq_idx);
	isns_wr.iq_id = csio_cpu_to_be16(physiqid);

	isns_wr.subop = data->op;
	isns_wr.conn_attr.in_port = csio_cpu_to_be16(isns->port);
	if(isns->type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
		isns_wr.conn_attr.in_type = FW_CHNET_ADDR_TYPE_IPV4;
		memcpy((uint8_t *)&isns_wr.conn_attr.u.in_addr.addr, (uint8_t *)isns->addr.ip6 + 12, 4);
	} else if(isns->type == CSIO_ISNS_L3CFG_TYPE_IPV6) {
		isns_wr.conn_attr.in_type = FW_CHNET_ADDR_TYPE_IPV6;
		memcpy((uint8_t *)isns_wr.conn_attr.u.in_addr6.addr,
			(uint8_t *)isns->addr.ip6, 16);
	}

	csio_wr_copy_to_wrp(&isns_wr, &wrp, 0, sizeof(struct fw_isns_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "Out of credits, cannot allocate wr\n");
	else
		csio_dump_wr_buffer((uint8_t *)&isns_wr, sizeof(struct fw_isns_wr));
#endif
#ifdef __CSIO_ISNS_CONN_MOD__
	if(!rc && isns_wr.subop == FW_FOISCSI_WR_SUBOP_DEL) {
		wait_for_completion(&rns->mod_cmplobj.cmpl);
	}
#endif

	return rc;
}

static inline uint32_t
coiscsi_isns_xmit_init_ultptx_dsgl(struct csio_hw *hw, isns_data *data, 
		struct ulptx_sgl *sgl, uint32_t nsge)
{
	struct ulptx_sge_pair *sge_pair = NULL;
	struct data_sgl *sgel = &data->sgl[0];
	uint32_t i = 0;
	uint32_t totlen = 0;

	sgl->cmd_nsge = csio_htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			F_ULP_TX_SC_MORE | V_ULPTX_NSGE(nsge));

	for (i = 0; i < nsge; i++, sgel++) {

		if (i == 0) {
			sgl->addr0 = csio_cpu_to_be64((uint64_t)csio_phys_addr(sgel->addr));
			sgl->len0 = csio_cpu_to_be32(sgel->len);
			totlen += sgel->len;

			sge_pair = (struct ulptx_sge_pair *)(sgl + 1);
			continue;
		}

		//ISNS TODO - check whether sge_pair needed for iSNS and fill it
	}

	return totlen;
}

static inline int
coiscsi_init_isns_xmit_wr(struct csio_hw *hw, struct csio_rnode *rn,
		isns_data *data, struct fw_isns_xmit_wr *wr, uint32_t size, uint32_t nsge)
{       
	int rc = 0;
	uint16_t physiqid;
	uint32_t xfer_cnt, op_to_immdlen;
	isns_info *isns = (isns_info *)&data->isns_info;
	struct ulptx_sgl *sgl;

	csio_memset(wr, 0, sizeof(*wr));

	op_to_immdlen = (V_FW_WR_OP(FW_ISNS_XMIT_WR) | F_FW_WR_COMPL);	
	wr->op_to_immdlen = csio_cpu_to_be32(op_to_immdlen);
	wr->flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(isns->ofid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));

	physiqid = csio_q_physiqid(hw, rn->iq_idx);
	wr->iq_id = csio_cpu_to_be16(physiqid);
	wr->xfer_len = csio_cpu_to_be32(data->totallen);
	wr->cookie = (u64)(uintptr_t)data;
	

	/*  Move WR pointer past WR command */
	sgl = (struct ulptx_sgl *)((uint8_t *)wr + sizeof(struct fw_isns_xmit_wr));

	/*  Fill in the DSGL */
	xfer_cnt = coiscsi_isns_xmit_init_ultptx_dsgl(hw, data, sgl, nsge);
	if (xfer_cnt < 0)
		return xfer_cnt;

	wr->xfer_len = csio_cpu_to_be32(xfer_cnt);
#ifdef __CSIO_DEBUG__
	csio_dump_wr_buffer((uint8_t *)wr, size);
#endif
	return rc;
}

int32_t 
coiscsi_isns_nsge_size(struct csio_hw *hw, isns_data *data, uint32_t wrsz, uint32_t *nsge)
{
	int32_t size;

	*nsge = data->sg_cnt;
	size = wrsz + sizeof(struct ulptx_sgl);

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

	csio_dbg(hw, "size %d nsge %d\n", size, *nsge);
	return size;
}

int csio_coiscsi_issue_isns_xmit_wr(isns_data *data)
{	
	int rc = CSIO_SUCCESS;
	int size;
	unsigned long flags;
	uint32_t nsge;
	isns_info *isns = (isns_info *)&data->isns_info;
	struct csio_hw *hw = (struct csio_hw *)data->pdata1;
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct csio_wr_pair wrp;
	struct coiscsi_snode *sn = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_isns *rns = NULL;
	struct csio_list *tmp = NULL;
	uint32_t flow_id = isns->ofid;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	/*    Search rn head in isnsm first */
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
		csio_err(hw, "No rnode found for conn id [%u], bailing out.\n", flow_id);
		rc = -CSIO_EINVAL;
		goto out;
	}

	if (rn->flags & CSIO_RNF_CLOSING_CONN) {
		csio_err(hw, "xmit on closed/closing conn rn:%p \n", rn);
		rc = -CSIO_EIO;
		goto out;
	}

	rns = csio_rnode_to_isns(rn);
	if(!rns->ch_conn) {
		csio_err(hw, "Connection to rnode %p closed\n", rn);
		rc = -CSIO_EINVAL;
		goto out;
	}

	size = coiscsi_isns_nsge_size(hw, data, sizeof(struct fw_isns_xmit_wr), &nsge);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS)) {
		csio_err(hw, "Out of credits, cannot allocate wr\n");
		rc = -CSIO_EINVAL;
		goto out;
	}

	if (wrp.size1 >= size) {
		rc = coiscsi_init_isns_xmit_wr(hw, rn, data,
				(struct fw_isns_xmit_wr*)wrp.addr1,
				size, nsge);

		if (rc < 0) {
			//ISNS TODO - what to do obtained credits
			csio_err(hw, "isns_xmit_wr addr1 failed, rc %d\n", rc);
			goto out;
		}
	} else {
		uint8_t tmpwr[512];
		rc = coiscsi_init_isns_xmit_wr(hw, rn, data,
				(struct fw_isns_xmit_wr*)tmpwr,
				size, nsge);

		if (rc < 0) {
			//ISNS TODO - what to do obtained credits
			csio_err(hw, "isns_xmit_wr tmpwr failed, rc %d\n", rc);
			goto out;
		}

		csio_memcpy(wrp.addr1, tmpwr, wrp.size1);
		csio_memcpy(wrp.addr2, tmpwr + wrp.size1, size - wrp.size1);
	}

	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
	return rc;
}

int validate_iface_state(struct csio_hw *hw, struct csio_chnet_iface *iface, isns_info *isns)
{
	int rc = 0;
	uint32_t ipv6_addr[4];

	memset(ipv6_addr, 0, 16);
	if(!iface) {
		csio_err(hw, "Iface not provisioned\n");
		return CSIO_EIFACE_NOT_PROVISIONED;
	}

	csio_mutex_lock(&iface->mlock);

	if(iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_err(hw, "Iface not UP\n");
		rc = CSIO_EIFACE_NOT_PROVISIONED;
		goto out;
	}

	if(isns->vlanid && iface->vlan_info.vlan_id != isns->vlanid) {
		csio_err(hw, "Invalid vlan(%d) specified, configured vlan(%d)\n",
				isns->vlanid, iface->vlan_info.vlan_id);
		rc = CSIO_INVAL;
		goto out;
	}

	if(isns->type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
		if(isns->vlanid) {
			if(!iface->vlan_info.ipv4.addr) 
				rc = CSIO_EIFACE_NOT_PROVISIONED;
		} else {
			if(!iface->ipv4.addr) 
				rc = CSIO_EIFACE_NOT_PROVISIONED;
		}
	} else {
		if(isns->vlanid) {
			if(!csio_memcmp((void*)iface->vlan_info.ipv6.addr, (void *)ipv6_addr, 16))
				rc = CSIO_EIFACE_NOT_PROVISIONED;
		} else {
			if(!csio_memcmp((void*)iface->ipv6.addr, (void *)ipv6_addr, 16))
				rc = CSIO_EIFACE_NOT_PROVISIONED;
		}
	}

	if(rc)
		csio_err(hw, "Iface IP not configured\n");

out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

int csio_start_isns(struct csio_hw *hw, isns_info *isns)
{
	int rc = 0;
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct coiscsi_snode *sn = NULL;
	struct csio_ctrl_chnet *chnet_cdev = NULL;
	struct csio_chnet_iface *iface = NULL;

	if(isns->mode == CSIO_APP_MOD_ISNS_SERVER) {

		/* Get interface */
		iface = csio_chnet_iface_addr_get(hw, isns->type, &isns->addr);
		if(!iface) {
			csio_err(hw, "Iface not found\n");
			return CSIO_EIFACE_NOT_PROVISIONED;
		}

		/*  Check whether port id matches */
		if(iface->tport->portid != isns->ifid){
			csio_err(hw, "Iface portid(%d) mismatches given portid(%d)\n",
					iface->tport->portid, isns->ifid);
			rc = CSIO_EIFACE_INVALID_PORT;
			goto put_iface;
		}

		/* Search for snode existence */
		sn = isns_find_snode(isnsm, isns);
		if(sn) {
			csio_err(hw, "snode %p already exist\n", sn); 
			rc = CSIO_EINST_EXISTS;
			goto put_iface;
		}

		/* Allocate snode */
		sn = isns_snode_alloc(isnsm);
		if(!sn) {
			csio_err(hw, "snode allocation failed\n"); 
			rc = CSIO_ENOMEM;
			goto put_iface;
		}

		sn->lprt = isns->port;
		sn->ip_type = isns->type;
		sn->iface = iface;
		if(sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
			csio_dbg(hw, "IPV6 address\n");
			memcpy(sn->lipv6, isns->addr.ip6, sizeof(sn->lipv6));
		} else if(sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4){
			csio_dbg(hw, "IPV4 address\n");
			sn->lipv4 = isns->addr.ip4;
		}
		sn->hwp = hw;
		sn->op_flag |= COISCSI_SNODE_OPF_ASSIGN;

		csio_dbg(hw, "sn:0x%p type:%d lipv4:0x%x, lprt:0x%x\n",	
				sn, sn->ip_type, sn->lipv4, sn->lprt);
	
	} else if(isns->mode == CSIO_APP_MOD_ISNS_CLIENT) {

		chnet_cdev = csio_hw_to_chnet_cdev(hw);
		if (!chnet_cdev) {
			csio_err(hw, "chnet_cdev inst not found\n");
			return CSIO_INVAL;
		}

		iface = &chnet_cdev->ifaces[isns->ifid];
		rc = validate_iface_state(hw, iface, isns);
		if(rc) {
			csio_err(hw, "Iface validation failed\n");
			return rc;
		}
	}


	if (chiscsi_handlers && chiscsi_handlers->start_isns) {
		rc = chiscsi_handlers->start_isns(hw, hw->os_dev, isns);
		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "start_isns failed, rc %d\n", rc);
			rc = CSIO_EISNS_OP_FAIL;
			goto free_snode;
		}
	} else {
		csio_err(hw, "start_isns function not implemented\n");
		rc = CSIO_ENOSYS;
		goto free_snode;
	}

	if(isns->mode == CSIO_APP_MOD_ISNS_SERVER) {

		/* send FW_COISCSI_TGT_WR now */
		rc = coiscsi_issue_start_server_wr(sn, iface->if_id);
		if ((rc != CSIO_SUCCESS) || (sn->wr_status != 0)) {
			csio_err(hw, "START SERVER FAILED "
				"hw:%p sn:%p ifid:%d rc %d status:%d\n",
				hw, sn, iface->if_id, rc, sn->wr_status);

			chiscsi_handlers->stop_isns(hw, hw->os_dev, isns);
			rc = CSIO_ELISTEN_FAIL;
			goto free_snode;
		}

		csio_enq_at_tail(&isnsm->snhead, sn);

		isnsm->list_server_cnt++;
		csio_dbg(hw, "isnsm listening serv count %d\n", isnsm->list_server_cnt);

	} else if(isns->mode == CSIO_APP_MOD_ISNS_CLIENT) {
		
		isnsm->client_cnt++;
		csio_dbg(hw, "isnsm client count %d\n", isnsm->client_cnt);
	}

	return 0;

free_snode:

	if((isns->mode == CSIO_APP_MOD_ISNS_SERVER) && sn)
		isns_snode_free(sn);

put_iface:

	if(isns->mode == CSIO_APP_MOD_ISNS_SERVER)
		csio_chnet_iface_addr_put(hw, iface, isns->type, &isns->addr);

	return rc;
}

int csio_stop_isns(struct csio_hw *hw, isns_info *isns)
{
	int rc = 0;
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct coiscsi_snode *sn = NULL;
	struct csio_ctrl_chnet *chnet_cdev = NULL;
	struct csio_chnet_iface *iface = NULL;

	if(isns->mode == CSIO_APP_MOD_ISNS_SERVER) {
		/* Find snode */
		sn = isns_find_snode(isnsm, isns);
		if(!sn) {
			csio_err(hw, "sn %d:%d not found\n",
					isns->ifid, isns->port);
			return CSIO_EINST_NOT_FOUND;
		}

		iface = (struct csio_chnet_iface *)sn->iface;
		if(iface->tport->portid != isns->ifid){
			csio_err(hw, "Iface portid(%d) mismatches given portid(%d)\n",
					iface->tport->portid, isns->ifid);
			return CSIO_EIFACE_INVALID_PORT;
		}

		set_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags);

	} else {

		chnet_cdev = csio_hw_to_chnet_cdev(hw);
		if (!chnet_cdev) {
			csio_err(hw, "chnet_cdev inst not found\n");
			return CSIO_INVAL;
		}

		iface = &chnet_cdev->ifaces[isns->ifid];
		rc = validate_iface_state(hw, iface, isns);
		if(rc) {
			csio_err(hw, "Iface validation failed\n");
			return rc;
		}
	}

	/* Stop associated things in chiscsi */
	if (chiscsi_handlers && chiscsi_handlers->stop_isns) {
		rc = chiscsi_handlers->stop_isns(hw, hw->os_dev, isns);
		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "stop_isns failed, rc %d\n", rc);
			return CSIO_EISNS_OP_FAIL;
		}
	} else {
		csio_err(hw, "stop_isns function not implemented\n");
		return CSIO_ENOSYS;
	}
	
	if(isns->mode == CSIO_APP_MOD_ISNS_SERVER) {

		/* Sleep for 5 seconds for all connections to close */
		csio_info(hw, "Waiting 5 seconds for everything to finish,sn %p\n", sn);
		csio_msleep(5000);

		if (coiscsi_snode_is_done(sn))
			isns_release_snode(isnsm, sn);

		csio_chnet_iface_addr_put(hw, iface, isns->type, &isns->addr);
		isnsm->list_server_cnt--;
		csio_dbg(hw, "isnsm listening server count %d\n", isnsm->list_server_cnt);

	} else if(isns->mode == CSIO_APP_MOD_ISNS_CLIENT) {

		isnsm->client_cnt--;
		csio_dbg(hw, "isnsm client count %d\n", isnsm->client_cnt);

	}
	
	return rc;
}


int csio_show_isns(struct csio_hw *hw, isns_info *isns)
{
	int rc = 0;

	if (chiscsi_handlers && chiscsi_handlers->show_isns) {
		rc = chiscsi_handlers->show_isns(hw, hw->os_dev, isns);
		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "show_isns failed, rc %d\n", rc);
			rc = CSIO_EISNS_OP_FAIL;
		}
	} else {
		csio_err(hw, "show_isns function not implemented\n");
		rc = CSIO_ENOSYS;
	}

	return rc;
}

