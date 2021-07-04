/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions to handle COiSCSI lnodes
 *
 */
#include <csio_defs.h>
#include <csio_snode.h>
#include <csio_lnode_coiscsi.h>
#include <csio_lnode.h>

#include <csio_os_defs.h>
#include <csio_coiscsi_ioctl.h>
#include <csio_coiscsi_external.h>
#include <csio_ctrl_devs.h>
#include <csio_ctrl_coiscsi.h>

struct uld_tgt_handler *chiscsi_handlers = NULL;
void coiscsi_snode_dec_stats(struct csio_coiscsi_tgtm *, struct coiscsi_snode *);

struct coiscsi_portal *coiscsi_portal_alloc(struct csio_lnode_coiscsi *lncoi)
{
	struct csio_lnode *ln = lncoi->ln;
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct coiscsi_portal *cprtl = NULL;

	cprtl = csio_alloc(csio_md(hw, CSIO_COISCSI_TGT_PORTAL_MD),
			sizeof(*cprtl), CSIO_MNOWAIT);

	if (!cprtl) {
		csio_err(hw,
			"lncoi:%p coiscsi portal allocatin failed\n",
			lncoi);
		return NULL;
	}

	memset(cprtl, 0, sizeof(*cprtl));
	csio_elem_init(cprtl);

	return cprtl;
}

void coiscsi_portal_free(struct csio_lnode_coiscsi *lncoi,
		struct coiscsi_portal *cprtl)
{
	struct csio_lnode *ln = lncoi->ln;
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	
	cprtl->snode = NULL;
	csio_free(csio_md(hw, CSIO_COISCSI_TGT_PORTAL_MD), cprtl);
}

struct csio_os_lnode *
csio_coiscsi_alloc_lnode(struct csio_coiscsi_tgtm *tgtm)
{
	struct csio_os_lnode *osln = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct csio_hw *hw = tgtm->hw;
	
	osln = csio_alloc(csio_md(hw, CSIO_COISCSI_LN_MD),
			sizeof(struct csio_os_lnode), CSIO_MNOWAIT);
	if (!osln) {
		csio_err(hw, "lnode alloc failed for COiSCSI TGT module.\n");
		goto out;
	}

	memset(osln, 0, sizeof(*osln));

	csio_lnode_to_os(csio_osln_to_ln(osln)) = osln;
	ln = csio_osln_to_ln(osln);

	if (!tgtm->rln)
		hw->rln = csio_osln_to_ln(osln);

	csio_lnode_to_hw(ln) = hw;
	ln->modl = tgtm;

	csio_head_init(&ln->rnhead);
	csio_head_init(&ln->cln_head);
	
	ln->params.log_level = hw->params.log_level;

	lncoi = csio_lnode_to_coiscsi(ln);
	csio_lnode_to_coiscsi(ln)->ln = ln;
	
	csio_mutex_init(&lncoi->lnc_mtx);
	csio_head_init(&lncoi->portal_head);

	lncoi->portal_cnt      = 0;
	lncoi->node_init_done  = 0;
		

	csio_spin_lock_irq(hw, &hw->lock);
	csio_enq_at_tail(&tgtm->sln_head, ln);
	csio_spin_unlock_irq(hw, &hw->lock);

	CSIO_INC_STATS(tgtm, n_lns);

	return osln;

out:
	if (osln) {
		csio_free(csio_md(hw, CSIO_COISCSI_LN_MD), osln);
		CSIO_DEC_STATS(tgtm, n_lns);
		osln = NULL;
	}

	return osln;
}

void csio_coiscsi_free_lnode(struct csio_os_lnode *osln)
{
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);

	csio_spin_lock_irq(hw, &hw->lock);
	csio_deq_elem(ln);

	/* clean up things if there any before freeing up */
	csio_free(csio_md(tgtm->hw, CSIO_COISCSI_LN_MD), osln);
	CSIO_DEC_STATS(tgtm, n_lns);

	if (csio_list_empty(&tgtm->sln_head))
		tgtm->rln = NULL;
	else
		tgtm->rln = (struct csio_lnode*)csio_list_next(&tgtm->sln_head);
	csio_spin_unlock_irq(hw, &hw->lock);

	csio_lnode_to_hw(ln) = NULL;
	ln->modl = NULL;
}

void csio_coiscsi_free_lnode_coiscsi(struct csio_lnode_coiscsi *lncoi)
{
	CSIO_ASSERT(lncoi);
	/* free lun list */
	if(lncoi->lun_list)
		kfree(lncoi->lun_list);
	/* free the lnode */
	csio_coiscsi_free_lnode(csio_lnode_to_os(lncoi->ln));
}

#ifdef __CSIO_PORT_EVTQ__
int csio_get_port_from_sn(struct coiscsi_snode *sn, uint8_t *port)
{
	struct coiscsi_portal *portal = (struct coiscsi_portal*)(sn->tportal);
	*port = M_FW_COISCSI_TGT_WR_PORTID;

	if (portal && portal->iface && portal->iface->tport) {
		*port = portal->iface->tport->portid;
	} else if (sn->iface) {
		struct csio_chnet_iface *iface = (struct csio_chnet_iface *)
						 sn->iface;
		*port = iface->tport->portid;
	}

	if (*port == M_FW_COISCSI_TGT_WR_PORTID) {
		csio_err(sn->hwp, "port NOT FOUND for sn %p\n", sn);
		return CSIO_INVAL;
	}
	return CSIO_SUCCESS;
}
#endif

static int csio_issue_coiscsi_tgt_wr(struct csio_hw *hw,
		struct coiscsi_snode *sn, uint32_t iface_id,
		uint8_t subop)
{
#ifdef __CSIO_PORT_EVTQ__
	uint8_t port = M_FW_COISCSI_TGT_WR_PORTID;
#endif
	struct fw_coiscsi_tgt_wr tgt_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	unsigned long flags;

	csio_dbg(hw, "Sizeof fw_coiscsi_tgt_wr [%lu] bytes\n",
			sizeof(struct fw_coiscsi_tgt_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_coiscsi_tgt_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&tgt_wr, 0, sizeof(struct fw_coiscsi_tgt_wr));

	tgt_wr.subop = subop;
	tgt_wr.op_compl = csio_cpu_to_be32 (
			V_FW_WR_OP(FW_COISCSI_TGT_WR));
#ifdef __CSIO_PORT_EVTQ__
	if (csio_unlikely((rc = csio_get_port_from_sn(sn, &port)) !=
			  CSIO_SUCCESS))
		goto out;

	tgt_wr.op_compl |= csio_cpu_to_be32(V_FW_COISCSI_TGT_WR_PORTID(port));
#endif

	if (tgt_wr.subop == FW_FOISCSI_WR_SUBOP_ADD) {
		tgt_wr.flowid_len16 = csio_cpu_to_be32 (
			V_FW_WR_FLOWID(iface_id) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	} else {
		CSIO_DB_ASSERT(sn->tgt_id != COISCSI_INVALID_TGT_ID);
		tgt_wr.flowid_len16 = csio_cpu_to_be32 (
			V_FW_WR_FLOWID(sn->tgt_id) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	}
		
	tgt_wr.cookie = (u64)(uintptr_t)sn;

	if (sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6)
		tgt_wr.conn_attr.in_type = FW_CHNET_ADDR_TYPE_IPV6;
	else 
		tgt_wr.conn_attr.in_type = FW_CHNET_ADDR_TYPE_IPV4;

	tgt_wr.conn_attr.in_port = csio_cpu_to_be16(sn->lprt);

	if (sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
		tgt_wr.conn_attr.u.in_addr6.addr[0] = *(__be64 *)(sn->lipv6);
		tgt_wr.conn_attr.u.in_addr6.addr[1] = *(__be64 *)(sn->lipv6 + 8);
	} else {
		tgt_wr.conn_attr.u.in_addr.addr = csio_cpu_to_be32(sn->lipv4);
	}

	csio_wr_copy_to_wrp(&tgt_wr, &wrp, 0, sizeof(struct fw_coiscsi_tgt_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "Out of credits, cannot allocate wr\n");
	else
		csio_dump_wr_buffer((uint8_t *)&tgt_wr, sizeof(struct fw_coiscsi_tgt_wr));
#endif
	return rc;
}

static int csio_issue_coiscsi_stats_wr(struct csio_hw *hw, 
			struct coiscsi_target_stats_ioctl *stats, uint8_t subop)
{
	struct fw_coiscsi_stats_wr stats_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	unsigned long flags;

	csio_dbg(hw, "Sizeof fw_coiscsi_stats_wr [%lu] bytes\n",
			sizeof(struct fw_coiscsi_stats_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_coiscsi_stats_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&stats_wr, 0, sizeof(struct fw_coiscsi_stats_wr));

	stats_wr.subop = subop;
	stats_wr.op_compl = csio_cpu_to_be32 (
			V_FW_WR_OP(FW_COISCSI_STATS_WR));
#ifdef __CSIO_PORT_EVTQ__
	stats_wr.op_compl |= csio_cpu_to_be32(
			     V_FW_COISCSI_STATS_WR_PORTID(0));
#endif

	stats_wr.flowid_len16 = csio_cpu_to_be32 (
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));

	stats_wr.cookie = (u64)(uintptr_t)stats;

	csio_wr_copy_to_wrp(&stats_wr, &wrp, 0, sizeof(struct fw_coiscsi_stats_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_err(hw, "Out of credits, cannot allocate wr, rc %d\n", rc);
	else
		csio_dump_wr_buffer((uint8_t *)&stats_wr, sizeof(struct fw_coiscsi_stats_wr));
#endif
	return rc;
}

int csio_coiscsi_issue_tgt_program_wr(struct csio_hw *hw, struct coiscsi_snode *sn,
		struct csio_rnode *rn, struct csio_target_props *tprops, uint8_t sub_op,
		void *cookie, u8 status, uint32_t close_flags)
{
#ifdef __CSIO_PORT_EVTQ__
	uint8_t port = M_FW_COISCSI_TGT_WR_PORTID;
#endif
	struct fw_coiscsi_tgt_conn_wr tgt_program_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	uint16_t physiqid;
	unsigned long flags;
	unsigned int settings = 0;

	csio_dbg(hw, "Sizeof fw_coiscsi_tgt_conn_wr [%lu] bytes\n",
			sizeof(struct fw_coiscsi_tgt_conn_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_coiscsi_tgt_conn_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&tgt_program_wr, 0, sizeof(struct fw_coiscsi_tgt_conn_wr));

	tgt_program_wr.op_compl = csio_cpu_to_be32 (
			V_FW_WR_OP(FW_COISCSI_TGT_CONN_WR));
#ifdef __CSIO_PORT_EVTQ__
	if (csio_unlikely((rc = csio_get_port_from_sn(sn, &port)) !=
			  CSIO_SUCCESS))
		goto out;

	tgt_program_wr.op_compl |= csio_cpu_to_be32(
				   V_FW_COISCSI_TGT_CONN_WR_PORTID(port));
#endif

	tgt_program_wr.subop = sub_op;
	tgt_program_wr.flowid_len16 = csio_cpu_to_be32(
			V_FW_WR_FLOWID(rn->flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	tgt_program_wr.conn_iscsi.tgt_id = csio_cpu_to_be32(sn->tgt_id);
	tgt_program_wr.status = status;

	if (close_flags)
		tgt_program_wr.flags_fin = csio_cpu_to_be32(close_flags);

	physiqid = csio_q_physiqid(hw, rn->iq_idx);
	tgt_program_wr.iq_id = csio_cpu_to_be16(physiqid);

	if(tprops) {
		if (tprops->hdigest)
			settings |=
			V_FW_FOISCSI_CTRL_WR_HDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32);

		if (tprops->ddigest)
			settings |=
			V_FW_FOISCSI_CTRL_WR_DDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32);

		tgt_program_wr.conn_iscsi.max_r2t = csio_cpu_to_be16(tprops->max_r2t);
		tgt_program_wr.conn_iscsi.max_rdsl = csio_cpu_to_be32(tprops->max_rdsl);
		tgt_program_wr.conn_iscsi.max_tdsl = csio_cpu_to_be32(tprops->max_tdsl);
		tgt_program_wr.conn_iscsi.max_burst = csio_cpu_to_be32(tprops->max_burst);
		tgt_program_wr.conn_iscsi.cur_sn = csio_cpu_to_be32(tprops->cur_statsn);
	}

	tgt_program_wr.conn_iscsi.hdigest_to_ddp_pgsz = csio_cpu_to_be32(settings);

	tgt_program_wr.cookie = (u64)(uintptr_t)cookie;
	/* Fill other fields */

	csio_wr_copy_to_wrp(&tgt_program_wr, &wrp, 0, sizeof(struct fw_coiscsi_tgt_conn_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "Out of credits, cannot allocate wr\n");
	else
		csio_dump_wr_buffer((uint8_t *)&tgt_program_wr, sizeof(struct fw_coiscsi_tgt_conn_wr));
#endif
	return rc;

}

int csio_issue_adjust_conn_wr(void *rnc_object, void *adjust_props)
{
	struct csio_rnode_coiscsi *rnc = (struct csio_rnode_coiscsi *)rnc_object;
	struct csio_target_props *negotiated_props = (struct csio_target_props *)adjust_props;
	struct csio_rnode *rn = rnc->rn;
	struct coiscsi_snode *sn = rn->snp;
	struct csio_hw *hw = sn->hwp;
	int rc = CSIO_SUCCESS;

	csio_tcp_dbg(hw, "sn %p rnc %p rn %p\n", sn, rnc, rn);
	if (sn) {
		csio_mutex_lock(&sn->sn_mtx);
		if (sn->op_pending) {
			csio_tcp_dbg(hw, "DEBUG OP PENDING: SN LOCK held sn:%p \n",sn);
                        rc = EBUSY;
                        goto ulock_out;
		}
	}

	init_completion(&sn->cmplobj.cmpl);

	sn->op_pending = 1;

	csio_tcp_dbg(hw, "%s: issue FW_FOISCSI_WR_SUBOP_MOD..\n",
			__FUNCTION__);

	rc = csio_coiscsi_issue_tgt_program_wr(hw, sn, rn, negotiated_props, 
					FW_FOISCSI_WR_SUBOP_MOD, rnc, FW_SUCCESS, 0);

	if (rc != CSIO_SUCCESS) {
		sn->op_pending = 0;
		goto ulock_out;
	}

	rn->flags |= CSIO_RNF_ADJ_PARAM;
	/* Save the value of the driver's current statsn which is 
	 * 1 less than what is sent to FW */
	rnc->statsn = negotiated_props->cur_statsn - 1;

	csio_tcp_dbg(hw, "%s: waiting for adjust wr completion..rn %p, io_id %x~~~>\n",
			__FUNCTION__, rn, rn->flowid);

	wait_for_completion(&sn->cmplobj.cmpl);
	csio_tcp_dbg(hw, "%s: waiting for adjust wr completion..done rn %p, io_id %x<~~~\n",
			__FUNCTION__, rn, rn->flowid);
	sn->op_pending = 0;

ulock_out:
	csio_mutex_unlock(&sn->sn_mtx);
	return rc;
}

int csio_coiscsi_issue_tgt_conn_wr_reply(struct csio_hw *hw,
		struct csio_rnode *rn, struct fw_coiscsi_tgt_conn_wr *recv_wr,
		enum fw_foiscsi_wr_subop subop)
{
#ifdef __CSIO_PORT_EVTQ__
	uint8_t port = M_FW_COISCSI_TGT_WR_PORTID;
#endif
	struct fw_coiscsi_tgt_conn_wr tgt_conn_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	uint32_t ifid;
	unsigned long flags;
	uint16_t physiqid;

	csio_vdbg(hw, "Sizeof fw_coiscsi_tgt_conn_wr [%lu] bytes\n",
			sizeof(struct fw_coiscsi_tgt_conn_wr));

	ifid = G_FW_WR_FLOWID(csio_be32_to_cpu(recv_wr->flowid_len16));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_coiscsi_tgt_conn_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&tgt_conn_wr, 0, sizeof(struct fw_coiscsi_tgt_conn_wr));
	memcpy(&tgt_conn_wr, recv_wr, sizeof(struct fw_coiscsi_tgt_conn_wr));

#ifdef __CSIO_PORT_EVTQ__
	if (csio_unlikely((rc = csio_get_port_from_sn(rn->snp, &port)) !=
			  CSIO_SUCCESS))
		goto out;
	tgt_conn_wr.op_compl |= csio_cpu_to_be32(
				   V_FW_COISCSI_TGT_CONN_WR_PORTID(port));
#endif

	if (!(rn->snp->tcp_wsen)) {
		rn->snp->tcp_wsen = 1;
		rn->snp->tcp_wscale = ISCSI_DEFAULT_WSF;
	}

	if (G_FW_COISCSI_TGT_CONN_WR_WSEN(tgt_conn_wr.u.conn_tcp.wscale_wsen))
		tgt_conn_wr.u.conn_tcp.wscale_wsen =
					V_FW_COISCSI_TGT_CONN_WR_WSCALE(
					rn->snp->tcp_wscale) |
					V_FW_COISCSI_TGT_CONN_WR_WSEN(
					rn->snp->tcp_wsen);
	else
		tgt_conn_wr.u.conn_tcp.wscale_wsen =
					V_FW_COISCSI_TGT_CONN_WR_WSCALE(0) |
					V_FW_COISCSI_TGT_CONN_WR_WSEN(0);

	physiqid = csio_q_physiqid(hw, rn->iq_idx);

	tgt_conn_wr.iq_id = csio_cpu_to_be16(physiqid);

	csio_tcp_dbg(hw, "ifid:0x%x, physiqid:0x%x, iq_id:0x%x, iq_idx:0x%x, "
			 "subop:0x%x\n", ifid, physiqid, tgt_conn_wr.iq_id,
			 rn->iq_idx, subop);

	tgt_conn_wr.subop = subop;

	csio_wr_copy_to_wrp(&tgt_conn_wr, &wrp, 0, sizeof(struct fw_coiscsi_tgt_conn_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	if (rc)
		csio_warn(hw, ":%s Out of WR credits \n", __func__);
#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	else
		csio_dump_wr_buffer((uint8_t *)&tgt_conn_wr, sizeof(struct fw_coiscsi_tgt_conn_wr));
#endif
	return rc;
}

int coiscsi_issue_del_n_wait_for_mod(struct csio_rnode *rn, void *cookie, 
		uint32_t close_flags, struct completion *mod_cmpl)
{
	struct coiscsi_snode *sn = rn->snp;
	struct csio_hw *hw = sn->hwp;
	int rc = CSIO_SUCCESS;

	rc = csio_coiscsi_issue_tgt_program_wr(hw, sn, rn, NULL, 
					FW_FOISCSI_WR_SUBOP_DEL, cookie, FW_SUCCESS, close_flags);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_DEL failed sn:%p rn:%p rc:%d\n",
				sn, rn, rc);
		goto done;
	}
	csio_tcp_dbg(hw, "wait for mod sn:%p rn:%p io_id 0x%x--->\n", sn, rn, rn->flowid);
	wait_for_completion(mod_cmpl);
	csio_tcp_dbg(hw, "wait for mod done sn:%p rn:%p io_id 0x%x<---\n", sn, rn, rn->flowid);
done:
	return rc;
}
EXPORT_SYMBOL(coiscsi_issue_del_n_wait_for_mod);

int coiscsi_ack_mod_n_wait_for_del(struct csio_rnode *rn, void *cookie, 
		struct completion *del_cmpl)
{
	struct coiscsi_snode *sn = rn->snp;
	struct csio_hw *hw = sn->hwp;
	int rc = CSIO_SUCCESS;

	rc = csio_coiscsi_issue_tgt_program_wr(hw, sn, rn, NULL, 
					FW_FOISCSI_WR_SUBOP_MOD, cookie, FW_SCSI_IO_BLOCK, 0);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_MOD failed sn:%p rn:%p rc:%d\n",
				sn, rn, rc);
		goto done;
	}
	csio_tcp_dbg(hw, "wait for del sn:%p rn:%p io_id 0x%x===>\n", sn, rn, rn->flowid);
	wait_for_completion(del_cmpl);
	csio_tcp_dbg(hw, "wait for del done  sn:%p rn:%p io_id 0x%x<===\n", sn, rn, rn->flowid);
done:
	return rc;
}
EXPORT_SYMBOL(coiscsi_ack_mod_n_wait_for_del);

#ifdef __CSIO_ISNS_CONN_MOD__
int isns_ack_mod_n_wait_for_del(struct csio_rnode *rn, void *cookie, 
	struct completion *del_cmpl)
{
	struct csio_rnode_isns *rns = (struct csio_rnode_isns *)cookie;
	struct csio_hw *hw = rns->hwp;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_wr_pair wrp;
	struct fw_isns_wr isns_wr;
	unsigned long flags;
	uint16_t physiqid;
	int size, cpu;
	int rc = CSIO_SUCCESS;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_isns_wr), 16);
	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS)) {
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		csio_dbg(hw, "Out of credits, cannot allocate wr\n");
		return rc;
	}

	memset(&isns_wr, 0, sizeof(struct fw_isns_wr));

	/* Init FW_ISNS_WR */
	isns_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_ISNS_WR));
	isns_wr.flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(rn->flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	isns_wr.conn_attr.in_tid  = csio_cpu_to_be32(rn->flowid);

	cpu = smp_processor_id();
	physiqid = csio_q_physiqid(hw, oshw->sqset[CSIO_SQS_CLNT_TRGT][cpu].iq_idx);
	isns_wr.iq_id = csio_cpu_to_be16(physiqid);
	isns_wr.subop = FW_FOISCSI_WR_SUBOP_MOD;
	isns_wr.status = FW_SCSI_IO_BLOCK;
	isns_wr.cookie = (u64)(uintptr_t)rns;

	csio_wr_copy_to_wrp(&isns_wr, &wrp, 0, sizeof(struct fw_isns_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	csio_dump_wr_buffer((uint8_t *)&isns_wr, sizeof(struct fw_isns_wr));
#endif

	csio_tcp_dbg(hw, "wait for del rn:%p io_id 0x%x===>\n", rn, rn->flowid);
	wait_for_completion(del_cmpl);
	csio_tcp_dbg(hw, "wait for del done  rn:%p io_id 0x%x<===\n", rn, rn->flowid);

	return rc;
}
EXPORT_SYMBOL(isns_ack_mod_n_wait_for_del);
#endif

int coiscsi_issue_close_conn_wr(struct csio_rnode *rn, void *cookie)
{
	struct coiscsi_snode *sn = rn->snp;
	struct csio_hw *hw = sn->hwp;
	int rc = CSIO_SUCCESS;

	init_completion(&sn->cmplobj.cmpl);
	rc = csio_coiscsi_issue_tgt_program_wr(hw, sn, rn, NULL, 
					FW_FOISCSI_WR_SUBOP_DEL, cookie, FW_SUCCESS, 0);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_DEL failed sn:%p rn:%p rc:%d\n",
				sn, rn, rc);
		goto done;
	}
	csio_tcp_dbg(hw, "SUBOP_DEL wait cmpl sn:%p rn:%p io_id 0x%x...>\n", sn, rn, rn->flowid);
	wait_for_completion(&sn->cmplobj.cmpl);
	csio_tcp_dbg(hw, "SUBOP_DEL done sn:%p rn:%p io_id 0x%x<...\n", sn, rn, rn->flowid);
done:
	return rc;
}
EXPORT_SYMBOL(coiscsi_issue_close_conn_wr);

int coiscsi_issue_start_server_wr(struct coiscsi_snode *sn,
				uint32_t ifid)
{
	struct csio_hw *hw = sn->hwp;
	int rc;

	init_completion(&sn->cmplobj.cmpl);
	rc = csio_issue_coiscsi_tgt_wr(hw, sn, ifid,
					FW_FOISCSI_WR_SUBOP_ADD);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_ADD failed sn:%p rc:%d\n", sn, rc);
		goto done;
	}
	csio_tcp_dbg(hw, "SUBOP_ADD wait cmpl sn:%p ifid:%d \n", sn, ifid);
	wait_for_completion(&sn->cmplobj.cmpl);
	csio_tcp_dbg(hw, "SUBOP_ADD done sn:%p ifid:%d\n", sn, ifid);
done:
	return rc;
}

int coiscsi_issue_stop_server_wr(struct coiscsi_snode *sn)
{
	struct csio_hw *hw = sn->hwp;
	int rc;

	init_completion(&sn->cmplobj.cmpl);
	rc = csio_issue_coiscsi_tgt_wr(hw, sn, sn->tgt_id,
			FW_FOISCSI_WR_SUBOP_DEL);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_DEL Failed sn:%p rc:%d\n", sn, rc);
		goto done;
	}
	csio_tcp_dbg(hw, "SUBOP_DEL wait cmpl sn:%p \n", sn);
	wait_for_completion(&sn->cmplobj.cmpl);
	csio_tcp_dbg(hw, "SUBOP_DEL done sn:%p tgt_id:%d\n", sn, sn->tgt_id);
done:
	return rc;
}

int csio_chiscsi_get_tprops(struct csio_lnode_coiscsi *lncoi, 
			struct coiscsi_target_ioctl *tinfo,
			struct csio_target_props *tprops)
{
	/*struct csio_hw *hw = csio_lnode_to_hw(lncoi->ln);*/
	uint32_t lipv4;
	int rc = 0;

	tprops->tinst_ptr = &lncoi->tinst;
	tprops->disc_auth = &lncoi->disc_auth;
	tprops->port = tinfo->conn_attr.listen_port;;
	tprops->tpgt = tinfo->conn_attr.tpgt;
	tprops->ip_type = tinfo->conn_attr.ip_type;
	tprops->redir = tinfo->conn_attr.redir;;
	lipv4 = tinfo->conn_attr.listen_addr.ip4;

	if (tprops->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6)
		memcpy(tprops->ip_addr, tinfo->conn_attr.listen_addr.ip6, 16);
	else {
		/* csiostor ipv4 ips are stored flipped wrt what
		 * chiscsi expects, do not change */
		tprops->ip_addr[0] = ((lipv4 >> 24) & 0xFF) |
			((lipv4 >> 16) & 0xFF) << 8 |
			((lipv4 >> 8) & 0xFF) << 16 |
			((lipv4 & 0xFF) << 24);
	}

	return rc;
}

void coiscsi_connection_close(void *rnc_object) {
	struct csio_rnode_coiscsi *rnc = (struct csio_rnode_coiscsi *)rnc_object;
	struct csio_rnode *rn = rnc->rn;
	struct coiscsi_snode *sn = rn->snp;

	CSIO_ASSERT(rnc);
	CSIO_ASSERT(sn);

	rn->flags |= CSIO_RNF_CLOSING_CONN;
	csio_dbg(sn->hwp, "CLOSE FLAG: rn:%p rnc:%p sn:%p\n", rn,sn,rnc);
}
EXPORT_SYMBOL(coiscsi_connection_close);

void coiscsi_connection_cleanup(void *rnc_object, uint32_t fin)
{
	struct csio_rnode_coiscsi *rnc = (struct csio_rnode_coiscsi *)rnc_object;
	struct csio_rnode *rn = rnc->rn;
	struct coiscsi_snode *sn = rn->snp;
	unsigned long flags;
	uint32_t close_flags = 0;

	//DEBUG add once you finish move to argument

	CSIO_ASSERT(rnc);
	CSIO_ASSERT(sn);

	rn->flags |= CSIO_RNF_CLOSING_CONN;

	if (fin)
		close_flags |= F_FW_COISCSI_TGT_CONN_WR_FIN;

	coiscsi_issue_del_n_wait_for_mod(rn, rnc, close_flags, &rnc->mod_cmplobj.cmpl);

	coiscsi_ack_mod_n_wait_for_del(rn, rnc, &rnc->del_cmplobj.cmpl);

	rnc->ch_conn = NULL;
	/* set rn to close state */
	csio_write_lock_irqsave(hw, &sn->sn_rwlock, flags);
	/* if rn is closed then put rnc else add to close q */
		csio_put_rnc(rnc);
		csio_warn(sn->hwp, "CLOSE PUT: sn:%p rn:%p rnc:%p flags:0x%x\n",
							sn, rn, rnc, rn->flags);
	csio_write_unlock_irqrestore(hw, &sn->sn_rwlock, flags);

#if 0
	if (!passive)
		csio_work_schedule(&sn->sn_work);
#endif
}
EXPORT_SYMBOL(coiscsi_connection_cleanup);

void coiscsi_slam_clean_snodeq(struct coiscsi_snode *sn)
{
	struct csio_rnode *rn;
	struct csio_rnode_coiscsi *rnc;
	struct csio_list *tmp, *next;
	int cnt = 0;

	tmp = next = NULL;
	cnt = 0;
	csio_list_for_each_safe(tmp, next, &sn->rn_backlog) {
		rn = (struct csio_rnode *)tmp;
		rnc = csio_rnode_to_coiscsi(rn);
		csio_dbg(sn->hwp, "sending conn reject rnc %p, rn %p\n", rnc, rn);
		coiscsi_reject_conn(rnc);
		cnt++;
	}
	csio_dbg(sn->hwp, "SLAM rn_backlog queues cnt:%d\n", cnt);

	tmp = next = NULL;
	cnt = 0;
	csio_list_for_each_safe(tmp, next, &sn->rnhead) {
		rn = (struct csio_rnode *)tmp;
		rnc = csio_rnode_to_coiscsi(rn);
		if (!(rn->flags & CSIO_RNF_CLOSING_CONN)) {
			csio_dbg(sn->hwp, "sending conn close rnc %p, rn %p\n", rnc, rn);
			coiscsi_connection_cleanup(rnc, 1);
		}
		cnt++;
	}
	csio_dbg(sn->hwp, "SLAM rnhead queues cnt:%d\n", cnt);
}

void coiscsi_slam_clean_snodes(struct csio_coiscsi_tgtm *tgtm)
{
	struct csio_list *tmp, *next;
	struct coiscsi_snode *sn;
	int cnt = 0;
	/* slam clean all snode queues */

	csio_list_for_each_safe(tmp, next, &tgtm->snhead) {
		sn = (struct coiscsi_snode *) tmp;
		coiscsi_slam_clean_snodeq(sn);
		coiscsi_snode_dec_stats(tgtm, sn);
		coiscsi_issue_stop_server_wr(sn);
		csio_deq_elem(sn);
		coiscsi_snode_free(sn);
		cnt++;
	}
	/* reset head */
	csio_head_init(&tgtm->snhead);
	csio_dbg(tgtm->hw, "SLAM snodes cnt:%d\n", cnt);
}

void __coiscsi_snode_work(void *data)
{
	struct coiscsi_snode *sn = data;

	if (!sn) {
		csio_err(sn->hwp, "ERR: inside snode work sn:null\n");
		return ;
	}
	csio_dbg(sn->hwp, "%s Worker Thread sn:%p \n",
					__func__, sn);
}

int csio_chiscsi_update_portal(struct csio_target_props *tprops)
{
	int rc = 0;

	if (chiscsi_handlers && chiscsi_handlers->update_portal)
		rc = chiscsi_handlers->update_portal(tprops);
	else
		rc =  -EINVAL;

	return rc;
}

int csio_chiscsi_init_node(struct csio_lnode_coiscsi *lncoi,
			struct csio_target_props *tprops)
{
	int rc = 0;

	if (chiscsi_handlers && chiscsi_handlers->start_target_node)
		rc = chiscsi_handlers->start_target_node(tprops, lncoi->lun_list);
	else
		rc =  -EINVAL;

	return rc;
}


int csio_chiscsi_update_node(struct csio_lnode_coiscsi *lncoi,
			struct csio_target_props *tprops)
{
	int rc = 0;
	struct csio_lnode *ln = NULL;

	ln = lncoi->ln;

	if (chiscsi_handlers && chiscsi_handlers->update_target_node)
		rc = chiscsi_handlers->update_target_node(tprops, lncoi->lun_list);
	else
		rc =  -EINVAL;


	return rc;
}

int csio_chiscsi_init_server(struct coiscsi_target_ioctl *tinfo, struct coiscsi_snode *sn)
{
	int rc = 0;

	/* ch_conn is part of snode, hence searh for given snode
	 * and pass ch_conn*/
	if (chiscsi_handlers && chiscsi_handlers->start_server)
		rc = chiscsi_handlers->start_server(tinfo, (void*)sn, &sn->ch_conn);
	else
		rc = -EINVAL;

	return rc;
}

int csio_chiscsi_stop_node(struct coiscsi_target_inst *tinst)
{
	if (chiscsi_handlers && chiscsi_handlers->stop_target_node)
		return chiscsi_handlers->stop_target_node(tinst);
	else
		return -EINVAL;
}

static void
csio_snode_tmo_handler(struct csio_oss_timer *t)
{
	struct coiscsi_snode *sn = csio_container_of(t, struct coiscsi_snode,
						     sn_timer);
	complete(&sn->cmplobj.cmpl);
}

struct coiscsi_snode *
coiscsi_snode_alloc(struct csio_coiscsi_tgtm *tgtm)
{
	struct coiscsi_snode *sn = NULL;

	sn = csio_alloc(csio_md(tgtm->hw, CSIO_COISCSI_SN_MD),
			sizeof(struct coiscsi_snode),
			CSIO_MNOWAIT);

	if (!sn)
		goto err;

	memset(sn, 0, sizeof(*sn));
	sn->hwp = tgtm->hw;
	csio_head_init(&sn->rnhead);
	csio_head_init(&sn->rn_backlog);
	csio_mutex_init(&sn->sn_mtx);
	csio_rwlock_init(&sn->sn_rwlock);
	csio_timer_init(&sn->sn_timer, csio_snode_tmo_handler, 0);
	csio_work_init(&sn->sn_work, __coiscsi_snode_work,
			(void *)sn, (void*)NULL, NULL);
	sn->tgt_id = COISCSI_INVALID_TGT_ID;
err:
	return sn;
}

void coiscsi_snode_free(struct coiscsi_snode *sn)
{
	CSIO_DB_ASSERT(sn);
	csio_dbg(sn->hwp, "FREE snode:%p\n",sn);
	csio_timer_stop(&sn->sn_timer);
	csio_work_cleanup(&sn->sn_work);
	csio_free(csio_md(sn->hwp, CSIO_COISCSI_SN_MD), sn);
	return;
}

int coiscsi_snode_put_ref(struct coiscsi_snode *sn)
{
	CSIO_ASSERT(sn);
	CSIO_ASSERT(sn->ref_cnt > 0);
	sn->ref_cnt--;
	csio_dbg(sn->hwp, "%s :SNODE ref:%d \n",
			__func__, sn->ref_cnt);
	return sn->ref_cnt;
}

void coiscsi_snode_get_ref(struct coiscsi_snode *sn)
{
	CSIO_ASSERT(sn);
	sn->ref_cnt++;
	csio_dbg(sn->hwp, "%s :SNODE ref:%d \n",
			__func__, sn->ref_cnt);
}

struct coiscsi_snode 
	*coiscsi_find_snode(struct csio_coiscsi_tgtm *tgtm, 
			struct coiscsi_trgt_conn_attr *tconn_attr)
{
	int found = 0;
	struct coiscsi_snode *sn, *rsn = NULL;
	struct csio_list *tmp;

	csio_list_for_each(tmp, &tgtm->snhead) {
		sn = (struct coiscsi_snode *)tmp;
		if(tconn_attr->listen_port == sn->lprt) {
			if (tconn_attr->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if (!memcmp(tconn_attr->listen_addr.ip6,
						sn->lipv6, sizeof(sn->lipv6))) {
					found = 1;
					rsn = sn;
					break;
				}
			} else {
				if (tconn_attr->listen_addr.ip4 == 
						sn->lipv4) {
					found = 1;
					rsn = sn;
					break;
				}
			}
		}
	}

	if (found) {
		csio_dbg(tgtm->hw, "sn:%p found tgtm:%p ref:%d\n",
				rsn, tgtm, rsn->ref_cnt);
	}
	return rsn;
}


struct coiscsi_portal *coiscsi_find_portal(struct csio_lnode_coiscsi *lncoi, 
					struct coiscsi_target_ioctl *tinfo)
{
	struct coiscsi_trgt_conn_attr *tconn_attr;
	struct coiscsi_portal *tportal, *rportal = NULL;
	struct csio_list *tmp;

	/* search if the portal is already provisioned */
	csio_list_for_each(tmp, &lncoi->portal_head) {
		tportal    = (struct coiscsi_portal *) tmp;
		tconn_attr = &tportal->conn_attr;
		if (tconn_attr->listen_port == tinfo->conn_attr.listen_port) {
			if (tinfo->conn_attr.ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if (!memcmp(tconn_attr->listen_addr.ip6,
							tinfo->conn_attr.listen_addr.ip6,
							sizeof(tconn_attr->listen_addr.ip6))) {
					rportal = tportal;
					break;
				}
			} else {
				if (tconn_attr->listen_addr.ip4 == tinfo->conn_attr.listen_addr.ip4) {
					rportal = tportal;
					break;
				}
			}
		}
	}

	return rportal;
}

struct csio_lnode_coiscsi *coiscsi_find_lnode(struct csio_coiscsi_tgtm *tgtm, 
						struct coiscsi_target_inst *tinst)
{
	struct csio_list *tmp;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	uint16_t cmp_len = 0;
	/* search if lnode is already present */
	csio_list_for_each(tmp, &tgtm->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lncoi = csio_lnode_to_coiscsi(ln);
		cmp_len = max(strlen(lncoi->tinst.tgt_name), strlen(tinst->tgt_name));
		if (!memcmp(lncoi->tinst.tgt_name,tinst->tgt_name, cmp_len)) {
			break;
		} else {
			lncoi = NULL;
		}
	}

	return lncoi;
}

struct coiscsi_snode *coiscsi_find_sn_in_lncoi(struct csio_lnode_coiscsi *lncoi)
{
	struct coiscsi_portal *tportal;
	struct csio_list *tmp;
	
	csio_list_for_each(tmp, &lncoi->portal_head) {
		tportal = (struct coiscsi_portal *) tmp;
		if (tportal->snode)
			return tportal->snode;
	}

	return NULL;
}


/* returns 1 if snode is not referenced else 0 */
int coiscsi_snode_is_done(struct coiscsi_snode *sn) {

	CSIO_ASSERT(sn);

	if (sn->ref_cnt == 0) {
		csio_dbg(sn->hwp, "%s :sn:%p ref_cnt:%d\n",
				__func__, sn, sn->ref_cnt);
		if(!csio_list_empty(&sn->rnhead)) {
			csio_err(sn->hwp,"snode:%p ref:%d but list not empty \n",
					sn,sn->ref_cnt);
			CSIO_ASSERT(0);
		}
		return 1;
	}

	csio_dbg(sn->hwp, "%s :sn:%p ref_cnt:%d\n",
			__func__, sn, sn->ref_cnt);
	return 0;
}

void coiscsi_snode_inc_stats(struct csio_coiscsi_tgtm *tgtm,
					struct coiscsi_snode *sn)
{
	if ((sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) ||
		(sn->ip_type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4))
		CSIO_INC_STATS(tgtm, n_ipv4_sn_cnt);
	else 
		CSIO_INC_STATS(tgtm, n_ipv6_sn_cnt);
}

void coiscsi_snode_dec_stats(struct csio_coiscsi_tgtm *tgtm,
					struct coiscsi_snode *sn)
{
	if ((sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) ||
		(sn->ip_type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4))
		CSIO_DEC_STATS(tgtm, n_ipv4_sn_cnt);
	else 
		CSIO_DEC_STATS(tgtm, n_ipv6_sn_cnt);
}


void coiscsi_release_snode(struct csio_coiscsi_tgtm *tgtm, 
					struct coiscsi_snode *sn)
{
	struct csio_list *tmp;
	struct coiscsi_snode *tsn;
	int found = 0, rc = -CSIO_INVAL;

	/* search the snode in the snhead list */
	csio_list_for_each(tmp, &tgtm->snhead) {
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
		csio_dbg(tgtm->hw, "snode freed sn:%p wr_status:%d \n",
				sn, sn->wr_status);
		csio_deq_elem(sn);
		coiscsi_snode_free(sn);

	} else {
		//DEBUG
		csio_dbg(tgtm->hw, "BUG: snode not found in tgtm \n");
		CSIO_ASSERT(0);
	}
}

void coiscsi_release_portal_snodes(struct csio_coiscsi_tgtm *tgtm, 
					struct csio_lnode_coiscsi *lncoi)
{
	struct coiscsi_portal *tportal;
	struct coiscsi_snode  *sn;
	struct csio_list *tmp;
	int cnt = 0;
	unsigned long flags;
	/* clean the closeq for all snodes in portal list */
	csio_list_for_each(tmp, &lncoi->portal_head) {
		tportal = (struct coiscsi_portal *) tmp;
		sn = tportal->snode;
		if (sn) {
			csio_write_lock_irqsave(sn->hwp,
					&sn->sn_rwlock, flags);
			coiscsi_snode_put_ref(sn);
			csio_write_unlock_irqrestore(sn->hwp,
					&sn->sn_rwlock, flags);
			csio_dbg(tgtm->hw, "snode:%p ref put cnt:%d \n",
					sn, sn->ref_cnt);
			/* release the snode if done */
			if (coiscsi_snode_is_done(sn)) {
				coiscsi_snode_dec_stats(tgtm, sn);
				coiscsi_release_snode(tgtm, sn);
				cnt++;
			}
		} else {
			csio_dbg(tgtm->hw, "tportal:%p has no sn \n", tportal);
		}
	}
	//DEBUG
	csio_dbg(tgtm->hw, "%d snodes freed \n", cnt);
}

void coiscsi_release_portals(struct csio_lnode_coiscsi *lncoi)
{
	struct coiscsi_portal *tp;
	int cnt = 0;
	/* purge the portal list */
	while(!csio_list_empty(&lncoi->portal_head)) {
		csio_deq_from_head(&lncoi->portal_head, &tp);
		coiscsi_portal_free(lncoi, tp);
		cnt++;
	}
}



/* 
 * checks if we have resources for this ioctl.
 * returns -1 when check fails and 0 on success
 */
int coiscsi_resource_check(struct csio_coiscsi_tgtm *tgtm,
		struct coiscsi_target_ioctl *tinfo)
{

	struct coiscsi_trgt_conn_attr *tconn_attr = &tinfo->conn_attr;
	struct coiscsi_snode *sn = NULL;
	uint8_t ip_type = tinfo->conn_attr.ip_type;
	uint16_t ipv4_cnt = tgtm->stats.n_ipv4_sn_cnt;
	uint16_t ipv6_cnt = tgtm->stats.n_ipv6_sn_cnt;

	CSIO_ASSERT(ipv6_cnt <= COISCSI_IPV6_SNODE_MAX);
	CSIO_ASSERT(ipv4_cnt <= COISCSI_IPV4_SNODE_MAX);

	/* check if we are below max limits */
	if ((((ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) ||
		(ip_type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6)) &&
		(ipv6_cnt < COISCSI_IPV6_SNODE_MAX)) ||
		(((ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) ||
		(ip_type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4)) &&
		(ipv4_cnt < COISCSI_IPV4_SNODE_MAX))) {

		csio_dbg(tgtm->hw, "%s: ip_type:%d v4_cnt:%d v6_cnt:%d \n",
				__func__, ip_type, ipv4_cnt, ipv6_cnt);
		return 0;
	}
	
	/* no more new resources but we can share */
	sn = coiscsi_find_snode(tgtm, tconn_attr);

	csio_dbg(tgtm->hw, "%s: sn:%p ip_type:%d v4_cnt:%d v6_cnt:%d \n",
				__func__, sn, ip_type, ipv4_cnt, ipv6_cnt);
	return (sn)?0:-1;
}

int csio_coiscsi_assign_target_instance(struct csio_hw *hw,
		struct coiscsi_target_ioctl *tinfo,
		void *handle,
		int state)

{
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_lnode *ln = NULL;
	struct csio_os_lnode *osln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct coiscsi_target_inst *tinst = &tinfo->tinst;
	struct csio_target_props tprops;
	struct coiscsi_trgt_conn_attr *tconn_attr = &tinfo->conn_attr;
	struct csio_ctrl_chnet *chnet_cdev = NULL;
	struct coiscsi_snode *sn = NULL;
	struct coiscsi_portal *tportal = NULL;
	struct csio_chnet_iface *iface = NULL;
	struct coiscsi_vla_block v_block;
	int rc = CSIO_SUCCESS;
	int sn_alloced = 0, ln_alloced = 0;
	unsigned long flags;

	switch (state) {
	case COISCSI_LNODE_INIT:

		/* check for cdev if not we can't proceed */
		if (!(chnet_cdev = csio_hw_to_chnet_cdev(hw))) {
			csio_err(hw, "coiscsi inst not found\n");
			tinfo->retval = CSIO_ENORES;
			return CSIO_ENORES;
		}

		/* get ref to iface */
		iface = csio_chnet_iface_addr_get(hw, tinfo->conn_attr.ip_type,
				&tinfo->conn_attr.listen_addr);

		/* FIXME: Ideally we should not proceed if iface
		 * is not present but it will break the current
		 * redirection implementation. We need to address
		 * redirection portals in a more cleaner way and 
		 * not spread iface checks in this function.
		 * For now these checks are kept since they are nops
		 * and not in fastpath.
		 */
		if (!iface) {
			csio_err(hw, "Tgt Interface not provisioned; Redirection not-supported\n");
			tinfo->retval = CSIO_EIFACE_NOT_PROVISIONED;
			return CSIO_EIFACE_NOT_PROVISIONED;
		}

		/* see if we have resources */
		if(iface) {
			if (coiscsi_resource_check(tgtm, tinfo)) {
				csio_err(hw, "No Resource: Max Snode count exceeded\n");
				tinfo->retval = CSIO_ENORES;
				csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
					&tinfo->conn_attr.listen_addr);
				return CSIO_ENORES;
			}
		}

		lncoi = coiscsi_find_lnode(tgtm, tinst);

		if (!lncoi) {
			/* Allocate a COiSCSI lnode */
			osln = csio_coiscsi_alloc_lnode(tgtm);
			if (!osln) {
				tinfo->retval = CSIO_ENOMEM;
				csio_err(hw, "ln alloc failed tgtm:%p \n",tgtm);
				if (iface)
					csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
						&tinfo->conn_attr.listen_addr);
				return CSIO_ENOMEM;
			}

			ln = csio_osln_to_ln(osln);
			lncoi = csio_lnode_to_coiscsi(ln);
			/* copy the tinst so next time we know */
			memcpy(&lncoi->tinst, tinst, sizeof(struct coiscsi_target_inst));
			memcpy(&lncoi->disc_auth, &tinfo->disc_auth, sizeof(struct coiscsi_target_disc));

			if (tinst->lun_count || tinst->acl_enable) {
				/* tinst comes with a VLA at the end, this cannot be adjusted for 
				 * in csio_alloc, so we create a separate memory area for this */
				memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
				memcpy(&v_block , tinst->tgt_disk, sizeof(struct coiscsi_vla_block));
				lncoi->lun_list = kmalloc(sizeof(char) * v_block.total_len, GFP_KERNEL);
				if (!(lncoi->lun_list)) {
					tinfo->retval = CSIO_ENOMEM;
					csio_coiscsi_free_lnode(osln);
					csio_err(hw, "lunlist alloc failed tgtm:%p \n",tgtm);
					if (iface)
						csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
							&tinfo->conn_attr.listen_addr);
					return CSIO_ENOMEM;
				}
				csio_dbg(hw, "lun_count:%d, acl_enable:%d len:%d\n",
						tinst->lun_count,tinst->acl_enable, v_block.total_len);
				memcpy(lncoi->lun_list, tinst->tgt_disk, sizeof(char) * v_block.total_len);
			}
			ln_alloced = 1;
			csio_dbg(hw, "ln alloced %p \n",lncoi);
		}
		/* Fall through */

	case COISCSI_PORTAL_INIT:
		/* see if portal is present */
		tportal = coiscsi_find_portal(lncoi, tinfo);
		if (tportal) {
			csio_dbg(hw, "Portal already present :%p sn:%p\n",
					tportal,sn);
			tinfo->retval = CSIO_EINST_EXISTS;
			if (iface)
				csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
					&tinfo->conn_attr.listen_addr);
			return CSIO_EINST_EXISTS;
		}

		if (!tportal) {
			/* allocate a portal */
			tportal = coiscsi_portal_alloc(lncoi);
			if (!tportal) {
				csio_err(hw, "%s portal alloc failed for lncoi:%p \n",
					__func__, lncoi);
				tinfo->retval = CSIO_ENOMEM;
				rc = CSIO_ENOMEM;
				goto ln_clean;
			}
			tportal->iface = iface;
			/* copy the conn attributes and enqueue */
			memcpy(&tportal->conn_attr, &tinfo->conn_attr, 
					sizeof(struct coiscsi_trgt_conn_attr));
			/* enqueue the portal but remember portal is not
			 * initialized to chiscsi unless a valid snode is
			 * found for this lnode
			 */
			csio_enq_at_tail(&lncoi->portal_head, tportal);
			csio_dbg(hw, "portal:%p allocted and enqueued on lncoi:%p\n",
					tportal, lncoi);
		}
		/* Fall through */

	case COISCSI_SNODE_INIT:
		/* see if we have an existing snode for this portal */
		sn = coiscsi_find_snode(tgtm, tconn_attr);
		if (sn) {
			csio_dbg(hw, "sn:%p exists for portal:%p lncoi:%p\n",
					sn, tportal,lncoi);
			//more debug code
			if (tportal->snode)
				BUG_ON(tportal->snode != sn);

			tportal->snode = sn;
			tportal->init_done = 1;
		} else {
			tportal->snode = NULL;
			tportal->init_done = 0;
		}

		/* if no sn alloc */
		if (!sn && iface) {
			sn = coiscsi_snode_alloc(tgtm);
			if (!sn) {
				csio_err(hw, "sn alloc failed for tgtm:%p \n",tgtm);
				tinfo->retval = CSIO_ENOMEM;
				rc = CSIO_ENOMEM;
				goto tp_clean;
			}

			sn->lprt = tinfo->conn_attr.listen_port;

			if (tinfo->conn_attr.ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6)
				memcpy(sn->lipv6, tinfo->conn_attr.listen_addr.ip6, 
						sizeof(sn->lipv6));
			else
				sn->lipv4 = tinfo->conn_attr.listen_addr.ip4;

			sn->ip_type = tinfo->conn_attr.ip_type;
			sn->tpgt = tinfo->conn_attr.tpgt;
			sn->redir = tinfo->conn_attr.redir;

			/* save context info */
			sn->tinfo   = tinfo;
			sn->handle  = handle;
			sn->hw      = hw;
			sn->lncoi   = lncoi;
			sn->tportal = tportal;
			/* set the op flag */
			sn->op_flag |= COISCSI_SNODE_OPF_ASSIGN;
			sn->tcp_wscale = tinst->tcp_wscale;
			sn->tcp_wsen = tinst->tcp_wsen;

			csio_dbg(hw, "ln:0x%p sn:0x%p lncoi:0x%p, lipv4:0x%x, lprt:0x%x\n",
							ln, sn, lncoi, sn->lipv4, sn->lprt);
			lncoi->transport_handle = handle;
			/* send FW_COISCSI_TGT_WR now */
			rc = coiscsi_issue_start_server_wr(sn, iface->if_id);
			if ((rc != CSIO_SUCCESS) || (sn->wr_status != 0)) {
				csio_err(hw, "FATAL: START SERVER WR FAILED"
					"hw:%p sn:%p ifid:%d rc:%d status:%d\n",
					hw, sn, iface->if_id, rc, sn->wr_status);
				coiscsi_snode_free(sn);
				tinfo->retval = CSIO_ELISTEN_FAIL;
				rc = CSIO_ELISTEN_FAIL;
				goto tp_clean;
			}
			sn_alloced = 1;
			coiscsi_snode_inc_stats(tgtm, sn);
		}
		/* Fall through */

	case COISCSI_CH_INIT:

		csio_chiscsi_get_tprops(lncoi, tinfo, &tprops);
		
		/* FIXME: need to unify all the below three chiscsi calls */
		/* chiscsi handles whether this is a new node or only a portal update */
		rc = csio_chiscsi_init_node(lncoi, &tprops);
		if (rc) {
			csio_err(hw, "chiscsi init node failed ln:%p \n",lncoi);
			tinfo->retval = CSIO_ENODE_INIT_FAIL;
			rc = CSIO_ENODE_INIT_FAIL;
			goto sn_clean;
		}

		rc = csio_chiscsi_update_portal(&tprops);
		if (rc) {
			csio_err(hw,"chiscsi update portal failed tprops:%p\n",&tprops);
			csio_chiscsi_stop_node(&lncoi->tinst);
			tinfo->retval = CSIO_ENODE_INIT_FAIL;
			rc = CSIO_ENODE_INIT_FAIL;
			goto sn_clean;
		}

		if (sn) {
			rc = csio_chiscsi_init_server(tinfo, sn);
			if (rc) {
				csio_err(hw,"chiscsi init server failed sn:%p\n",sn);
				csio_chiscsi_stop_node(&lncoi->tinst);
				tinfo->retval = CSIO_ENODE_INIT_FAIL;
				rc = CSIO_ENODE_INIT_FAIL;
				goto sn_clean;
			}
		}

		/* all is fine so let's take an sn ref */
		if (sn) {
			/* this extra check is done to simply cleanup
			 * ideally all the chiscsi calls should be a
			 * single call so if it fails then we don't need
			 * to get reference to snode
			 */
			if (sn_alloced) {
				tportal->snode = sn;
				csio_enq_at_tail(&tgtm->snhead, sn);
			}
			csio_write_lock_irqsave(sn->hwp, &sn->sn_rwlock, flags);
			coiscsi_snode_get_ref(sn);
			csio_write_unlock_irqrestore(sn->hwp, &sn->sn_rwlock, flags);
			tportal->init_done = 1;
			csio_dbg(hw, "portal initied tinfo:%p tportal:%p sn:%p snref:%d \n",
					tinfo,tportal,sn,sn->ref_cnt);
		}

		lncoi->portal_cnt++;
		csio_dbg(hw, "target added tportal:%p\n",tportal);
		break;
	default:
		CSIO_ASSERT(0);
	}

	return rc;

	/* clean up and return */
sn_clean:
	/* free only if newly alloced */
	if (sn_alloced) {
		coiscsi_snode_dec_stats(tgtm, sn);
		coiscsi_issue_stop_server_wr(sn);
		csio_dbg(tgtm->hw, "snode freed sn:%p wr_status:%d \n",
				sn, sn->wr_status);
		coiscsi_snode_free(sn);
	}
tp_clean:
	/* there will always be atleast one new portal add */
	csio_deq_elem(tportal);
	coiscsi_portal_free(lncoi,tportal);
ln_clean:
	/* free only if newly alloced */
	if (ln_alloced)
		csio_coiscsi_free_lnode_coiscsi(lncoi);

	if (iface)
		csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
			&tinfo->conn_attr.listen_addr);

	return rc;
}

int csio_coiscsi_remove_target_instance(struct csio_hw *hw,
		struct coiscsi_target_ioctl *tinfo, void *handle)
{

	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct coiscsi_target_inst *tinst = &tinfo->tinst;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct coiscsi_portal *tportal    = NULL;
	int rv = CSIO_SUCCESS;


	// 1. find the ln instance of the target 
	lncoi = coiscsi_find_lnode(tgtm, tinst);

	if (!lncoi) {
		csio_err(hw, "Lnode instance not found for :%s \n",tinst->tgt_name);
		return -EINVAL;
	}
	
	// 2.  find the portal for the instance on the ln
	// 2.1 if there is no matching portal it's a bug. 
	
	tportal = coiscsi_find_portal(lncoi, tinfo);

	if (!tportal) {
		csio_err(hw, "tportal instance not found on ln:%p for :%s \n",
				lncoi, tinst->tgt_name);
		return -EINVAL;
	}


	// 2.2 if portal is found mark the portal for removal (decrement portalcount)
	// 2.3 if portal count is not zero return
	// 2.4 we need to mark any snodes
	
	lncoi->portal_cnt--;
	if (tportal->iface)
		csio_chnet_iface_addr_put(hw, tportal->iface, tinfo->conn_attr.ip_type,
			&tinfo->conn_attr.listen_addr);
	if (lncoi->portal_cnt) {
		csio_dbg(hw, "DEBUG: Portal marked to remove ln:%p portalcnt:%d \n",
				lncoi, lncoi->portal_cnt);
		return CSIO_SUCCESS;
	}

	csio_dbg(hw, "DEBUG: goign to initiate node stop on tinst:%s \n",
			lncoi->tinst.tgt_name);
	/*
	* 3.1. initiate iscsi_node_remove which will schedule
	*      the close connection and wait till all sessions
	*      are removed.
	*/
	rv = csio_chiscsi_stop_node(&lncoi->tinst);

	if (rv) {
		csio_err(hw, "Chiscsi node remove failed: rv:%d for :%s \n",
				rv, tinst->tgt_name);
			return -EINVAL;
	}

	csio_dbg(hw, "DEBUG: node stop on tinst:%s RETURNED \n",
						lncoi->tinst.tgt_name);

	/* release the snodes belonging to this node */
	coiscsi_release_portal_snodes(tgtm, lncoi);
	/* release the portals */

	// portal remove
	coiscsi_release_portals(lncoi);

	// remove the lnode
	csio_dbg(hw,"Freeing lncoi:%p tinst:%s\n",lncoi,
			lncoi->tinst.tgt_name);

	csio_coiscsi_free_lnode_coiscsi(lncoi);

	if (csio_list_empty(&tgtm->sln_head))
		coiscsi_slam_clean_snodes(tgtm);
	
	return 0;
}

int csio_coiscsi_update_target_instance(struct csio_hw *hw,
		struct coiscsi_target_ioctl *tinfo, void *handle)
{

	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_lnode *ln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct coiscsi_target_inst *tinst = &tinfo->tinst;
	struct csio_target_props tprops;
	struct csio_list *tmp;
	struct csio_chnet_iface *iface = NULL;
	struct coiscsi_vla_block v_block;
	struct coiscsi_portal *tportal;
	int rc = CSIO_SUCCESS;
	uint16_t exists = 0;
	uint16_t cmp_len = 0;

	iface = csio_chnet_iface_addr_get(hw, tinfo->conn_attr.ip_type,
			&tinfo->conn_attr.listen_addr);

	if (!iface) {
		csio_err(hw, "Tgt Interface not provisioned\n");
		rc = CSIO_EIFACE_NOT_PROVISIONED;
		goto out;
	}

	/*
 	 * put back the iface. It was got, only to check if iface was provisioned.
 	 */
	csio_chnet_iface_addr_put(hw, iface, tinfo->conn_attr.ip_type,
		&tinfo->conn_attr.listen_addr);
	
	csio_list_for_each(tmp, &tgtm->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lncoi = csio_lnode_to_coiscsi(ln);
		cmp_len = max(strlen(lncoi->tinst.tgt_name), strlen(tinst->tgt_name));
		if (!memcmp(lncoi->tinst.tgt_name,tinst->tgt_name, cmp_len)) {
			break;
		} else {
			lncoi = NULL;
		}
	}

	if(!lncoi) {
		csio_err(hw, "Update for non-existing target %s\n",tinst->tgt_name);
		rc = CSIO_EINST_NOT_FOUND;
		goto out;
	}

	if (lncoi) {
		csio_mutex_lock(&lncoi->lnc_mtx);
		if (lncoi->op_pending) {
			tinfo->retval = CSIO_EIFACE_BUSY;
			rc = EBUSY;
			goto ulock_out;
		}
	}

	csio_list_for_each(tmp, &lncoi->portal_head) {
		tportal = (struct coiscsi_portal *)tmp;
		if (tportal->conn_attr.listen_port == tinfo->conn_attr.listen_port) {
			if (tinfo->conn_attr.ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if (!memcmp(tportal->conn_attr.listen_addr.ip6,
					tinfo->conn_attr.listen_addr.ip6,
					sizeof(tinfo->conn_attr.listen_addr.ip6)))
					exists = 1;
			} else {
				if (tportal->conn_attr.listen_addr.ip4 == 
						tinfo->conn_attr.listen_addr.ip4)
					exists = 1;
			}
		}
	}

	if (!exists) {
		csio_dbg(hw, "New portal %d:%d, Portal update not supported\n",
		                tinfo->conn_attr.listen_addr.ip4,
				tinfo->conn_attr.listen_port);
		rc = CSIO_EINVAL;
		goto ulock_out;
	}

	memcpy(&lncoi->tinst, tinst, sizeof(struct coiscsi_target_inst));
	memcpy(&lncoi->disc_auth, &tinfo->disc_auth, sizeof(struct coiscsi_target_disc));

	if (tinst->lun_count || tinst->acl_enable) {
		/* tinst comes with a VLA at the end, this cannot be adjusted for 
		 * in csio_alloc, so we create a separate memory area for this */
		memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
		memcpy(&v_block , tinst->tgt_disk, sizeof(struct coiscsi_vla_block));

		lncoi->lun_list = kmalloc(sizeof(char) * v_block.total_len, GFP_KERNEL);
		if (!(lncoi->lun_list)) {
			rc = -ENOMEM;
			goto ulock_out;
		}
		memcpy(lncoi->lun_list, tinst->tgt_disk, sizeof(char) * v_block.total_len);
	}
	
	/* We got a new COiSCSI lnode, init all chiscsi stuffs
	 * required for __this__ target instance */
	rc = csio_chiscsi_get_tprops(lncoi, tinfo, &tprops);

	/* chiscsi handles whether this is a new node or only a portal update */
	rc = csio_chiscsi_update_node(lncoi, &tprops);

ulock_out:
	csio_mutex_unlock(&lncoi->lnc_mtx);
out:
	return rc;
}

int csio_coiscsi_show_target_instance(struct csio_hw *hw,
                struct coiscsi_target_ioctl *tinfo, void *handle)
{

	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_lnode *ln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct coiscsi_vla_block v_block;
	struct coiscsi_portal_info co_portal;
	struct coiscsi_portal *tportal;
	struct coiscsi_trgt_conn_attr *c_attr;
	struct csio_list *tmp;
	int rc = CSIO_SUCCESS;
	char *ptmp;
	uint16_t lbuf_size = 0;


	csio_list_for_each(tmp, &tgtm->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lncoi = csio_lnode_to_coiscsi(ln);
		if (!strcmp(lncoi->tinst.tgt_name, tinfo->tinst.tgt_name)) {
			memcpy(&tinfo->tinst, &lncoi->tinst, sizeof(struct coiscsi_target_inst));

			if(lncoi->lun_list) {
				memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
				memcpy(&v_block, lncoi->lun_list, sizeof(struct coiscsi_vla_block));
				lbuf_size = v_block.total_len;
				memcpy(tinfo->tinst.tgt_disk, lncoi->lun_list, (sizeof(char) * lbuf_size));
			}
			ptmp = (tinfo->tinst.tgt_disk + (sizeof(char) * lbuf_size));
			csio_list_for_each(tmp, &lncoi->portal_head) {
				memset(&co_portal, 0, sizeof(struct coiscsi_portal_info));
				tportal = (struct coiscsi_portal *)tmp;
				c_attr  = &tportal->conn_attr;

				if (c_attr->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6)
					memcpy(&co_portal.ip.ip6, c_attr->listen_addr.ip6, 
							sizeof(c_attr->listen_addr.ip6));
				else
					co_portal.ip.ip4 = c_attr->listen_addr.ip4;

				co_portal.port = c_attr->listen_port;
				co_portal.tpgt = c_attr->tpgt;
				co_portal.ip_type = c_attr->ip_type;
				co_portal.redir = c_attr->redir;

				memcpy(ptmp, &co_portal, sizeof(struct coiscsi_portal_info));
				ptmp += sizeof(struct coiscsi_portal_info);
			}
			return rc;
		}
	}

	return rc;
}


int csio_coiscsi_get_target_info(struct csio_hw *hw,
		struct coiscsi_target_info_ioctl *tinfo, void *handle)
{
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_lnode *ln = NULL;
	struct csio_lnode_coiscsi *lncoi = NULL;
	struct csio_list *tmp;
	struct coiscsi_vla_block v_block;
	int rc = CSIO_SUCCESS;

	csio_list_for_each(tmp, &tgtm->sln_head) {
		ln = (struct csio_lnode *) tmp;
		lncoi = csio_lnode_to_coiscsi(ln);
		if (!strcmp(lncoi->tinst.tgt_name, tinfo->tgt_name)) {
			tinfo->lun_count = lncoi->tinst.lun_count;
			tinfo->portal_count = lncoi->portal_cnt;
			if(lncoi->lun_list) {
				memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
				memcpy(&v_block, lncoi->lun_list, sizeof(struct coiscsi_vla_block));
				tinfo->lun_buf_size = v_block.total_len;
			}

			if (chiscsi_handlers && chiscsi_handlers->display_target_info)
				rc = chiscsi_handlers->display_target_info(&lncoi->tinst, tinfo->databuf);
			break;
		} else
			lncoi = NULL;
	}

	if (!lncoi)
		rc = CSIO_EZERO_OBJ_FOUND;

	return rc;
}

int csio_coiscsi_get_target_stats(struct csio_hw *hw, 
		struct coiscsi_target_stats_ioctl *stats, uint32_t op, void *handle)
{
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	uint8_t subop;
	int rc = CSIO_SUCCESS;

	init_completion(&tgtm->cmplobj.cmpl);
	/* Send FW_COISCST_STATS_WR with subop TOTAL and populate stats 
	 * TOTAL(index 0) details */
	rc = csio_issue_coiscsi_stats_wr(hw, stats, FW_COISCSI_WR_SUBOP_TOT);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_TOT failed rc:%d\n", rc);
		goto done;
	}
	csio_dbg(hw, "SUBOP_TOT wait cmpl rc %d \n", rc);
	wait_for_completion(&tgtm->cmplobj.cmpl);
	csio_dbg(hw, "SUBOP_TOT done rc %d \n", rc);

	if(stats->wr_status) {
		csio_err(hw, "TOT STATS wr failed, status %d\n", stats->wr_status);
		rc = CSIO_EINVAL;
		goto done;
	}

	/* Send FW_COISCST_STATS_WR with subop TOTAL and populate stats 
	 * MAX(index 1) details */
	if(op == CSIO_COISCSI_TARGET_STATS_CLR_IOCTL)
		subop = FW_COISCSI_WR_SUBOP_CLR;
	else
		subop = FW_COISCSI_WR_SUBOP_MAX;

	rc = csio_issue_coiscsi_stats_wr(hw, stats, subop);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_MAX failed rc:%d\n", rc);
		goto done;
	}
	csio_dbg(hw, "SUBOP_MAX wait cmpl rc %d \n", rc);
	wait_for_completion(&tgtm->cmplobj.cmpl);
	csio_dbg(hw, "SUBOP_MAX done rc %d \n", rc);

	if(stats->wr_status) {
		csio_err(hw, "MAX STATS wr failed, status %d\n", stats->wr_status);
		rc = CSIO_EINVAL;
		goto done;
	}

	/* Send FW_COISCST_STATS_WR with subop TOTAL and populate stats 
	 * CUR(index 2) details */
	rc = csio_issue_coiscsi_stats_wr(hw, stats, FW_COISCSI_WR_SUBOP_CUR);
	if (rc != CSIO_SUCCESS) {
		csio_err(hw, "SUBOP_CUR failed rc:%d\n", rc);
		goto done;
	}
	csio_dbg(hw, "SUBOP_CUR wait cmpl rc %d \n", rc);
	wait_for_completion(&tgtm->cmplobj.cmpl);
	csio_dbg(hw, "SUBOP_CUR done rc %d \n", rc);

	if(stats->wr_status) {
		csio_err(hw, "CUR STATS wr failed, status %d\n", stats->wr_status);
		rc = CSIO_EINVAL;
	}

done:
	return rc;
}

void csio_register_target_handlers(struct uld_tgt_handler *ch_handlers) {
	chiscsi_handlers = ch_handlers;

	if (ch_handlers != NULL) {
		ch_handlers->xmit_data = coiscsi_xmit_data;
		ch_handlers->adjust_connection = csio_issue_adjust_conn_wr;
		ch_handlers->send_isns_pdu = csio_isns_pdu_handle;
		ch_handlers->send_isns_conn_req = csio_isns_conn_handle;
	}
}

EXPORT_SYMBOL(csio_register_target_handlers);
