/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function definitions for COiSCSI fwevt handlers
 *
 */
#include <csio_lnode.h>
#include <csio_snode.h>
#include <csio_rnode.h>
#include <csio_coiscsi_ioctl.h>
#include <csio_os_hw.h>
#include <csio_ctrl_devs.h>
#include <csio_coiscsi_external.h>
#include <csio_lnode_coiscsi.h>
#include <csio_rnode_coiscsi.h>
#include <csio_coiscsi_fwevts.h>

extern struct uld_tgt_handler *chiscsi_handlers;

int csio_coiscsi_tgt_fwevt_handler(struct csio_hw *hw, struct fw_coiscsi_tgt_wr *wr)
{
	int rc = CSIO_SUCCESS;
	struct coiscsi_snode *sn =
		(struct coiscsi_snode *)(uintptr_t)wr->cookie;

	/* Handler target WR response from FW */
#ifdef __CSIO_DEBUG__
	csio_dump_wr_buffer((uint8_t *)wr, sizeof(struct fw_coiscsi_tgt_wr));
#endif

	if (!wr->status) {

		if (wr->subop ==  FW_FOISCSI_WR_SUBOP_ADD) {
			sn->tgt_id = G_FW_WR_FLOWID(csio_be32_to_cpu(wr->flowid_len16));
			csio_tcp_dbg(hw, "tgt wr success sn:%p tgt_id:%d\n",sn,sn->tgt_id);
		} else if (wr->subop == FW_FOISCSI_WR_SUBOP_DEL) {
			csio_tcp_dbg(hw, "sub op del succes sn:%p \n",sn);
		}
	} else {
		csio_tcp_dbg(hw, "tgt wr failed sn:%p \n",sn);
	}

	sn->wr_status = wr->status;
	complete(&sn->cmplobj.cmpl);

	return rc;
}

int csio_coiscsi_stats_fwevt_handler(struct csio_hw *hw, struct fw_coiscsi_stats_wr *wr)
{
	struct coiscsi_target_stats_ioctl *stats =
		(struct coiscsi_target_stats_ioctl *)(uintptr_t)wr->cookie;
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	int i, rc = CSIO_SUCCESS;

	/* Handler target WR response from FW */
#ifdef __CSIO_DEBUG__
	csio_dump_wr_buffer((uint8_t *)wr, sizeof(struct fw_coiscsi_stats_wr));
#endif

	if (!wr->status) {

		csio_dbg(hw, "tgt wr success, subop :%d \n",wr->subop);
		if (wr->subop ==  FW_COISCSI_WR_SUBOP_TOT) {
			stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_TOT] = 
						wr->u.rsrc.num_ipv4_tgt;
			stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_TOT] = 
						wr->u.rsrc.num_ipv6_tgt;
			stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_TOT] = 
					csio_be16_to_cpu(wr->u.rsrc.num_l2t_entries);
			stats->u.rsrc.num_csocks[TGT_FW_RSRC_TOT] = 
					csio_be16_to_cpu(wr->u.rsrc.num_csocks);
			stats->u.rsrc.num_tasks[TGT_FW_RSRC_TOT] = 
					csio_be16_to_cpu(wr->u.rsrc.num_tasks);
			stats->u.rsrc.num_bufll64[TGT_FW_RSRC_TOT] =
				csio_be32_to_cpu(wr->u.rsrc.num_bufll64);

			csio_dbg(hw, "TOT: ipv4 0x%x ipv6 0x%x l2t 0x%x "
				"csock 0x%x ntasks 0x%x nbufll64 0x%x\n",
				stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_TOT], 
				stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_TOT],
				stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_TOT], 
				stats->u.rsrc.num_csocks[TGT_FW_RSRC_TOT],
				stats->u.rsrc.num_tasks[TGT_FW_RSRC_TOT],
				stats->u.rsrc.num_bufll64[TGT_FW_RSRC_TOT]);

			for(i=0 ; i<MAX_PPOD_ZONES ; i++) {
				stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_TOT] = 
					csio_be16_to_cpu(wr->u.rsrc.num_ppods_zone[i]);
				csio_dbg(hw, "TOT: zone %d ppods 0x%x\n", 
					i, stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_TOT]);
			}			
		} else if (wr->subop == FW_COISCSI_WR_SUBOP_MAX ||
				wr->subop == FW_COISCSI_WR_SUBOP_CLR) {
			stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_MAX] = 
						wr->u.rsrc.num_ipv4_tgt;
			stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_MAX] = 
						wr->u.rsrc.num_ipv6_tgt;
			stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_MAX] = 
					csio_be16_to_cpu(wr->u.rsrc.num_l2t_entries);
			stats->u.rsrc.num_csocks[TGT_FW_RSRC_MAX] = 
					csio_be16_to_cpu(wr->u.rsrc.num_csocks);
			stats->u.rsrc.num_tasks[TGT_FW_RSRC_MAX] = 
					csio_be16_to_cpu(wr->u.rsrc.num_tasks);
			stats->u.rsrc.num_bufll64[TGT_FW_RSRC_MAX] =
				csio_be32_to_cpu(wr->u.rsrc.num_bufll64);

			csio_dbg(hw, "MAX: ipv4 0x%x ipv6 0x%x l2t 0x%x "
				"csock 0x%x ntasks 0x%x nbufll64 0x%x\n",
				stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_MAX], 
				stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_MAX],
				stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_MAX], 
				stats->u.rsrc.num_csocks[TGT_FW_RSRC_MAX],
				stats->u.rsrc.num_tasks[TGT_FW_RSRC_MAX],
				stats->u.rsrc.num_bufll64[TGT_FW_RSRC_MAX]);

			for(i=0 ; i<MAX_PPOD_ZONES ; i++) {
				stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_MAX] = 
					csio_be16_to_cpu(wr->u.rsrc.num_ppods_zone[i]);	
				csio_dbg(hw, "MAX: zone %d ppods 0x%x\n", 
					i, stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_MAX]);
			}
		} else if (wr->subop == FW_COISCSI_WR_SUBOP_CUR) {
			stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_CUR] = 
						wr->u.rsrc.num_ipv4_tgt;
			stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_CUR] = 
						wr->u.rsrc.num_ipv6_tgt;
			stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_CUR] = 
					csio_be16_to_cpu(wr->u.rsrc.num_l2t_entries);
			stats->u.rsrc.num_csocks[TGT_FW_RSRC_CUR] = 
					csio_be16_to_cpu(wr->u.rsrc.num_csocks);
			stats->u.rsrc.num_tasks[TGT_FW_RSRC_CUR] = 
					csio_be16_to_cpu(wr->u.rsrc.num_tasks);
			stats->u.rsrc.num_bufll64[TGT_FW_RSRC_CUR] =
				csio_be32_to_cpu(wr->u.rsrc.num_bufll64);

			csio_dbg(hw, "CUR: ipv4 0x%x ipv6 0x%x l2t 0x%x "
				"csock 0x%x ntasks 0x%x nbufll64 0x%x\n",
				stats->u.rsrc.num_ipv4_tgt[TGT_FW_RSRC_CUR], 
				stats->u.rsrc.num_ipv6_tgt[TGT_FW_RSRC_CUR],
				stats->u.rsrc.num_l2t_entries[TGT_FW_RSRC_CUR], 
				stats->u.rsrc.num_csocks[TGT_FW_RSRC_CUR],
				stats->u.rsrc.num_tasks[TGT_FW_RSRC_CUR],
				stats->u.rsrc.num_bufll64[TGT_FW_RSRC_CUR]);

			for(i=0 ; i<MAX_PPOD_ZONES ; i++) {
				stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_CUR] = 
					csio_be16_to_cpu(wr->u.rsrc.num_ppods_zone[i]);
				csio_dbg(hw, "CUR: zone %d ppods 0x%x\n", 
					i, stats->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_CUR]);
			}
		}
	} else {
		csio_err(hw, "stats wr failed, status:%d \n", wr->status);
	}

	stats->wr_status = wr->status;
	complete(&tgtm->cmplobj.cmpl);

	return rc;
}

#define FLOWID_INVALID 0xffffffff
int csio_coiscsi_tgt_conn_fwevt_handler(struct csio_hw *hw,
				struct fw_coiscsi_tgt_conn_wr *wr)
{
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_rnode_coiscsi *rnc = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_scsi_qset *sqset = NULL;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_scsi_cpu_info *cpu_info;
	struct csio_list *tmp;
	int rc = CSIO_SUCCESS, found = 0;
	unsigned long flags;

	switch (wr->subop) {
	case FW_FOISCSI_WR_SUBOP_ADD:
		/* Handle target conn WR response from FW */
		csio_list_for_each(tmp, &tgtm->snhead) {
			sn = (struct coiscsi_snode *)tmp;
			csio_tcp_dbg(hw, "sn:%p, wr:%p, sn->tgt_id:0x%x, wr->conn_iscsi.tgt_id:0x%x, wr->in_stid:0x%x\n",
					sn, wr, sn->tgt_id, 
					csio_be32_to_cpu(wr->conn_iscsi.tgt_id),
					csio_be32_to_cpu(wr->in_stid));
			if (sn->tgt_id == csio_be32_to_cpu(wr->conn_iscsi.tgt_id))
				found =1;
			else
				sn = NULL;
			if (found)
				break;
		}

		if (!sn) {
			csio_tcp_dbg(hw, "Connection request for unknown target flowid %d\n",
					csio_be32_to_cpu(wr->conn_iscsi.tgt_id));
			rc = CSIO_EINVAL;
			goto out;
		}

		/* check if snode is marked for removal */
		if (test_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags)) {
			csio_tcp_dbg(hw, "Connection request for stopped target\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		csio_tcp_dbg(hw, "conn SUBOP_ADD rcvd sn:%p, sn->listen_id:0x%x, wr->listen_id:0x%x, io_id:0x%x\n",
				sn, sn->tgt_id, csio_be32_to_cpu(wr->in_stid),
				G_FW_WR_FLOWID(csio_be32_to_cpu(wr->flowid_len16)));


		csio_write_lock_irqsave(hw, &sn->sn_rwlock, flags);
		rnc = csio_get_rnc(sn, G_FW_WR_FLOWID(csio_be32_to_cpu(wr->flowid_len16)));
		if (!rnc) {
			rc = CSIO_NOMEM;
			csio_dbg(hw, "rnc is NULL\n");
			csio_write_unlock_irqrestore(hw, &sn->sn_rwlock, flags);
			goto out;
		}

		cpu_info = &oshw->scsi_cpu_info[CSIO_SQS_CLNT_TRGT];
		sqset = &oshw->sqset[CSIO_SQS_CLNT_TRGT][cpu_info->cur_iq_cpu];
		cpu_info->cur_iq_cpu =
				(cpu_info->cur_iq_cpu + 1) % cpu_info->max_cpus;

		rn = rnc->rn;
		csio_rnode_to_snode(rn) = sn;
		rn->eq_idx = sqset->eq_idx;
		rn->iq_idx = sqset->iq_idx;

		csio_tcp_dbg(hw, "flq_idx:%d, iq_idx:%d, iqid:%d\n",
				csio_q_iq_flq_idx(hw, rn->iq_idx),
				rn->iq_idx,
				csio_q_physiqid(hw, rn->iq_idx));

		csio_tcp_dbg(hw, "rnc:%p, rn:%p, sn:%p, eq_idx:%u, iq_idx:%u wscale:%u\n",
				rnc, rn, csio_rnode_to_snode(rn), rn->eq_idx, rn->iq_idx,
				G_FW_COISCSI_TGT_CONN_WR_WSCALE(wr->u.conn_tcp.wscale_wsen));

		rnc->v_num[4] = csio_be16_to_cpu(wr->u.conn_tcp.in_dport);

		/* chiscsi accepts peer addess in BE */
		if (sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
			rnc->v_num[2] = 0xffff0000;
			memcpy(&rnc->v_num[3], &wr->u.conn_tcp.u.in_addr.daddr, sizeof(uint32_t));
		} else {
			memcpy(&rnc->v_num[0], &wr->u.conn_tcp.u.in_addr6.daddr[0], sizeof(uint64_t));
			memcpy(&rnc->v_num[2], &wr->u.conn_tcp.u.in_addr6.daddr[1], sizeof(uint64_t));
		}

		wr->cookie = (u64)(uintptr_t)rnc;
		/* save the wr on rnc */
		memcpy(&rnc->c_wr, wr, sizeof(struct fw_coiscsi_tgt_conn_wr));
		if (chiscsi_handlers && chiscsi_handlers->accept_connection)
			rc = chiscsi_handlers->accept_connection(sn->ch_conn, sn, hw, hw->os_dev);

		csio_write_unlock_irqrestore(hw, &sn->sn_rwlock, flags);
		break;
	case FW_FOISCSI_WR_SUBOP_MOD:
		rnc = (struct csio_rnode_coiscsi *)wr->cookie;
		
		if (!rnc) {
			csio_err(hw, "FATAL: Conn close WR(MOD):%p with null rnc\n",wr);
			goto out;
		}
	
		rn = rnc->rn;

		if (wr->status == FW_SCSI_IO_BLOCK) {

			csio_warn(hw, "conn SUBOP_MOD rcvd sts: FW_SCSI_IO_BLOCK rnc:%p, conn:%p flags:0x%x\n",
					rnc, rnc->ch_conn, rn->flags);

			/* If connection is not in closign state initiate close */
			if (!(rn->flags & CSIO_RNF_CLOSING_CONN) &&
					chiscsi_handlers &&
					chiscsi_handlers->close_connection) {
				rn->flags |= CSIO_RNF_CLOSING_CONN;
				csio_tcp_dbg(hw, "FW Initiated close  rn:%p rnc:%p sn:%p\n",
					rnc, rnc->rn, rnc->rn->snp);
				chiscsi_handlers->close_connection(rnc->ch_conn,
							rnc, hw->os_dev, 1);
			}
			/* Complete mod object */
			complete(&rnc->mod_cmplobj.cmpl);
		} else {
			csio_tcp_dbg(hw, "SUBOP_MOD rcvd adjust wr rn:%p rnc:%p sn:%p\n",
				rnc, rnc->rn, rnc->rn->snp);
			complete(&rnc->rn->snp->cmplobj.cmpl);
		}
		break;
	case FW_FOISCSI_WR_SUBOP_DEL:
		rnc = (struct csio_rnode_coiscsi*)wr->cookie;
		/* this is fatal */
		if (!rnc) {
			csio_err(hw, "FATAL: Conn close WR(DEL):%p with null rnc\n",wr);
			goto out;
		}

		rn = rnc->rn;
		sn = csio_rnode_to_snode(rn);

		csio_info(hw, "conn:%p ddp_reqs %d ddp_cmpls %d ddp_aborts %d ddp_bps %d\n",
			rnc->ch_conn, csio_be32_to_cpu(wr->u.stats.ddp_reqs), csio_be32_to_cpu(wr->u.stats.ddp_cmpls),
			csio_be16_to_cpu(wr->u.stats.ddp_aborts), csio_be16_to_cpu(wr->u.stats.ddp_bps));
		//DEBUG
		csio_warn(hw, "conn SUBOP_DEL rcvd "
				"sn:%p rnc:%p rn:%p conn:%p flag:0x%x\n", 
				sn, rnc, rn, rnc->ch_conn, rn->flags);

		/* Invalidate flow-id for this connection */
		rn->flowid = FLOWID_INVALID;
		/* Complete del object */
		complete(&rnc->del_cmplobj.cmpl);
		break;
	default:
		CSIO_DB_ASSERT(0);
	}
out:
	return rc;
}

int 
csio_isns_conn_fwevt_handler(struct csio_hw *hw, struct fw_coiscsi_tgt_conn_wr *wr)
{
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct csio_rnode_isns *rns = NULL;
	struct csio_rnode *rn = NULL;
	struct coiscsi_snode *sn = NULL;
	struct csio_scsi_qset *sqset = NULL;
	struct csio_list *ptmp;
	uint32_t ep[5];
	unsigned long flags;
	enum fw_foiscsi_wr_subop subop = wr->subop;
	int rc = CSIO_SUCCESS, found = 0;

	csio_vdbg(hw, "tgt_id %d\n", csio_be32_to_cpu(wr->conn_iscsi.tgt_id));

	switch (wr->subop) {
	case FW_FOISCSI_WR_SUBOP_ADD:

		/* Get appropriate snode */
		csio_list_for_each(ptmp, &isnsm->snhead) {
			sn = (struct coiscsi_snode *)ptmp;
			if (sn->tgt_id == csio_be32_to_cpu(wr->conn_iscsi.tgt_id))
				found = 1;
			else
				sn = NULL;

			if(found)
				break;
		}

		if (!sn) {
			csio_tcp_dbg(hw, "Connection request for unknown target flowid %d\n", 
					csio_be32_to_cpu(wr->conn_iscsi.tgt_id));
			rc = CSIO_EINVAL;
			goto out;
		}

		/* 
		 * snode marked as REMOVING when iSNS listening server is stopped, 
		 * so do not accept any new connection when snode is in removing state
		 */
		if (test_bit(CSIO_SNF_REMOVING_INSTANCE, &sn->flags)) {
			csio_tcp_dbg(hw, "Connection request for stopped target\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		csio_tcp_dbg(hw, "conn SUBOP_ADD rcvd sn:%p, sn->listen_id:0x%x, wr->listen_id:0x%x, io_id:0x%x\n",
					sn, sn->tgt_id, csio_be32_to_cpu(wr->in_stid),
					G_FW_WR_FLOWID(csio_be32_to_cpu(wr->flowid_len16)));

		/* Get rnode */
		csio_spin_lock_irqsave(hw, &sn->sn_spinlock, flags);
		rns = csio_get_rns(hw, &sn->rnhead, G_FW_WR_FLOWID(csio_be32_to_cpu(wr->flowid_len16)));
		if (!rns) {
			csio_spin_unlock_irqrestore(hw, &sn->sn_spinlock, flags);
			rc = CSIO_ENOMEM;
			goto out;
		}

		rn = rns->rn;
		csio_rnode_to_snode(rn) = sn;

		sqset = &oshw->sqset[CSIO_SQS_CLNT_TRGT][smp_processor_id()];
		rn->eq_idx = sqset->eq_idx;
		rn->iq_idx = sqset->iq_idx;

		csio_tcp_dbg(hw, "flq_idx:%d, iq_idx:%d, iqid:%d\n",
			csio_q_iq_flq_idx(hw, rn->iq_idx),
			rn->iq_idx, csio_q_physiqid(hw, rn->iq_idx));

		csio_tcp_dbg(hw, "rns:%p, rn:%p, sn:%p, eq_idx:%u, iq_idx:%u\n",
			rns, rn, csio_rnode_to_snode(rn), rn->eq_idx, rn->iq_idx);

		rns->v_num[4] = csio_be16_to_cpu(wr->u.conn_tcp.in_dport);

		memset((uint8_t *)ep, 0, sizeof(ep));
		ep[4] = sn->lprt;
		if (sn->ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
			rns->v_num[2] = 0xffff0000;
			memcpy(&rns->v_num[3], &wr->u.conn_tcp.u.in_addr.daddr, sizeof(uint32_t));

			ep[2] = csio_be32_to_cpu(0x0000ffff);
			ep[3] = csio_be32_to_cpu(sn->lipv4);
		} else {
			memcpy(&rns->v_num[0], &wr->u.conn_tcp.u.in_addr6.daddr[0], sizeof(uint64_t));
			memcpy(&rns->v_num[2], &wr->u.conn_tcp.u.in_addr6.daddr[1], sizeof(uint64_t));

			memcpy((uint8_t *)ep, &sn->lipv6, sizeof(sn->lipv6));
		}

		if (chiscsi_handlers && chiscsi_handlers->accept_isns_conn) {
			rc = chiscsi_handlers->accept_isns_conn(rns, hw->os_dev, rn->flowid, ep);
			if(rc) {
				csio_err(hw, "accept_isns_conn failed %d\n", rc);
				subop = FW_FOISCSI_WR_SUBOP_DEL;
			}
		}

		/* Reply iSNS connection WR */
		wr->cookie = (u64)(uintptr_t)rns;
		csio_coiscsi_issue_tgt_conn_wr_reply(hw, rn, wr, subop);

		if(rc)
			csio_put_rns(rns);

		csio_spin_unlock_irqrestore(hw, &sn->sn_spinlock, flags);
		break;
	case FW_FOISCSI_WR_SUBOP_MOD:
		rns = (struct csio_rnode_isns *)wr->cookie;
		
		if (!rns) {
			csio_err(hw, "FATAL: Conn close WR:%p with null rns\n",wr);
			goto out;
		}
	
		rn = rns->rn;

		if (wr->status == FW_SCSI_IO_BLOCK) {

			csio_warn(hw, "conn SUBOP_MOD rcvd sts: FW_SCSI_IO_BLOCK rns:%p, conn:%p flags:0x%x\n",
					rns, rns->ch_conn, rn->flags);

			/* If connection is not in closign state initiate close */
			if (!(rn->flags & CSIO_RNF_CLOSING_CONN) &&
					chiscsi_handlers &&
					chiscsi_handlers->close_isns_conn) {
				rn->flags |= CSIO_RNF_CLOSING_CONN;
				csio_tcp_dbg(hw, "FW Initiated close  rn:%p rns:%p sn:%p\n",
					rns, rns->rn, rns->rn->snp);
				chiscsi_handlers->close_isns_conn(rns->ch_conn, 1);
			}
			/* Complete mod object */
			complete(&rns->mod_cmplobj.cmpl);
		} else {
			csio_tcp_dbg(hw, "SUBOP_MOD rcvd adjust wr rn:%p rns:%p sn:%p\n",
				rns, rns->rn, rns->rn->snp);
			complete(&rns->rn->snp->cmplobj.cmpl);
		}
		break;
	case FW_FOISCSI_WR_SUBOP_DEL:
		rns = (struct csio_rnode_isns *)wr->cookie;
		/* this is fatal */
		if (!rns) {
			csio_err(hw, "FATAL: Conn close WR:%p with null rns\n",wr);
			goto out;
		}

		rn = rns->rn;
		sn = csio_rnode_to_snode(rn);

		//DEBUG
		csio_warn(hw, "conn SUBOP_DEL rcvd "
				"sn:%p rns:%p rn:%p conn:%p flag:0x%x\n", 
				sn, rns, rn, rns->ch_conn, rn->flags);

		/* Complete del object */
		complete(&rns->del_cmplobj.cmpl);
		break;
	default:
		CSIO_DB_ASSERT(0);
	}
out:
	return rc;
}

int 
csio_conn_fwevt_handler(struct csio_hw *hw, struct fw_coiscsi_tgt_conn_wr *wr)
{
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct coiscsi_snode *sn = NULL;
	struct csio_list *tmp;
	int rc = CSIO_SUCCESS, tgt_found = 0, isns_found = 0;

#if defined(CSIO_DEBUG_BUFF) && defined(__CSIO_DEBUG__)
	csio_dump_wr_buffer((uint8_t *)wr, sizeof(struct fw_coiscsi_tgt_conn_wr));
#endif

	csio_vdbg(hw, "wr->conn_iscsi.tgt_id:0x%x, wr->in_stid:0x%x\n",
		csio_be32_to_cpu(wr->conn_iscsi.tgt_id), csio_be32_to_cpu(wr->in_stid));

	/* Look for flowid in the Target portals */
	if(!csio_list_empty(&tgtm->snhead)) {
		csio_list_for_each(tmp, &tgtm->snhead) {
			sn = (struct coiscsi_snode *)tmp;
			if (sn->tgt_id == csio_be32_to_cpu(wr->conn_iscsi.tgt_id))
				tgt_found =1;
			else
				sn = NULL;

			if (tgt_found)
				break;
		}
	} else {
		csio_vdbg(hw, "tgtm snhead list empty\n");
	}

	/* Look for flowid in the iSNS portals */
	if(isnsm->init_done && !csio_list_empty(&isnsm->snhead)) {
		csio_list_for_each(tmp, &isnsm->snhead) {
			sn = (struct coiscsi_snode *)tmp;
			if (sn->tgt_id == csio_be32_to_cpu(wr->conn_iscsi.tgt_id))
				isns_found =1;
			else
				sn = NULL;
	
			if (isns_found)
				break;
		}
	} else {
		csio_vdbg(hw, "isnsm snhead list empty\n");
	}

	csio_vdbg(hw, "tgt_found %d isns_found %d\n", tgt_found, isns_found);
	
	if(tgt_found)
		rc = csio_coiscsi_tgt_conn_fwevt_handler(hw, wr);
	else if(isns_found)
		rc = csio_isns_conn_fwevt_handler(hw, wr);
	else {
		csio_err(hw, "Connection request for unknown tgt_id 0x%x\n", 
				csio_be32_to_cpu(wr->conn_iscsi.tgt_id));
		hex_dump((u8 *)wr, sizeof(*wr));
		rc = CSIO_EINVAL;
	}

	return rc;
}

int 
csio_isns_client_fwevt_handler(struct csio_hw *hw, struct fw_isns_wr *wr)
{
	isns_data *data = (isns_data *)(uintptr_t)wr->cookie;
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	struct csio_rnode *rn = NULL;
	struct csio_rnode_isns *rns = NULL;
	uint32_t tid = 0;
	unsigned long flags;
	int rc = CSIO_SUCCESS;

	CSIO_ASSERT(data);

#ifdef __CSIO_DEBUG__
	csio_dump_wr_buffer((uint8_t *)wr, sizeof(struct fw_isns_wr));
#endif

	tid = csio_be32_to_cpu(wr->conn_attr.in_tid);
	data->flow_id = tid;
	csio_dbg(hw, "fw_isns_wr subop 0x%x tid 0x%x status %d\n", wr->subop, tid, wr->status);

#ifdef __CSIO_ISNS_CONN_MOD__
	if(wr->status != 0  && wr->subop != FW_FOISCSI_WR_SUBOP_MOD) {
#else
	if(wr->status != 0) {
#endif
		csio_dbg(hw, "fw_isns_wr failed status %d\n", wr->status);
		rc = CSIO_EINVAL;
		goto out;
	}

	switch(wr->subop) {
	case FW_FOISCSI_WR_SUBOP_ADD:

		if(tid) {
			csio_spin_lock_irqsave(hw, &isnsm->isns_spinlock, flags);
			rns = csio_get_rns(hw, &isnsm->rnhead, tid);
			if(!rns) {
				csio_err(hw, "%s: csio_get_rns failed\n",__func__);
				csio_spin_unlock_irqrestore(hw, &isnsm->isns_spinlock, flags);
				rc = CSIO_ENOMEM;
				goto out;
			}
			rn = rns->rn;
			rn->iq_idx = data->iq_idx;
			csio_dbg(hw, "rns %p rn %p\n", rns, rn);
 
			/* Copy iSNS server IP and Port details to rns->v_num */
			rns->v_num[4] = data->isns_info.port;
			if (data->isns_info.type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
				rns->v_num[2] = 0xffff0000;
				memcpy(&rns->v_num[3], data->isns_info.addr.ip6 + 12, sizeof(uint32_t));
			} else {
				memcpy(&rns->v_num[0], data->isns_info.addr.ip6, 16);
 			}

			if(chiscsi_handlers && chiscsi_handlers->accept_isns_conn) {
				rc = chiscsi_handlers->accept_isns_conn(rns, hw->os_dev, rn->flowid, NULL);
				if(rc) {
					csio_err(hw, "accept_isns_conn failed %d\n", rc);
					csio_put_rns(rns);
					rc = CSIO_ENOMEM;
					csio_spin_unlock_irqrestore(hw, &isnsm->isns_spinlock, flags);
					goto out;
				}
 			}
			csio_spin_unlock_irqrestore(hw, &isnsm->isns_spinlock, flags);
 		} else {
			csio_err(hw, "tid invalid %d\n", tid);
			rc = CSIO_EINVAL;
			goto out;
 		}

		break;
#ifdef __CSIO_ISNS_CONN_MOD__
	case FW_FOISCSI_WR_SUBOP_MOD:

		rn = csio_isns_rn_lookup(hw, &isnsm->rnhead, tid);
		if(!rn) {
			csio_err(hw, "rn with flowid 0x%x not found\n", tid);
			rc = CSIO_EINVAL;
			goto exit;
		}

		rns = csio_rnode_to_isns(rn);
		if(rns->ch_conn &&  !(rn->flags & CSIO_RNF_CLOSING_CONN) &&
			chiscsi_handlers && chiscsi_handlers->close_isns_conn) {
			rn->flags |= CSIO_RNF_CLOSING_CONN;
			if(chiscsi_handlers && chiscsi_handlers->close_isns_conn)
				chiscsi_handlers->close_isns_conn(rns->ch_conn, 0);
		} else {
			csio_err(hw, "rns ch_conn invalid %p\n", rns->ch_conn);
			rc = CSIO_EINVAL;
		}
		complete(&rns->mod_cmplobj.cmpl);
		goto exit;
		break;
#endif
	case FW_FOISCSI_WR_SUBOP_DEL:
#ifdef __CSIO_ISNS_CONN_MOD__
		rns = (struct csio_rnode_isns *)wr->cookie;
		/* this is fatal */
		if (!rns) {
			csio_err(hw, "FATAL: Conn close WR:%p with null rns\n",wr);
			goto out;
                }

		rn = rns->rn;
		csio_warn(hw, "conn SUBOP_DEL rcvd rns:%p rn:%p conn:%p flag:0x%x\n", 
			rns, rn, rns->ch_conn, rn->flags);

		/* Complete del object */
		complete(&rns->del_cmplobj.cmpl);
#else
		rn = csio_isns_rn_lookup(hw, &isnsm->rnhead, tid);
		if(!rn) {
			csio_err(hw, "rn with flowid 0x%x not found\n", tid);
			rc = CSIO_EINVAL;
			goto out;
		}

		rns = csio_rnode_to_isns(rn);
		if(rns->ch_conn &&  !(rn->flags & CSIO_RNF_CLOSING_CONN) &&
			chiscsi_handlers && chiscsi_handlers->close_isns_conn) {
			rn->flags |= CSIO_RNF_CLOSING_CONN;
			if(chiscsi_handlers && chiscsi_handlers->close_isns_conn)
                                chiscsi_handlers->close_isns_conn(rns->ch_conn, 0);
		} else {
			csio_err(hw, "rns ch_conn invalid %p\n", rns->ch_conn);
			rc = CSIO_EINVAL;
			goto out;
		}

#endif
		break;

	default:
		csio_err(hw, "%s: Invalid isns_wr opcode\n", __func__);
		break;  
	} 

out:
	data->status = rc;
	if(data->conn_wait_cmpl == 1)
		complete(data->conn_op_cmpl);
#ifdef __CSIO_ISNS_CONN_MOD__
exit:
#endif
 	return rc;
 }
