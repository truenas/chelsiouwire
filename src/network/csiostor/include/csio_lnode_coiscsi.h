/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures,constants & function prototype declaration for
 * COiSCSI target lnodes
 *
 */
#ifndef	__CSIO_LNODE_COISCSI_H__
#define	__CSIO_LNODE_COISCSI_H__

#include <csio_defs.h>
#include <csio_hw.h>
/*#include <csio_mb_coiscsi.h>*/
#include <csio_coiscsi_ioctl.h>

#define COISCSI_INVALID_TGT_ID	0x00FFFFFF

struct coiscsi_portal {
	struct csio_list	list;
	struct coiscsi_snode	*snode;
	struct coiscsi_trgt_conn_attr conn_attr;
	uint32_t 		init_done;
	uint32_t		do_cmpl;
	struct csio_chnet_iface *iface;
};

struct csio_lnode_coiscsi {
	struct csio_sm			sm;
	struct csio_lnode		*ln;
	
	struct csio_list		ssnhead;
	//struct csio_list		snhead;	

	uint32_t 			op_pending;
	void 				*transport_handle;

	struct csio_list		portal_head;
	uint32_t			portal_cnt;
	uint32_t			node_init_done;
	
	/* target_inst comes in with a vla at the end.
	 * csio_coiscsi_alloc_lnode cannot account for this,
	 * and lncoi is embedded in the middle of the lnode, so
	 * we use this extra pointer */
	void				*lun_list;

	struct coiscsi_target_inst	tinst;
	struct coiscsi_target_disc	disc_auth;
	csio_mutex_t            	lnc_mtx;
};

enum coiscsi_target_op_state {
	COISCSI_LNODE_INIT, 
	COISCSI_PORTAL_INIT,
	COISCSI_SNODE_INIT,
	COISCSI_CH_INIT,
	COISCSI_OP_MAX
};

struct csio_os_lnode *csio_coiscsi_alloc_lnode(struct csio_coiscsi_tgtm *);
void csio_coiscsi_free_lnode(struct csio_os_lnode *);
void csio_coiscsi_free_lnode_coiscsi(struct csio_lnode_coiscsi *);
int csio_chiscsi_stop_node(struct coiscsi_target_inst *sn);
//void csio_coiscsi_oslnode_exit(struct csio_lnode *);

int csio_coiscsi_assign_target_instance(struct csio_hw *,
		struct coiscsi_target_ioctl *, void *, int);
int csio_coiscsi_remove_target_instance(struct csio_hw *hw, struct coiscsi_target_ioctl *tinfo, void *handle);
int csio_coiscsi_show_target_instance(struct csio_hw *hw, struct coiscsi_target_ioctl *tinfo, void *handle);
int csio_coiscsi_get_target_info(struct csio_hw *hw, struct coiscsi_target_info_ioctl *tinfo, void *handle);
int csio_coiscsi_get_target_stats(struct csio_hw *hw, struct coiscsi_target_stats_ioctl *tinfo, uint32_t op, void *handle);
int csio_coiscsi_update_target_instance(struct csio_hw *hw, struct coiscsi_target_ioctl *tinfo, void *handle);

int csio_coiscsi_issue_tgt_conn_wr_reply(struct csio_hw *hw,
		struct csio_rnode *rn, struct fw_coiscsi_tgt_conn_wr *,
		enum fw_foiscsi_wr_subop);

struct coiscsi_portal *coiscsi_portal_alloc(struct csio_lnode_coiscsi *);
void coiscsi_portal_free(struct csio_lnode_coiscsi *, struct coiscsi_portal *);
void coiscsi_snode_get_ref(struct coiscsi_snode *);
int coiscsi_snode_put_ref(struct coiscsi_snode *);

#endif	/* __CSIO_LNODE_COISCSI_H__ */
