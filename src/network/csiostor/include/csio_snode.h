/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures,constants & enum definition for COiSCSI snodes
 *
 */
#ifndef	__CSIO_SNODE_H__
#define	__CSIO_SNODE_H__

#include <csio_defs.h>

#include <csio_lnode_foiscsi.h>

#define CSIO_SNF_REMOVING_INSTANCE 0


/* snode operation flags for worker thread */
#define COISCSI_SNODE_OPF_CLOSE 	0x1
#define COISCSI_SNODE_OPF_ASSIGN	0x2
#define COISCSI_SNODE_OPF_REMOVE	0x4

struct coiscsi_snode {
	struct csio_list		list;
	//struct csio_lnode_coiscsi	*lnc;
	
	struct csio_list		rnhead;
	struct csio_list		rn_backlog;
	uint32_t			n_reg_rnodes;

	struct csio_hw			*hwp;

	uint8_t				ip_type;
	uint16_t			redir;
	union {
		uint32_t			lipv4;
		uint8_t				lipv6[16];
	};

	uint32_t			tgt_id;
	
	uint16_t			lprt;
	uint16_t			tpgt;

	void				*ch_conn;
	csio_mutex_t			sn_mtx;
	csio_spinlock_t			sn_spinlock;
	csio_rwlock_t			sn_rwlock;
	uint32_t			op_pending;
	csio_cmpl_t			cmplobj;
	csio_timer_t			sn_timer;
	csio_work_t			sn_work;
	unsigned long			flags;
	uint8_t				rnc_passive;
	uint8_t				tcp_wscale;
	uint8_t				tcp_wsen;
	int32_t				ref_cnt;
	uint32_t			wr_status;
	uint32_t			op_flag;
	void				*iface;
	/* context info for target assign */
	void 				*tinfo;
	void				*handle;
	void				*hw;
	void 				*lncoi;
	void 				*tportal;
};

struct coiscsi_snode *coiscsi_snode_alloc(struct csio_coiscsi_tgtm *);
void coiscsi_snode_free(struct coiscsi_snode *);

#endif	/* __CSIO_SNODE_H__ */
