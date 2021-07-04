/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 * 
 * Description: Data structures, constants and function prototype declarations
 * for COiSCSI I/O operations.
 * 
 */

#ifndef	__CSIO_COISCSI_TGT_H__
#define __CSIO_COISCSI_TGT_H__

#include <csio_defs.h>
#include <csio_wr.h>
#include <csio_ctrl_coiscsi.h>
/*#include <csio_chiscsi_tgt_api.h>*/

#define CSIO_COISCSI_TGT_OFLDQ_SZ		4096
#define COISCSI_TGT_MAX_SGE			32


#define CSIO_COISCSI_TGT_Q_NUMS	((CSIO_MAX_SCSI_QSETS * 4) +\
		CSIO_HW_NEQ + CSIO_HW_NIQ +\
		CSIO_HW_NFLQ + CSIO_HW_NINTXQ)

#define CSIO_COISCSI_TGT_FLLEN	128

struct csio_rnode_coiscsi;

struct coiscsi_dbuf {
	struct csio_list	list;
	void			*addr;
	void			*raddr;
	csio_dma_obj_t		dmahdl;
	uint32_t		len;
	uint32_t		rlen;
};

struct	data_sgl {
	unsigned long long addr;
	uint32_t	len;
	uint32_t	offset;
};

struct csio_coiscsi_rcvreq {
	struct csio_list	list;
	struct csio_list	bufhead;
	struct csio_hw		*hw;
	struct csio_rnode	*rnode;
	uint32_t		n_buf_cnt;
	uint16_t		plen;
	uint8_t			ddp_cmp;
	uint8_t			r1;
	uint32_t		status;
	void                    *cookie;
};

struct csio_coiscsi_tgtreq {
	struct csio_sm          sm;
	struct csio_list	rlist;
	struct csio_list	tlist;
	uint8_t			state;		/* State of the request */
	uint8_t			op;		/* Tgtreq operation */
	struct csio_hw		*hw;		/* Owning hw */
	int			iq_idx;		/* Ingress queue index */
	int			eq_idx;		/* Egress queue index */
	uint32_t		ssn_flowid;	/* Session flow id */
	uint32_t		req_flowid;	/* flow id of the I/O */
	struct csio_dma_buf	dma_buf;	/* Req/resp DMA buffers */
	uint16_t		wr_status;	/* WR completion status */
	uint16_t		drv_status;	/* Driver internal status */
	struct csio_lnode	*lnode;		/* Owner lnode */
	struct csio_rnode	*rnode;		/* Src/destination rnode */
	uint32_t		req_len;	/* Requested data len */
	uint32_t		xfrd_len;	/* Transferred data len */
	void			*scratch1;	/* Scratch area 1. */
	void			*scratch2;	/* Scratch area 2. */
	struct csio_sgel 	*cur_sgel;	/* Current SG element (in
						 * case of chained request
						 */
	uint32_t		chain_idx;	/* Current WR index (in case
						 * of chained request)
						 */
	struct csio_list	unreg_list;	/* Used during session unreg
						 * cleanup.
						 */
	csio_spinlock_t		lock;		/* per request lock */
	uint32_t		tmo;		/* Driver timeout. */
	void 			*wr_priv; 	/* wr request priv data*/
	uint32_t		pdu_ndsn;	/* next pdu's dsn */
	uint32_t		def_treq;	/* is this a default treq*/
	uint32_t		treq_wait;	/* set to 1 if waiting for cmpl*/
	uint32_t		nosched;	/* don't schedule connection */
	uint32_t		flags;		/* Flags (defined above) */
	void			*rnc;		/* connection rnc for default treq */
	void			*sc_cmd;	/* owning scsi cmd */
	void			*conn;		/* xmit connection */
	uint32_t		wait_cmpl;	/* caller is waiting for completion */
	csio_cmpl_t		cmpl_obj;	/* completion object */

	struct {
		uint8_t			bhs[48];
		uint8_t			hdigest_en;
		uint8_t			ddigest_en;
		uint8_t			final_req;
		uint8_t			cmpl_req;
		uint8_t			imm_len;
		uint8_t			r2t_ddp;
		uint8_t			ddp_skip;
		void			*pad;
		uint32_t		sg_cnt;
		uint32_t		padlen;
		uint32_t		totallen;
		uint32_t		doffset;
		struct	data_sgl	sgl[32];
	} tx_data;
};

struct csio_coiscsi_tgtm_stats {
	uint64_t		n_good_cmpl;	/* Total number of good 
						 * completions 
						 */
	uint16_t		n_active;	/* Count of active I/Os */
	uint16_t		n_max_active;	/* Max outstanding I/O count at
						 * any point.
						 */
	uint16_t		n_draining;	/* Count of I/Os in drain q */
	
	uint16_t		n_drop_no_reqs;	/* Number of I/Os dropped owing
						 * to running out of tgtreqs 
						 */
	uint16_t		n_err_link_down;/* Number of link down errors */

	uint16_t		n_lns;		/* Number of lnoded attached */

	uint32_t		n_free_tgtreq;	/* Count of tgtreq entries */

	uint32_t		n_abrtd_driver;
	uint32_t		n_abrtd_fw;

	uint32_t		n_free_dbuf;
	uint32_t		n_free_rcvreq;

	uint32_t		n_ddp_miss;
	uint64_t		n_ddp_pass;
	uint32_t		n_ddp_skip;
	uint64_t		n_poff_cnt;

	uint32_t		n_invalid_cplop;

#define COISCSI_IPV4_SNODE_MAX	12
#define COISCSI_IPV6_SNODE_MAX	4
	uint16_t		n_ipv4_sn_cnt;	/* ipv4 snode/listen conn count */
	uint16_t		n_ipv6_sn_cnt;	/* ipv6 snode/listen conn count */
	uint32_t		tcredit_avail;  /* tgtreq credits available */
	uint32_t		tcredit_req_cnt; /* no of conns/credits requested */
	uint32_t		tcredit_req_max; /* max no of request possible */
};

struct csio_coiscsi_tgtm {
	struct csio_hw		*hw;		/* Pointer to HW moduel */
	uint8_t			proto_cmd_len;  /* Proto specific SCSI
						 * cmd length
						 */
	uint16_t		proto_rsp_len;	/* Proto specific SCSI
						 * response length
						 */
	/* Children */
	struct csio_lnode 	*rln; 		/* Root lnode */
	struct csio_list	sln_head;	/* Sibling lnode list */

	struct csio_list	snhead;		/* snode head */
		
	uint8_t                 max_sge;	/* Max SGE */
	struct csio_list	rcvreq_flist;
	csio_spinlock_t		rcvreq_flist_lck;
	struct csio_list	dbuf_flist;
	csio_spinlock_t		dbuf_flist_lck;
	struct csio_list	tgtreq_freelist;/* Free list of tgtreq's */
	csio_spinlock_t		freelist_lock;  /* Lock for tgtreq freelist */
	csio_spinlock_t		tcredit_lock;	/* lock for tgtreq credits */
	csio_mutex_t		ioctl_lock;     /* serialize ioctls */
	uint32_t		ioctl_pending;

	struct csio_list	drain_q;	/* Drain queue */
	csio_work_t		unreg_cleanup_work;	
						/* Worker thread for cleaning up
						 * I/Os from unregistered 
						 * sessions. */
	struct csio_list	unreg_cleanup_q;/* Queue used by this worker */
	struct csio_coiscsi_tgtm_stats	stats;
	csio_cmpl_t		cmplobj;
};


enum csio_coiscsi_tgtreq_state {
	CSIO_COISCSI_TGTREQ_STATE_UNINIT = 1,
	CSIO_COISCSI_TGTREQ_STATE_INUSE,
	CSIO_COISCSI_TGTREQ_STATE_FREE,

};

static inline void
csio_coiscsi_tgtreq_set_state(struct csio_coiscsi_tgtreq *tgtreq,
		enum csio_coiscsi_tgtreq_state state)
{
	tgtreq->state = state;
}

static inline enum csio_coiscsi_tgtreq_state
csio_coiscsi_tgtrq_get_state(struct csio_coiscsi_tgtreq *tgtreq)
{
	return tgtreq->state;
}

static inline int
csio_coiscsi_tgtreq_is_state(struct csio_coiscsi_tgtreq *tgtreq,
		enum csio_coiscsi_tgtreq_state state)
{
	return tgtreq->state == state;
}

extern void coiscsi_init_cmpl_tgtreq(struct csio_coiscsi_tgtreq *);
extern void coiscsi_wait_cmpl_tgtreq(struct csio_coiscsi_tgtreq *);
extern void coiscsi_lock_tgtreq(struct csio_coiscsi_tgtreq *);
extern void coiscsi_unlock_tgtreq(struct csio_coiscsi_tgtreq *);
extern void coiscsi_done_tgtreq(struct csio_coiscsi_tgtreq *);
extern void coiscsi_put_tgtreq(struct csio_coiscsi_tgtreq *);
extern struct csio_coiscsi_tgtreq *coiscsi_get_tgtreq(struct csio_rnode_coiscsi *, void *);
extern void csio_coiscsi_put_rcvreq(struct csio_coiscsi_rcvreq *);
extern int coiscsi_put_treq_credit(struct csio_rnode_coiscsi *, uint32_t);
extern int coiscsi_get_treq_credit(struct csio_rnode_coiscsi *);

csio_retval_t
csio_coiscsi_tgtm_init(struct csio_coiscsi_tgtm *, struct csio_hw *);
void csio_coiscsi_tgtm_exit(struct csio_coiscsi_tgtm *);
int csio_coiscsi_tgt_isr(struct csio_hw *, void *, uint32_t,
		struct csio_fl_dma_buf *, void *);

extern int32_t coiscsi_xmit_data(struct csio_coiscsi_tgtreq *);
extern int32_t coiscsi_abort_req(struct csio_coiscsi_tgtreq *);

#endif	/* __CSIO_COISCSI_TGT_H__ */

