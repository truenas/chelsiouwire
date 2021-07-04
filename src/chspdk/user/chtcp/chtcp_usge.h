/*
 * Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2 or the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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
#ifndef __CHTCP_USGE_H__
#define __CHTCP_USGE_H__

#include <string.h>
#include <errno.h>

#include <rte_io.h>

#include "spdk/sock.h"
#include "spdk_internal/sock.h"
#include "spdk/log.h"

#include "t4_hw.h"
#include "t4_chip_type.h"

#include "chtcp_ucompat.h"
#include "chtcp_umain.h"

TAILQ_HEAD(chtcp_mbuf_q, chtcp_mbuf_private);
struct chtcp_sock;
struct tid_info;

struct tx_desc {
	__be64 flit[8];
};

struct tx_sw_desc {                /* SW state per Tx descriptor */
	struct rte_mbuf *mbuf;
	struct ulptx_sgl *sgl;
};

struct chtcp_sge_txq {
	const struct rte_memzone *mz;     /* hardware desc memzone */
	struct tx_desc *desc;       /* address of HW Tx descriptor ring */
	struct tx_sw_desc *sdesc;   /* address of SW Tx descriptor ring */
	struct sge_qstat *stat;     /* queue status entry */

	u64 phys_addr;         /* physical address of the ring */

	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	u32 bar2_qid;      /* Queue ID for BAR2 Queue registers */

	u32 cntxt_id;     /* SGE relative QID for the Tx Q */
	u32 in_use;       /* # of in-use Tx descriptors */
	u32 size;         /* # of descriptors, fill before alloc */
	u32 cidx;         /* SW consumer index */
	u32 pidx;         /* producer index */
	u32 dbidx;	   /* last idx when db ring was done */
	u32 equeidx;	   /* last sent credit request */
	u32 last_pidx;	   /* last pidx recorded by tx monitor */
	u32 last_coal_idx;/* last coal-idx recorded by tx monitor */
	u32 abs_id;
	u8 port_id;      /* adapter port id, fill before alloc */
};

struct chtcp_sge_ofld_txq {
	struct chtcp_sge_txq q;
	struct chtcp_mbuf_q sendq;        /* list of packets needed to send to chtcp_sge_txq*/
	struct chtcp_uadapter *adap;
	u32 reactor_id;                    /* reactor id, fill before alloc */
};

struct chtcp_sge_rspq {                   /* state for an SGE response queue */
	const struct rte_memzone *mz;       /* hardware desc memzone */
	struct rte_mempool  *mb_pool; /* associated mempool */

	dma_addr_t phys_addr;       /* physical address of the ring */
	__be64 *desc;               /* address of HW response ring */
	const __be64 *cur_desc;     /* current descriptor in queue */

	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	u32 bar2_qid;      /* Queue ID for BAR2 Queue registers */
	struct sge_qstat *stat;

	u32 cidx;          /* consumer index */
	u32 gts_idx;	    /* last gts write sent */
	u32 iqe_len;       /* entry size, fill before alloc */
	u32 size;          /* capacity of response queue */

	u8 intr_params;             /* interrupt holdoff parameters */
	u8 next_intr_params;        /* holdoff params for next interrupt */
	u8 pktcnt_idx;              /* interrupt packet threshold */
	u8 port_id;		    /* associated port-id, fill before alloc  */
	u8 idx;                     /* queue index within its group */
	u16 cntxt_id;               /* SGE relative QID for the response Q */
	u16 abs_id;                 /* absolute SGE id for the response q */
};

struct rx_sw_desc {                /* SW state per Rx descriptor */
	void *buf;                 /* struct page or mbuf */
	dma_addr_t dma_addr;
};

struct chtcp_sge_fl {                     /* SGE free-buffer queue state */
	const struct rte_memzone *mz;     /* hardware desc memzone */ 
	struct rx_sw_desc *sdesc;   /* address of SW Rx descriptor ring */

	dma_addr_t addr;            /* bus address of HW ring start */
	__be64 *desc;               /* address of HW Rx descriptor ring */

	void __iomem *bar2_addr;    /* address of BAR2 Queue registers */
	u32 bar2_qid;      /* Queue ID for BAR2 Queue registers */

	u32 cntxt_id;      /* SGE relative QID for the free list */
	u32 size;          /* capacity of free list, fill before alloc */

	u32 avail;         /* # of available Rx buffers */
	u32 pend_cred;     /* new buffers since last FL DB ring */
	u32 cidx;          /* consumer index */
	u32 pidx;          /* producer index */

	u64 alloc_failed; /* # of times buffer allocation failed */
	u64 low;          /* # of times momentarily starving */
};

struct chtcp_sge_ofld_rxq {               /* a SW offload Rx queue */
	struct chtcp_sge_rspq rspq;
	struct chtcp_sge_fl fl;
	struct chtcp_uadapter *adap;
	u32 reactor_id;                    /* reactor id, fill before alloc */ 
};

struct chtcp_sge {
	u32 stat_len;        /* Length of status page at the end of ring */
	u32 fl_starve_thres; /* Free list starvation threshold */
	u32 fl_align;        /* Response queue message alignment */
	u32 pktshift;        /* Paddign between CPL and packet data */
	u32 fl_buf_size;     /* FL buffer size */
	u8 fl_buf_idx;	     /* FL buffer index */
};

int chtcp_usge_alloc_ofld_txq(struct chtcp_uadapter *adap,
			       struct chtcp_sge_ofld_txq *txq);

int chtcp_usge_alloc_ofld_rxq(struct chtcp_uadapter *adap,
			       struct rte_mempool *mp,
			       struct chtcp_sge_ofld_rxq *txq);

int chtcp_queue_tx_mbuf(struct chtcp_sock *csk, struct rte_mbuf *mbuf);
void chtcp_process_csk_sendq(struct chtcp_sock *csk);
void chtcp_service_ofld_txq(struct chtcp_sge_ofld_txq *txq);
void
chtcp_ofld_queue_xmit(struct chtcp_sge_ofld_txq *txq, struct rte_mbuf *mbuf);
void chtcp_usge_ofld_txq_release(struct chtcp_uadapter *adap,
				  struct chtcp_sge_ofld_txq *txq);
void chtcp_usge_ofld_rxq_release(struct chtcp_uadapter *adap,
				  struct chtcp_sge_ofld_rxq *rxq);
int chtcp_poller_cb(void *ctx);

#endif /* __CHTCP_USGE_H__ */
