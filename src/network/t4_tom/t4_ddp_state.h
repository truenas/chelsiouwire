/*
 * Definitions for TCP DDP state management.
 *
 * Copyright (C) 2006-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef T4_DDP_STATE_H
#define T4_DDP_STATE_H

/* Should be 1 or 2 indicating single or double kernel buffers. */
#define NUM_DDP_KBUF 2

/* min receive window for a connection to be considered for DDP */
#define MIN_DDP_RCV_WIN (48 << 10)

/* amount of Rx window not available to DDP to avoid window exhaustion */
#define DDP_RSVD_WIN (16 << 10)

/* page pods are allocated in groups of this size (must be power of 2) */
#define PPOD_CLUSTER_SIZE 16U

#define PPOD_SIZE sizeof(struct pagepod)

/* ULPTX has a max DSGL payload of 1KB which matches 16 pagepods */
#define NUM_ULP_TX_SC_DSGL_PPODS PPOD_CLUSTER_SIZE
#define ULP_TX_MEMWRITE_ALIGN 5

struct page;
struct pci_dev;

/* DDP gather lists can specify an offset only for the first page. */
struct ddp_gather_list {
	unsigned int length;
	unsigned int offset;
	unsigned int nelem;
	unsigned int type;
        unsigned int nppods;
        unsigned int tag;
	unsigned int color;
	struct sg_table sgt;
	struct page **pages;
	dma_addr_t phys_addr[0];
};

struct dsgl_req {
	void *dsgl_vaddr;
	dma_addr_t dsgl_iova;
};

struct ddp_buf_state {
	unsigned int cur_offset;     /* offset of latest DDP notification */
	unsigned int flags;
	struct ddp_gather_list *gl;
};

struct ddp_state {
	struct pci_dev *pdev;
	struct ddp_buf_state buf_state[2];   /* per buffer state */
	unsigned int ddp_setup;
	unsigned int state;
	int cur_buf;
	unsigned int ubuf_nppods;
	unsigned int ubuf_tag;
	struct ddp_gather_list *ubuf[2];
	int cur_ubuf;
	int get_tcb_count;
	int indout_count;
	unsigned int ddp_off;
	unsigned int indicate;
	unsigned int ind_rcv_nxt;
	unsigned int ind_size;
	unsigned int ubuf_ddp_pending;
	unsigned int ddp_tag;
	unsigned int ddp_color;
	unsigned int avg_request_len;
	int cancel_ubuf;
	int post_failed;
};

enum {
	DDP_TYPE_USER = 1 << 0,
	DDP_TYPE_KERNEL =  1 << 1,
	DDP_TYPE_DSGL = 1 << 2,
};

enum {
	DDP_ENABLED = 1 << 0,
};

/* buf_state flags */
enum {
	DDP_BF_NOINVAL = 1 << 0,   /* buffer is set to NO_INVALIDATE */
	DDP_BF_NOCOPY  = 1 << 1,   /* DDP to final dest, no copy needed */
	DDP_BF_NOFLIP  = 1 << 2,   /* buffer flips after GET_TCB_RPL */
	DDP_BF_PSH     = 1 << 3,   /* set in skb->flags if the a DDP was 
	                              completed with a segment having the
				      PSH flag set */
	DDP_BF_NODATA  = 1 << 4,   /* buffer completed before filling */ 
};

#endif  /* T4_DDP_STATE_H */
