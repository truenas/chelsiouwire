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
#ifndef __CHTCP_UMAIN_H__
#define __CHTCP_UMAIN_H__

#include <string.h>
#include <errno.h>

#include <rte_io.h>

#include "spdk/sock.h"
#include "spdk_internal/sock.h"
#include "spdk/log.h"
#include "spdk_internal/thread.h"

#include "t4_hw.h"
#include "t4_chip_type.h"
#include "chtcp_ioctl.h"
#include "chtcp_ucompat.h"
#include "chtcp_usge.h"

TAILQ_HEAD(chtcp_listen_list, chtcp_listen_sock);
TAILQ_HEAD(chtcp_sock_list, chtcp_sock);

#define CHTCP_GET_CH_REACTOR(reactor) ((struct chtcp_reactor *)reactor->priv_data)
#define CHTCP_PRIV_TO_MBUF(priv) RTE_PTR_SUB(priv, sizeof(struct rte_mbuf))
#define CHTCP_MBUF_TO_PRIV(mbuf) ((struct chtcp_mbuf_private *)RTE_PTR_ADD(mbuf, sizeof(struct rte_mbuf)))

struct serv_entry {
	void *data;
};

struct tid_info {
	void **tid_tab;
	u32 tid_base;
	u32 ntids;

	struct serv_entry *stid_tab;
	u32 nstids;
	u32 stid_base;

	/* TIDs in the TCAM */
	rte_atomic32_t tids_in_use;
	rte_atomic32_t conns_in_use;
};

struct chtcp_uadapter {
	struct chtcp_sge sge;
	void __iomem *bar2;
	enum chip_type adapter_type;
	u64 bar2_length;
	u8 pci_devname[CHTCP_PCI_DEVNAME_LEN];
	u8 pf;
	u8 nports;
	u8 wr_cred;
	u8 adap_idx;
	int dev_fd;
	u32 sge_fl_db;
	u16 mtus[NMTUS];
	rte_atomic32_t server_count;
	struct chtcp_sge_ofld_txq *txq;
	struct chtcp_sge_ofld_rxq *rxq;
	struct tid_info tids;
	struct chtcp_listen_list lcsk_list; /* listen sock list */
	rte_spinlock_t lcsk_lock;           /* listen sock list lock */
};

struct chtcp_reactor {
	struct chtcp_sock_list acsk_req_list; /* accept sock req list */
};

struct chtcp_root {
	struct chtcp_uadapter *adapter[CHTCP_MAX_ADAPTER_NUM];
	struct spdk_reactor *reactors[RTE_MAX_LCORE];
	struct rte_mempool **fl_mbuf_pool;
	struct rte_mempool **tx_mbuf_pool;
	struct spdk_poller **poller;
	rte_atomic32_t poller_count;
	u32 nreactors;
	u16 num_adapter;
};

struct chtcp_listen_sock {
	struct spdk_sock base;
	struct chtcp_uadapter *adap;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	struct chtcp_sge_ofld_txq *txq;
	struct rte_mempool *tx_mbuf_pool;
	struct spdk_poller *cleanup_poller;
	enum chtcp_lcsk_state state;
	rte_atomic32_t conn_count;
	struct spdk_nvmf_tcp_port *port;
	rte_spinlock_t acsk_lock;          /* accept sock list lock */
	struct chtcp_sock_list acsk_list;  /* accept sock list in listen sock*/
	TAILQ_ENTRY(chtcp_listen_sock) lcsk_link;     /* link used for listen sock */
	u32 stid;
	u16 port_id;
	u8 is_ipv4;
};

enum chtcp_csk_state {
	CHTCP_CSK_STATE_IDLE = 0,
	CHTCP_CSK_STATE_LISTEN,
	CHTCP_CSK_STATE_CONNECTING,
	CHTCP_CSK_STATE_ESTABLISHED,
	CHTCP_CSK_STATE_ABORTING,
	CHTCP_CSK_STATE_CLOSING,
	CHTCP_CSK_STATE_MORIBUND,
	CHTCP_CSK_STATE_DEAD,
};

enum CHTCP_CSK_FLAGS {
	CHTCP_CSK_FLAG_NO_WR_CREDIT	= 1U << 0,
	CHTCP_CSK_FLAG_APP_CLOSE	= 1U << 1,
	CHTCP_CSK_FLAG_FLOWC_SENT	= 1U << 2,
	CHTCP_CSK_FLAG_FORCE_FLUSH	= 1U << 3,
};

struct chtcp_sock {
	struct spdk_sock base;
	struct chtcp_uadapter *adap;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	struct chtcp_sge_ofld_txq *txq;
	struct rte_mempool *tx_mbuf_pool;
	struct spdk_nvmf_poll_group *pg;
	struct chtcp_sock_group_impl *group_impl;
	struct chtcp_mbuf_q recvq;
	struct chtcp_mbuf_q sendq;
	struct chtcp_mbuf_q res_mbufq;
	struct chtcp_mbuf_q wr_ack_mbufq;
	enum chtcp_csk_state state;
	TAILQ_ENTRY(chtcp_sock) acsk_link;     /* link used for accept sock */
	u32 tid;
	u32 stid;
	u32 tx_chan;
	u32 snd_una;
	u32 snd_win;
	u32 rcv_win;
	u32 snd_nxt;
	u32 rcv_nxt;
	u32 flags;
	u32 write_seq;
	u16 rss_qid;
	u16 emss;
	u16 mss;
	u16 port_id;
	u8 wr_cred;
	u8 wr_max_cred;
	u8 wr_una_cred;
	u8 snd_wscale;
};

struct chtcp_sock_group_impl {
	struct spdk_sock_group_impl base;
	struct spdk_sock *next_sock;
};

enum chtcp_mbuf_flags {
	CHTCP_MBUF_FLAG_TX_DATA		= 1U << 0,  /* packet needs a TX_DATA_WR header */
	CHTCP_MBUF_FLAG_IMM_DATA	= 1U << 1,  /* set for immediate data */
	CHTCP_MBUF_FLAG_DISCONNECT	= 1U << 2,  /* set for close conn */
	CHTCP_MBUF_FLAG_COMPLETION	= 1U << 3,  /* set for close conn */
};

struct chtcp_mbuf_private {
	TAILQ_ENTRY(chtcp_mbuf_private) link;  /* to add in recvq/sendq/mbufq */
	TAILQ_ENTRY(chtcp_mbuf_private) ack_link; /* to add in wr_ack_mbufq */
	struct spdk_nvmf_poll_group *pg;
	u32 tid;
	u32 credits;
	u32 flags;
	u32 pkt_len;
	u32 nmbuf;	/* total mbufs attached */
	u32 nflits;     /* total 8 bytes flits required */
};

#define CHTCP_QUEUE_MBUF(q, mbuf, link)		\
do {						\
	struct chtcp_mbuf_private *priv;	\
	priv = CHTCP_MBUF_TO_PRIV(mbuf);	\
	TAILQ_INSERT_TAIL(q, priv, link);	\
} while (0)

#define CHTCP_DEQUEUE_MBUF(q, mbuf, link)	\
do {						\
	struct chtcp_mbuf_private *priv;	\
	priv = CHTCP_MBUF_TO_PRIV(mbuf);	\
	TAILQ_REMOVE(q, priv, link);		\
} while (0)

#define CHTCP_PURGE_MBUF_Q(q, link) 			\
do { 							\
	struct chtcp_mbuf_private *priv_data; 		\
	struct chtcp_mbuf_private *tpriv; 		\
	struct rte_mbuf *mbuf;				\
	TAILQ_FOREACH_SAFE(priv_data, q, link, tpriv){ 	\
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data); 	\
		TAILQ_REMOVE(q, priv_data, link); 	\
		rte_pktmbuf_free(mbuf);			\
	} 						\
} while (0)

#define CHTCP_MBUF_Q_FIRST(q) CHTCP_PRIV_TO_MBUF(TAILQ_FIRST(q));

static inline bool 
chtcp_test_mbuf_flag(const struct rte_mbuf *mbuf, u32 flag)
{
	struct chtcp_mbuf_private *priv_data;

	priv_data = CHTCP_MBUF_TO_PRIV(mbuf);

	if (priv_data->flags & flag)
		return true;
	else
		return false;
}

static inline void 
chtcp_set_mbuf_flag(struct rte_mbuf *mbuf, u32 flag)
{
	struct chtcp_mbuf_private *priv_data;

	priv_data = CHTCP_MBUF_TO_PRIV(mbuf);

	priv_data->flags |= flag;
}

static inline struct rte_mbuf *
chtcp_alloc_tx_mbuf(struct chtcp_sock *csk)
{
	struct rte_mbuf *mbuf;
	struct chtcp_mbuf_private *priv_data;

	mbuf = rte_pktmbuf_alloc(csk->tx_mbuf_pool);
	if (!mbuf) {
		SPDK_DEBUGLOG(chtcp, "%s core[%d]: mbuf alloc failed\n",
			      csk->adap->pci_devname, rte_lcore_id());
		return NULL;
	}

	rte_mbuf_refcnt_set(mbuf, 1);
	priv_data = CHTCP_MBUF_TO_PRIV(mbuf);
	memset(priv_data, 0, sizeof(struct chtcp_mbuf_private));

	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->data_len = mbuf->buf_len - mbuf->data_off;
	mbuf->pkt_len = mbuf->data_len;

	return mbuf;
}

/* alloc mbuf from reserved mbuf q */
static inline struct rte_mbuf *
chtcp_alloc_mbuf_res(struct chtcp_sock *csk, u32 len)
{
	struct chtcp_mbuf_private *priv_data;
	struct rte_mbuf *mbuf;

	priv_data = TAILQ_FIRST(&csk->res_mbufq);

	mbuf = CHTCP_PRIV_TO_MBUF(priv_data);
	if (!mbuf) {
		SPDK_ERRLOG("%s core[%d]: mbuf alloc failed from mbufq\n",
			csk->adap->pci_devname, rte_lcore_id());
		return NULL;
	}

	TAILQ_REMOVE(&csk->res_mbufq, priv_data, link);

	mbuf->data_len = len;
	mbuf->pkt_len = mbuf->data_len;
	
	return mbuf;
}

struct chtcp_sge_ofld_txq *
chtcp_get_txq(struct chtcp_uadapter *adap, u32 port_id, u32 reactor_id);
struct chtcp_sge_ofld_rxq *
chtcp_get_rxq(struct chtcp_uadapter *adap, u32 port_id, u32 reactor_id);

static inline void 
chtcp_insert_tid(struct tid_info *t, void *data,
		 u32 tid, u16 family)
{
	t->tid_tab[tid - t->tid_base] = data;

	if (family == AF_INET6)
		rte_atomic32_add(&t->tids_in_use, 2);
	else
		rte_atomic32_inc(&t->tids_in_use);

	rte_atomic32_inc(&t->conns_in_use);
}

static inline void *
chtcp_lookup_tid(const struct tid_info *t, u32 tid)
{
	return (tid - t->tid_base) < t->ntids ?
		t->tid_tab[tid - t->tid_base] : NULL;
}

static inline u32 
tid_out_of_range(const struct tid_info *t, u32 tid)
{
	return (tid >= (t->tid_base + t->ntids));
}

void
chtcp_remove_tid(struct tid_info *t, u32 chan, u32 tid, u16 family);
void chtcp_handle_poller_register(void *arg1, void *arg2);
void chtcp_handle_poller_unregister(void *arg1, void *arg2);
int chtcp_cleanup_conn(void *ctx);

#endif /* __CHTCP_UMAIN_H__ */
