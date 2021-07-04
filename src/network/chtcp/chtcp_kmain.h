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
#ifndef __CHTCP_K_H__
#define __CHTCP_K_H__

#include "chtcp_ioctl.h"

#define	CHTCP_PCI_BAR_NUM	(2)

struct chtcp_kadapter {
	struct list_head list_node;
	struct cxgb4_lld_info lldi;
	struct adapter *adap;
	struct device *pdev;
	struct cdev chtcp_cdev;
	dev_t devno;
	u8 nports;
	bool file_in_use;
	struct mutex adap_lock;
	struct list_head lcsk_list;
	struct mutex lcsk_lock;
	struct list_head ktxq_list;
	struct list_head krxq_list;
};

struct chtcp_sock_common {
	struct chtcp_kadapter *dev;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	unsigned long flags;
};

struct chtcp_ksock {
	struct chtcp_kadapter *dev;
	struct sockaddr_storage local_addr;
	struct l2t_entry *l2t;
	struct dst_entry *dst;
	atomic_t arp_failed;
	u32 tid;
	struct list_head acsk_link;  /* accept sock link */
};

struct chtcp_klisten_sock {
	struct chtcp_kadapter *dev;
	u32 stid;
	u16 ss_family;
	u8 port_id;
	struct list_head lcsk_link;  /* listen sock link */
	struct list_head acsk_list;  /* accept sock list */
	struct mutex acsk_lock;
};


struct chtcp_sock_info {
	struct chtcp_sock_common com;
	struct l2t_entry *l2t;
	struct dst_entry *dst;
	u32 wr_cred;
	u32 wr_una_cred;
	u32 wr_max_cred;
	u32 tid;
	u32 smac_idx;
	u32 tx_chan;
	u32 rx_chan;
	u32 mtu;
	u32 snd_win;
	u32 rcv_win;
	u16 rss_qid;
	u16 ctrlq_idx;
	u8 tos;
	u8 port_id;
};

struct chtcp_ktxq_info {
	__u8 port_id;
	__u32 eq_id;
	struct list_head ktxq_link;
};

struct chtcp_krxq_info {
	__u8 port_id;
	__u32 iq_id;
	__u32 fl_id;
	struct list_head krxq_link;
};

static inline void chtcp_infinite_wait(void)
{
	struct completion cmpl;

	pr_err("%s: app terminated abnormally: Reboot required\n", __func__);
	init_completion(&cmpl);
	wait_for_completion(&cmpl);
}


int chtcp_ksge_alloc_ofld_txq(struct chtcp_kadapter *dev,
			       struct chtcp_txq_info *txq_info);
int chtcp_ksge_alloc_ofld_rxq(struct chtcp_kadapter *dev,
			       struct chtcp_rxq_info *rxq_info);
int chtcp_kofld_eq_free(struct chtcp_kadapter *dev,
			 struct chtcp_free_txq_info *fti);
int chtcp_kofld_iq_free(struct chtcp_kadapter *dev,
			 struct chtcp_free_rxq_info *fri);
int chtcp_setup_conm_ctx(struct chtcp_kadapter *dev,
			 struct chtcp_conm_ctx_info *ctx_info);
void chtcp_free_krxq_info(struct chtcp_kadapter *dev,
			  struct chtcp_free_rxq_info *fri);
void chtcp_free_ktxq_info(struct chtcp_kadapter *dev,
			  struct chtcp_free_txq_info *fti);
#endif /* __CHTCP_K_H__ */
