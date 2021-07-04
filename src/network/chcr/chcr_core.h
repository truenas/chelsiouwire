/*
 * This file is part of the Chelsio T6 Crypto driver for Linux.
 *
 * Copyright (c) 2003-2021 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef __CHCR_CORE_H__
#define __CHCR_CORE_H__

#include <crypto/algapi.h>
#include "common.h"
#include "t4_hw.h"
#include "cxgb4_ofld.h"
#include "t4_msg.h"

#define CHCR_PAD_OR_MAC_FAIL    22 /* ie EINVAL */
/* #define CHCR_TIMER_TEST */
#define CHCR_TEST_RESPONSE_TIMEOUT 1000 /* in ms */

#define DRV_MODULE_NAME "chcr"
#define DRV_VERSION "3.14.0.3"
#define DRV_DESC "Chelsio T6 Crypto Co-processor Driver"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define MAX_PENDING_REQ_TO_HW 20
#define CHCR_TEST_RESPONSE_TIMEOUT 1000

/* #define ENABLE_MULTI_CHANNEL */
#define DEBUG
#ifdef DEBUG
#define CHCR_DBG printk
#else
#define CHCR_DBG(format, args...)
#endif

#define PAD_ERROR_BIT		1
#define CHK_PAD_ERR_BIT(x)	(((x) >> PAD_ERROR_BIT) & 1)

#define MAC_ERROR_BIT          0
#define CHK_MAC_ERR_BIT(x)     (((x) >> MAC_ERROR_BIT) & 1)
#define MAX_SALT                4
#define CIP_WR_MIN_LEN (sizeof(struct chcr_wr) + \
		    sizeof(struct cpl_rx_phys_dsgl) + \
		    sizeof(struct ulptx_sgl) + 16) //IV

#define HASH_WR_MIN_LEN (sizeof(struct chcr_wr) + \
			DUMMY_BYTES + \
		    sizeof(struct ulptx_sgl))

#define padap(dev) pci_get_drvdata(dev->u_ctx->lldi.pdev)
struct uld_ctx;

struct _key_ctx {
	__be32 ctx_hdr;
	u8 salt[MAX_SALT];
	__be64 reserverd;
	unsigned char key[0];
};

struct chcr_wr {
	struct fw_crypto_lookaside_wr wreq;
	struct ulp_txpkt ulptx;
	struct ulptx_idata sc_imm;
	struct cpl_tx_sec_pdu sec_cpl;
	struct _key_ctx key_ctx;
};

struct chcr_pending_reqs {
	spinlock_t lock_req;
	struct list_head req_list;
};

struct chcr_dev {
	struct uld_ctx *u_ctx;
	/* maintained per rxq */
	struct chcr_pending_reqs *pending_reqs;
};

struct uld_ctx {
	struct list_head entry;
	struct cxgb4_lld_info lldi;
	struct chcr_dev *dev;
};

#ifdef CONFIG_INLINE_IPSEC
struct chcr_ipsec_req {
	struct ulp_txpkt ulptx;
	struct ulptx_idata sc_imm;
	struct cpl_tx_sec_pdu sec_cpl;
	struct _key_ctx key_ctx;
};

struct chcr_ipsec_wr {
	struct fw_ulptx_wr wreq;
	struct chcr_ipsec_req req;
};

#define ESN_IV_INSERT_OFFSET 12
struct chcr_ipsec_aadiv {
	__be32 spi;
	u8 seq_no[8];
	u8 iv[8];
};

struct ipsec_sa_entry {
	int hmac_ctrl;
	u16 esn;
	u16 imm;
	unsigned int enckey_len;
	unsigned int kctx_len;
	unsigned int authsize;
	__be32 key_ctx_hdr;
	char salt[MAX_SALT];
	char key[2 * AES_MAX_KEY_SIZE];
};
#endif

/*
 *      sgl_len - calculates the size of an SGL of the given capacity
 *      @n: the number of SGL entries
 *      Calculates the number of flits needed for a scatter/gather list that
 *      can hold the given number of entries.
 */
static inline unsigned int sgl_len(unsigned int n) {
n--;
return (3 * n) / 2 + (n & 1) + 2; 
}

struct uld_ctx *assign_chcr_device(void);
int chcr_send_wr(struct sk_buff *skb);
int start_crypto(void);
int stop_crypto(void);
int chcr_uld_rx_handler(void *handle, const __be64 *rsp,
			const struct pkt_gl *pgl);
int chcr_handle_resp(struct crypto_async_request *req, unsigned char *input,
		     int err);
int chcr_uld_tx_handler(struct sk_buff *skb, struct net_device *dev);
int chcr_ipsec_xmit(struct sk_buff *skb, struct net_device *dev);
void chcr_add_xfrmops(const struct cxgb4_lld_info *lld);
#endif /* __CHCR_CORE_H__ */
