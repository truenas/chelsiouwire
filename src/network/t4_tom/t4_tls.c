/*
 * Function definition for TLS and DTLS functionalities
 *
 * Copyright (C) 2011-2021 Chelsio Communications.  All rights reserved.
 * Written By Atul Gupta (atul.gupta@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/toedev.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/crypto.h>
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#include <linux/pagemap.h>
#include <linux/mm.h>
#endif

#include <net/offload.h>
#include <net/tcp.h>
#include <net/ip.h>
#if defined(CONFIG_TCPV6_OFFLOAD)
#include <net/transp_v6.h>
#endif
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include "defs.h"
#include "t4_ddp.h"
#include "tom.h"
#include "cxgb4_ofld.h"
#include "t4_tcb.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "trace.h"
#include "offload.h"
#include "t4_tls.h"
#include "t4_tlskey.h"

extern void t4_set_tcb_tflag(struct sock *sk, unsigned int bit_pos, int val);
extern void __set_tcb_field(struct sock *sk, struct sk_buff *skb, u16 word,
		u64 mask, u64 val, u8 cookie, int no_reply);
extern void send_or_defer(struct sock *sk, struct tcp_sock *tp,
			  struct sk_buff *skb, int through_l2t);

/*
 * Returns true if an sk_buff carries urgent data.
 */
static inline int skb_urgent(struct sk_buff *skb)
{
	return (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_URG) != 0;
}

static void t4_set_tls_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val)
{
	struct sk_buff *skb;
        struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen = roundup(sizeof(struct cpl_set_tcb_field) +
				     sizeof(struct ulptx_idata), 16);
	unsigned int credits_needed = DIV_ROUND_UP(wrlen , 16);

        if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
	        return;

        skb = alloc_skb(wrlen, GFP_KERNEL);
        BUG_ON(!skb);

        __set_tcb_field(sk, skb, word, mask, val, 0, 1);
        set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	cplios->wr_credits -= credits_needed;
	cplios->wr_unacked += credits_needed;
	enqueue_wr(sk, skb);
	cxgb4_ofld_send(cplios->egress_dev, skb);
}

#if defined(CONFIG_CHELSIO_IO_SPIN)
/*
 * Return nanosecond "cycle counter".  This is used to time short intervals
 * via simple unsigned integer subtraction.  E.g. (t1 - t0) < interval.
 */
static inline unsigned long long get_ns_cycles(void)
{
	return (unsigned long long)ktime_to_ns(ktime_get());
}
#endif

/* TLS and DTLS common routines */
int tls_tx_key(struct sock *sk)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

	return (tls_ofld->tx_key_id >= 0);
}

int tls_rx_key(struct sock *sk)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

	return (tls_ofld->rx_key_id >= 0);
}

static int nos_ivs(struct sock *sk, int size)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

	return ceil(size, tls_ofld->k_ctx->frag_size);
}

static int key_size(struct sock *sk)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);

	return ((tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_IMMEDIATE) ?
		tls_ofld->k_ctx->tx_key_info_size : KEY_IN_DDR_SIZE);
}

static inline unsigned int sgl_len(unsigned int n)
{
        n--;
        return (3 * n) / 2 + (n & 1) + 2;
}


static int data_sgl_len(const struct sk_buff *skb)
{
	unsigned int cnt;

	cnt = skb_shinfo(skb)->nr_frags;
	return (sgl_len(cnt) * 8);
}

static int is_ivs_imm(struct sock *sk, const struct sk_buff *skb)
{
	int ivs_size = nos_ivs(sk, skb->len) * CIPHER_BLOCK_SIZE;
	int hlen = TLS_WR_CPL_LEN + data_sgl_len(skb);

	if ((hlen + key_size(sk) + ivs_size) <
	    MAX_IMM_OFLD_TX_DATA_WR_LEN) {
		ULP_SKB_CB(skb)->ulp.tls.iv = 1;
		return 1;
	}
	ULP_SKB_CB(skb)->ulp.tls.iv = 0;
	return 0;
}

static int is_key_imm(struct sock *sk)
{
	return (TLS_WR_CPL_LEN + key_size(sk) < MAX_IMM_OFLD_TX_DATA_WR_LEN);
}

static int max_ivs_size(struct sock *sk, int size)
{
	return (nos_ivs(sk, size) * CIPHER_BLOCK_SIZE);
}

static int ivs_size(struct sock *sk, const struct sk_buff *skb)
{
	return (is_ivs_imm(sk, skb) ? (nos_ivs(sk, skb->len) * CIPHER_BLOCK_SIZE) :
		0);
}

/* Set TLS Key-Id in TCB */
static void t4_set_tls_keyid(struct sock *sk, unsigned int key_id)
{
	t4_set_tls_tcb_field(sk, W_TCB_RX_TLS_KEY_TAG,
			 V_TCB_RX_TLS_KEY_TAG(M_TCB_RX_TLS_BUF_TAG),
			 V_TCB_RX_TLS_KEY_TAG(key_id));
}

/* Clear the Rx quiesce */
static void t4_set_rx_quiesce(struct sock *sk, int val)
{
	t4_set_tls_tcb_field(sk, W_TCB_T_FLAGS, 1ULL << S_TF_RX_QUIESCE, val << S_TF_RX_QUIESCE);
}

/* This clears the tls overlay fields*/
static void initialize_tls_overlay(struct sock *sk)
{
	t4_set_tcb_field(sk, W_TCB_RX_TLS_BUF_OFFSET,
			 V_TCB_RX_TLS_BUF_OFFSET(M_TCB_RX_TLS_BUF_OFFSET) |
			 V_TCB_RX_TLS_BUF_LEN(M_TCB_RX_TLS_BUF_LEN),
			 V_TCB_RX_TLS_BUF_OFFSET(0) |
			 V_TCB_RX_TLS_BUF_LEN(0));

	t4_set_tcb_field(sk, W_TCB_RX_TLS_FLAGS, V_TCB_RX_TLS_FLAGS(M_TCB_RX_TLS_FLAGS),
			 V_TCB_RX_TLS_FLAGS(0));

	t4_set_tcb_field(sk, W_TCB_RX_TLS_BUF_TAG, V_TCB_RX_TLS_BUF_TAG(M_TCB_RX_TLS_BUF_TAG),
		 	 V_TCB_RX_TLS_BUF_TAG(0));

	t4_set_tcb_field(sk, W_TCB_RX_TLS_KEY_TAG, V_TCB_RX_TLS_KEY_TAG(W_TCB_RX_TLS_KEY_TAG),
			 V_TCB_RX_TLS_KEY_TAG(0));
}

/* Initialize TLS offload mode. It will use toe queues, not initializing separate queues
 * for TLS stats as we have debugfs to show tls stats.
 * */
int tls_set_ofld_mode(struct sock *sk)
{
	struct cpl_io_state *cplios;
	struct offload_req orq;
	struct offload_settings settings;
	struct toedev *tdev = NULL;
	struct tom_data *td = NULL;
	struct adapter *adap = NULL;
	int init_ulp_mode;

	cplios = CPL_IO_STATE(sk);
	tdev = cplios->toedev;
	td = TOM_DATA(tdev);

	 /* Lookup cop policy settings for this connection */
	offload_req_from_sk(&orq, sk, OPEN_TYPE_ACTIVE);
	settings = *lookup_ofld_policy(tdev, &orq, td->conf.cop_managed_offloading);
	if (!settings.offload) {
		return -1;
	}

	init_ulp_mode = cplios->ulp_mode;
	 /* Initialize tls offload if we have inline tls enabled adapter and
	  * tls offload is enabled using sysctl variable or cop policy.
	  * */
	adap = netdev2adap(cplios->egress_dev);
	if (adap && (adap->params.ulp_crypto & ULP_CRYPTO_INLINE_TLS) &&
		    (is_tls_sock(sk, tdev) || settings.tls))
			tls_offload_init(cplios);

	if (!cplios->tls_ofld.tls_offload)
		return -1;
	cplios->lro = 0;

	/* set option 2 for tls ulp */
	t4_set_tcb_field(sk, W_TCB_T_FLAGS, (1ULL << S_TF_RCV_COALESCE_ENABLE)
					   |(1ULL << S_TF_RX_FLOW_CONTROL_DDP)
					   |(1ULL << S_TF_RX_FLOW_CONTROL_DISABLE), 0);

	/* If initial ulp mode is ULP_MODE_NONE the tls overlay fields may hold stale
	 * info so clearing it. */
	if(init_ulp_mode == ULP_MODE_NONE)
		initialize_tls_overlay(sk);

        return 0;
}

/* Clear the TLS off-load mode and move connection to TCP offload mode */
int tls_clr_ofld_mode(struct sock *sk)
{
	struct cpl_io_state *cplios;
	struct tls_ofld_info *tls_ofld;

	lock_sock(sk);
	tls_ofld = TLS_IO_STATE(sk);
	cplios = CPL_IO_STATE(sk);
	/* cancel handshake work */
	stop_hndsk_work(sk);
	/* Operate in PDU extraction mode only */
	t4_set_tcb_field(sk, W_TCB_ULP_RAW, V_TCB_ULP_RAW(V_TF_TLS_ENABLE(1)),
			 V_TCB_ULP_RAW(V_TF_TLS_ENABLE(0)));
	t4_set_tcb_field(sk, W_TCB_ULP_TYPE, V_TCB_ULP_TYPE(M_TCB_ULP_TYPE),
			 V_TCB_ULP_TYPE(0));
	cplios->ulp_mode = ULP_MODE_NONE;
	release_sock(sk);

	return 0;
}

/* clear quiesce for non-ccs packets */
int tls_clr_quiesce(struct sock *sk)
{
       struct tls_ofld_info *tls_ofld;

       lock_sock(sk);
       tls_ofld = TLS_IO_STATE(sk);
	/* cancel handshake work */
       stop_hndsk_work(sk);

	t4_set_rx_quiesce(sk, 0);
	release_sock(sk);

	return 0;
}

/*
 * Calculate the TLS data expansion size
 */
static int tls_expansion_size(struct sock *sk, int data_len,
				int full_pdus_only,
				unsigned short *pdus_per_ulp)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct tls_scmd *scmd = &tls_ofld->scmd0;
	int expn_size = 0, frag_count = 0, pad_per_pdu = 0,
	    pad_last_pdu = 0, last_frag_size = 0, max_frag_size = 0;
	int exp_per_pdu = 0;
	int hdr_len = ((sk->sk_type == SOCK_DGRAM) ?
		       DTLS_HEADER_LENGTH : TLS_HEADER_LENGTH);

	do {
		max_frag_size = tls_ofld->k_ctx->frag_size;
		if (G_SCMD_CIPH_MODE(scmd->seqno_numivs) ==
		   SCMD_CIPH_MODE_AES_GCM) {
			frag_count = (data_len / max_frag_size);
			exp_per_pdu = GCM_TAG_SIZE + AEAD_EXPLICIT_DATA_SIZE +
				hdr_len;
			expn_size =  frag_count * exp_per_pdu;
			if (full_pdus_only) {
				*pdus_per_ulp = data_len / (exp_per_pdu +
					max_frag_size);
				if (*pdus_per_ulp > 32)
					*pdus_per_ulp = 32;
				else if(!*pdus_per_ulp)
					*pdus_per_ulp = 1;
				expn_size = (*pdus_per_ulp) * exp_per_pdu;
				break;
			}	
			if ((last_frag_size = data_len % max_frag_size) > 0) {
				frag_count += 1;
				expn_size += exp_per_pdu;
			}
			break;
		} else if (G_SCMD_CIPH_MODE(scmd->seqno_numivs) !=
			   SCMD_CIPH_MODE_NOP) {
			/* Calculate the number of fragments we can make */
			frag_count  = (data_len / max_frag_size);
			if (frag_count > 0) {
				pad_per_pdu = (((ceil((max_frag_size +
						       tls_ofld->mac_length),
						      CIPHER_BLOCK_SIZE)) *
						CIPHER_BLOCK_SIZE) -
					       (max_frag_size +
						tls_ofld->mac_length));
				if (!pad_per_pdu)
					pad_per_pdu = CIPHER_BLOCK_SIZE;
				exp_per_pdu = pad_per_pdu +
				       	tls_ofld->mac_length +
					hdr_len + CIPHER_BLOCK_SIZE;
				expn_size = frag_count * exp_per_pdu;
			}
			if(full_pdus_only) { 
				*pdus_per_ulp = data_len / (exp_per_pdu +
					max_frag_size);
				if (*pdus_per_ulp > 32)
					*pdus_per_ulp = 32;
				else if(!*pdus_per_ulp)
					*pdus_per_ulp = 1;
				expn_size = (*pdus_per_ulp) * exp_per_pdu;
				break;
			}
			/* Consider the last fragment */
			if ((last_frag_size = data_len % max_frag_size) > 0) {
				pad_last_pdu = (((ceil((last_frag_size +
							tls_ofld->mac_length),
						       CIPHER_BLOCK_SIZE)) *
						 CIPHER_BLOCK_SIZE) -
						(last_frag_size +
						 tls_ofld->mac_length));
				if (!pad_last_pdu)
					pad_last_pdu = CIPHER_BLOCK_SIZE;
				expn_size += (pad_last_pdu +
					      tls_ofld->mac_length + hdr_len +
					      CIPHER_BLOCK_SIZE);
			}
		}
	} while (0);

	return expn_size;
}

/* Copy IVs to WR */
static int tls_copy_ivs(struct sock *sk, struct sk_buff *skb)

{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	u16 number_of_ivs = 0;
	int err = 0;
	unsigned char *ivs;
	unsigned char *iv_loc = NULL;
	struct page *page;

	number_of_ivs = nos_ivs(sk, skb->len);

	if (number_of_ivs > MAX_IVS_PAGE) {
		pr_warn("MAX IVs in PAGE exceeded %d\n", number_of_ivs);
		return -ENOMEM;
	}

	/* generate the  IVs */
	ivs = kmalloc(number_of_ivs * CIPHER_BLOCK_SIZE, GFP_ATOMIC);
	if (!ivs) {
		pr_warn("Failed to allocate iv space\n");
		return -ENOMEM;
	}
	get_random_bytes(ivs, number_of_ivs * CIPHER_BLOCK_SIZE);

	if (skb_ulp_tls_skb_iv(skb)) {
		/* send the IVs as immediate data in the WR */
		iv_loc = (unsigned char *)__skb_push(skb, number_of_ivs *
						     CIPHER_BLOCK_SIZE);
		if (NULL != iv_loc)
			memcpy(iv_loc, ivs, number_of_ivs * CIPHER_BLOCK_SIZE);
		tls_ofld->copied_imm_ivs_size = number_of_ivs *
			CIPHER_BLOCK_SIZE;
	} else {
		/* Send the IVs as sgls */
		/* Already accounted IV DSGL for credits */
		skb_shinfo(skb)->nr_frags--;
		page = alloc_pages(GFP_ATOMIC | __GFP_COMP, 0);
		if (!page) {
			printk(KERN_ERR "%s : Page allocation for IVs failed\n",
			       __func__);
			err = -ENOMEM;
			goto out;
		}
		memcpy(page_address(page), ivs, number_of_ivs *
		       CIPHER_BLOCK_SIZE);
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags, page, 0,
				   number_of_ivs * CIPHER_BLOCK_SIZE);
		tls_ofld->copied_imm_ivs_size = 0;
	}
out:
	kfree(ivs);
	return err;
}

static unsigned int keyid_to_addr(int start_addr, int keyid)
{
	return ((start_addr + (keyid * TLS_KEY_CONTEXT_SZ)) >> 5);
}

/* Copy Key to WR */
static void tls_copy_tx_key(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	struct ulptx_sc_memrd *sc_memrd;
	unsigned char *key_loc = NULL;
	struct ulptx_idata *sc;
	u32 immdlen;

	if (tls_ofld->k_ctx->tx_key_info_size <= 0)
		return;

	if (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_DDR) {
		immdlen = sizeof(*sc) + sizeof(*sc_memrd);
		sc = (struct ulptx_idata *)__skb_push(skb, immdlen);
		if (NULL != sc) {
			sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
			sc->len = htonl(0);
			sc_memrd = (struct ulptx_sc_memrd *)(sc + 1);
			sc_memrd->cmd_to_len = htonl(
						V_ULPTX_CMD(ULP_TX_SC_MEMRD) |
						V_ULP_TX_SC_MORE(1) |
						V_ULPTX_LEN16(
				tls_ofld->k_ctx->tx_key_info_size >> 4));
			sc_memrd->addr = htonl(keyid_to_addr(td->kmap.start,
					       tls_ofld->tx_key_id));
		}
		tls_ofld->key_len = immdlen;
	} else if ((tls_ofld->key_location ==
		    TLS_SFO_WR_CONTEXTLOC_IMMEDIATE) && is_key_imm(sk)) {
		key_loc = (unsigned char *)
			__skb_push(skb, tls_ofld->k_ctx->tx_key_info_size);
		if (NULL != key_loc) {
			memcpy(key_loc, &tls_ofld->k_ctx->tx,
			       tls_ofld->k_ctx->tx_key_info_size);
		} else {
			pr_warn("SKB_PUSH failed\n");
		}
		tls_ofld->key_len = tls_ofld->k_ctx->tx_key_info_size;
	}
}

/* TLS/DTLS content type  for CPL SFO */
static inline unsigned char tls_content_type(unsigned char content_type)
{
	switch (content_type) {
	case CONTENT_TYPE_CCS:
		return CPL_TX_TLS_SFO_TYPE_CCS;
	case CONTENT_TYPE_ALERT:
		return CPL_TX_TLS_SFO_TYPE_ALERT;
	case CONTENT_TYPE_HANDSHAKE:
		return CPL_TX_TLS_SFO_TYPE_HANDSHAKE;
	case CONTENT_TYPE_HEARTBEAT:
		return CPL_TX_TLS_SFO_TYPE_HEARTBEAT;
	}
	return CPL_TX_TLS_SFO_TYPE_DATA;
}

static unsigned char get_cipher_key_size(unsigned int ck_size)
{
	switch (ck_size) {
	case AES_NOP: /* NOP */
		return 15;
	case AES_128: /* AES128 */
		return CH_CK_SIZE_128;
	case AES_192: /* AES192 */
		return CH_CK_SIZE_192;
	case AES_256: /* AES256 */
		return CH_CK_SIZE_256;
	default:
		return CH_CK_SIZE_256;
	}
}

static unsigned char get_mac_key_size(unsigned int mk_size)
{
	switch (mk_size) {
	case SHA_NOP: /* NOP */
		return CH_MK_SIZE_128;
	case SHA_GHASH: /* GHASH */
	case SHA_512: /* SHA512 */
		return CH_MK_SIZE_512;
	case SHA_224: /* SHA2-224 */
		return CH_MK_SIZE_192;
	case SHA_256: /* SHA2-256*/
		return CH_MK_SIZE_256;
	case SHA_384: /* SHA384 */
		return CH_MK_SIZE_512;
	case SHA1: /* SHA1 */
	default:
		return CH_MK_SIZE_160;
	}
}

static unsigned char get_proto_ver(int proto_ver)
{
	switch (proto_ver) {
	case TLS1_2_VERSION:
		return TLS_1_2_VERSION;
	case TLS1_1_VERSION:
		return TLS_1_1_VERSION;
	case DTLS1_2_VERSION:
		return DTLS_1_2_VERSION;
	default:
		return TLS_VERSION_MAX;
	}
}

static void tls_rxkey_flit1(struct tls_keyctx *kwr,
			    struct tls_key_context *kctx)
{
	if (kctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		kwr->u.rxhdr.ivinsert_to_authinsrt =
			cpu_to_be64(V_TLS_KEYCTX_TX_WR_IVINSERT(6ULL) |
				    V_TLS_KEYCTX_TX_WR_AADSTRTOFST(1ULL) |
				    V_TLS_KEYCTX_TX_WR_AADSTOPOFST(5ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHSRTOFST(14ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(16ULL) |
				    V_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(14ULL) |
				    V_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(0ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHINSRT(16ULL));
		kwr->u.rxhdr.ivpresent_to_rxmk_size &=
			~(V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(1));
		kwr->u.rxhdr.authmode_to_rxvalid &=
			~(V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(1));
	} else {
		kwr->u.rxhdr.ivinsert_to_authinsrt =
			cpu_to_be64(V_TLS_KEYCTX_TX_WR_IVINSERT(6ULL) |
				    V_TLS_KEYCTX_TX_WR_AADSTRTOFST(1ULL) |
				    V_TLS_KEYCTX_TX_WR_AADSTOPOFST(5ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHSRTOFST(22ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(0ULL) |
				    V_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(22ULL) |
				    V_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(0ULL) |
				    V_TLS_KEYCTX_TX_WR_AUTHINSRT(0ULL));
	}
}

/* Rx key */
static void prepare_rxkey_wr(struct tls_keyctx *kwr,
			     struct tls_key_context *kctx)
{
	unsigned int ck_size = kctx->cipher_secret_size;
	unsigned int mk_size = kctx->mac_secret_size;
	int proto_ver = kctx->proto_ver;

	kwr->u.rxhdr.flitcnt_hmacctrl =
		((kctx->tx_key_info_size >> 4) << 3) | kctx->hmac_ctrl;

	kwr->u.rxhdr.protover_ciphmode =
		V_TLS_KEYCTX_TX_WR_PROTOVER(get_proto_ver(proto_ver)) |
		V_TLS_KEYCTX_TX_WR_CIPHMODE(kctx->state.enc_mode);

	kwr->u.rxhdr.authmode_to_rxvalid =
		V_TLS_KEYCTX_TX_WR_AUTHMODE(kctx->state.auth_mode) |
		V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(1) |
		V_TLS_KEYCTX_TX_WR_SEQNUMCTRL(3) |
		V_TLS_KEYCTX_TX_WR_RXVALID(1);

	kwr->u.rxhdr.ivpresent_to_rxmk_size =
		V_TLS_KEYCTX_TX_WR_IVPRESENT(0) |
		V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_RXCK_SIZE(get_cipher_key_size(ck_size)) |
		V_TLS_KEYCTX_TX_WR_RXMK_SIZE(get_mac_key_size(mk_size));

	tls_rxkey_flit1(kwr, kctx);

	/* No key reversal for GCM */
	if (kctx->state.enc_mode != CH_EVP_CIPH_GCM_MODE) {
		get_aes_decrypt_key(kwr->keys.edkey, kctx->rx.key,
				    (kctx->cipher_secret_size << 3));
		memcpy(kwr->keys.edkey + kctx->cipher_secret_size,
		       kctx->rx.key + kctx->cipher_secret_size,
		       (IPAD_SIZE + OPAD_SIZE));
	} else {
		memcpy(kwr->keys.edkey, kctx->rx.key,
		       (kctx->tx_key_info_size - SALT_SIZE));
		memcpy(kwr->u.rxhdr.rxsalt, kctx->rx.salt, SALT_SIZE);
	}
}

/* Tx key */
static void prepare_txkey_wr(struct tls_keyctx *kwr,
			     struct tls_key_context *kctx)
{
	unsigned int ck_size = kctx->cipher_secret_size;
	unsigned int mk_size = kctx->mac_secret_size;

	kwr->u.txhdr.ctxlen =
		(kctx->tx_key_info_size >> 4);
	kwr->u.txhdr.dualck_to_txvalid =
		V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_SALT_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_TXCK_SIZE(get_cipher_key_size(ck_size)) |
		V_TLS_KEYCTX_TX_WR_TXMK_SIZE(get_mac_key_size(mk_size)) |
		V_TLS_KEYCTX_TX_WR_TXVALID(1);

	memcpy(kwr->keys.edkey, kctx->tx.key, HDR_KCTX_SIZE);
	if (kctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		memcpy(kwr->u.txhdr.txsalt, kctx->tx.salt, SALT_SIZE);
		kwr->u.txhdr.dualck_to_txvalid &=
			~(V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1));
	}
	kwr->u.txhdr.dualck_to_txvalid = htons(kwr->u.txhdr.dualck_to_txvalid);
}

/* TLS Key bitmap processing */
int tls_init_kmap(struct tom_data *td, struct cxgb4_lld_info *lldi)
{
	unsigned int num_key_ctx, bsize;

	num_key_ctx = (lldi->vr->key.size / TLS_KEY_CONTEXT_SZ);
	bsize = BITS_TO_LONGS(num_key_ctx);

	td->kmap.size = num_key_ctx; 
	td->kmap.available = bsize; 
	td->kmap.addr = t4tom_alloc_mem(sizeof(*td->kmap.addr) *
					      bsize);
	if (!td->kmap.addr)
		return -1;

	td->kmap.start = lldi->vr->key.start;
	spin_lock_init(&td->kmap.lock);
	return 0;
}

static int get_new_keyid(struct sock *sk, struct tls_key_context *k_ctx)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	struct net_device *dev = cplios->egress_dev;
	struct adapter *adap = netdev2adap(dev);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	int keyid;

	spin_lock_bh(&td->kmap.lock);
	keyid = find_first_zero_bit(td->kmap.addr, td->kmap.size);
	if (keyid < td->kmap.size) {
		 __set_bit(keyid, td->kmap.addr);
		if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX)
			tls_ofld->rx_key_id = keyid;
		else
			tls_ofld->tx_key_id = keyid;
		atomic_inc(&adap->tls_stats.tls_key);
	} else {
		keyid = -1;
	}
	spin_unlock_bh(&td->kmap.lock);
	return keyid;
}

void clear_tls_keyid(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct net_device *dev = cplios->egress_dev;
	struct adapter *adap = netdev2adap(dev);

	if (!td->kmap.addr)
		return;

	spin_lock_bh(&td->kmap.lock);
	if (tls_ofld->rx_key_id >= 0) {
		__clear_bit(tls_ofld->rx_key_id, td->kmap.addr);
		tls_ofld->rx_key_id = -1;
		atomic_dec(&adap->tls_stats.tls_key);
	}
	if (tls_ofld->tx_key_id >= 0) {
		__clear_bit(tls_ofld->tx_key_id, td->kmap.addr);
		tls_ofld->tx_key_id = -1;
		atomic_dec(&adap->tls_stats.tls_key);
	}
	spin_unlock_bh(&td->kmap.lock);
}

static int get_keyid(struct tls_ofld_info *tls_ofld, unsigned int ops)
{
	return (ops & KEY_WRITE_RX ? tls_ofld->rx_key_id :
		((ops & KEY_WRITE_TX) ? tls_ofld->tx_key_id : -1));
}

static int get_tp_plen_max(struct tls_ofld_info *tls_ofld)
{
	int plen = ((min(3*4096, TP_TX_PG_SZ))/1448) * 1448;

	return (tls_ofld->k_ctx->frag_size <= 8192 ? plen : FC_TP_PLEN_MAX);	
}

/* Send request to get the key-id */
static int tls_program_key_id(struct sock *sk, struct tls_key_context *k_ctx)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
	int kwrlen, kctxlen, keyid, len;
	struct sk_buff *skb;
	struct tls_key_req *kwr;
	struct tls_keyctx *kctx;

	kwrlen = ALIGN(sizeof(*kwr), 16);
	kctxlen = ALIGN(sizeof(*kctx), 32);
	len = kwrlen + kctxlen;

	/* Dont initialize key for re-neg */
	if (!G_KEY_CLR_LOC(k_ctx->l_p_key)) {
		if ((keyid = get_new_keyid(sk, k_ctx)) < 0) {
			return -ENOSPC;
		}
	} else {
		keyid = get_keyid(tls_ofld, k_ctx->l_p_key);
	}

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	kwr = (struct tls_key_req *)__skb_put(skb, len);
	memset(kwr, 0, kwrlen);

	kwr->wr_hi =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) |
			    F_FW_WR_COMPL |
			    F_FW_WR_ATOMIC);
	kwr->wr_mid =
		cpu_to_be32(V_FW_WR_LEN16(DIV_ROUND_UP(len, 16)) |
		      V_FW_WR_FLOWID(cplios->tid));
	kwr->protocol = get_proto_ver(k_ctx->proto_ver);
	kwr->mfs = htons(tls_ofld->k_ctx->frag_size);
	tls_ofld->fcplenmax = get_tp_plen_max(tls_ofld);
	kwr->reneg_to_write_rx = k_ctx->l_p_key;

	/* master command */
	kwr->cmd = cpu_to_be32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
			 V_T5_ULP_MEMIO_ORDER(1) |
			 V_T5_ULP_MEMIO_IMM(1));
	kwr->dlen = cpu_to_be32(V_ULP_MEMIO_DATA_LEN(kctxlen >> 5));
	kwr->len16 = cpu_to_be32((cplios->tid << 8) |
				 DIV_ROUND_UP(len - sizeof(struct work_request_hdr), 16));
	kwr->kaddr = cpu_to_be32(V_ULP_MEMIO_ADDR(keyid_to_addr(td->kmap.start, keyid)));

	/* sub command */
	kwr->sc_more = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));	
	kwr->sc_len = cpu_to_be32(kctxlen);

	kctx = (struct tls_keyctx *)(kwr + 1);
	memset(kctx, 0, kctxlen);

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX)
		prepare_txkey_wr(kctx, k_ctx);
	else if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX)
		prepare_rxkey_wr(kctx, k_ctx);

	set_wr_txq(skb, CPL_PRIORITY_DATA, tls_ofld->tx_qid);
	tls_ofld->key_rqst = 0;
	cplios->wr_credits -= DIV_ROUND_UP(len, 16);
	cplios->wr_unacked += DIV_ROUND_UP(len, 16);
	enqueue_wr(sk, skb);
	cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

/* Program the key info received from SSL to DDR */
int program_key_context(struct sock *sk,
			struct tls_key_context *uk_ctx)
{
	struct cpl_io_state *cplios;
	struct tls_ofld_info *tls_ofld;
	struct tls_key_context *k_ctx;
	int rc = 0;

	lock_sock(sk);
	cplios = CPL_IO_STATE(sk);
	tls_ofld = TLS_IO_STATE(sk);
	k_ctx = tls_ofld->k_ctx;
	/* cancel handshake work */
	stop_hndsk_work(sk);

	if (!sk_in_state(sk, TCPF_ESTABLISHED)) {
		rc = -ENOENT;
		goto out;
	}

	if (!k_ctx) {
		k_ctx = kzalloc(sizeof(struct tls_key_context),
				GFP_KERNEL);
		if (!k_ctx) {
			rc = -ENOMEM;
			goto out;
		}
	}

	memcpy(((char *)k_ctx + TLS_KEY_COMMON_OFST),
	       ((char *)uk_ctx + TLS_KEY_COMMON_OFST), TLS_KEY_COMMON_SZ);

	/* TLS version != 1.1 and !1.2 OR DTLS != 1.2 */
	if (get_proto_ver(k_ctx->proto_ver) > DTLS_1_2_VERSION) {
		if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
			tls_ofld->rx_key_id = -1;
			t4_set_rx_quiesce(sk, 0);
		} else {
			tls_ofld->tx_key_id = -1;
		}
		kfree(k_ctx);
		tls_ofld->k_ctx = NULL;
		tls_ofld->key_reply = 0;
		rc = 0;
		goto out;
	}

	if (k_ctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		k_ctx->iv_size = 4;
		k_ctx->mac_first = 0;
		k_ctx->hmac_ctrl = 0;
	} else {
		k_ctx->iv_size = 8; /* for CBC, iv is 16B, unit of 2B */
		k_ctx->mac_first = 1;
	}

	tls_ofld->scmd0.seqno_numivs =
		(V_SCMD_SEQ_NO_CTRL(3) |
		 V_SCMD_PROTO_VERSION(get_proto_ver(k_ctx->proto_ver)) |
		 V_SCMD_ENC_DEC_CTRL(SCMD_ENCDECCTRL_ENCRYPT) |
		 V_SCMD_CIPH_AUTH_SEQ_CTRL((k_ctx->mac_first == 0)) |
		 V_SCMD_CIPH_MODE(k_ctx->state.enc_mode) |
		 V_SCMD_AUTH_MODE(k_ctx->state.auth_mode) |
		 V_SCMD_HMAC_CTRL(k_ctx->hmac_ctrl) |
		 V_SCMD_IV_SIZE(k_ctx->iv_size) |
		 V_SCMD_NUM_IVS(1));

	tls_ofld->scmd0.ivgen_hdrlen =
		(V_SCMD_IV_GEN_CTRL(k_ctx->iv_ctrl) |
		 V_SCMD_KEY_CTX_INLINE(0) |
		 V_SCMD_TLS_FRAG_ENABLE(1));

	tls_ofld->mac_length = k_ctx->mac_secret_size;

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		memcpy(((char *)k_ctx + TLS_KEY_TX_CONTEXT),
		       ((char *)uk_ctx + TLS_KEY_TX_CONTEXT),
		       TLS_KEY_RX_CONTEXT);
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->rx_key_id = -1;
	} else {
		memcpy((char *)k_ctx, (char *)uk_ctx, TLS_KEY_TX_CONTEXT);
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->tx_key_id = -1;
	}

	tls_ofld->k_ctx = k_ctx;

	/* Flush pending data before new Tx key becomes active */
	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX) {
		if (skb_queue_len(&cplios->tx_queue))
			t4_push_frames(sk, 0);
		tls_ofld->tx_seq_no = 0;
	}

	if ((G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) ||
	    (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_DDR)) {
		rc = tls_program_key_id(sk, k_ctx);
		if (rc < 0) {
			t4_set_rx_quiesce(sk, 0);
			tls_ofld->tx_key_id = -1;
			tls_ofld->rx_key_id = -1;
			rc = -EINVAL;
			goto out;
		}
	}

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		/* Key address is 3 multiple of key-id */
		t4_set_tls_keyid(sk, (unsigned int)(3 * tls_ofld->rx_key_id));
		t4_set_tls_tcb_field(sk, W_TCB_ULP_RAW,
				 V_TCB_ULP_RAW(M_TCB_ULP_RAW),
				 V_TCB_ULP_RAW((V_TF_TLS_KEY_SIZE(3) |
						V_TF_TLS_CONTROL(1) |
						V_TF_TLS_ACTIVE(1) |
						V_TF_TLS_ENABLE(1))));
		t4_set_tls_tcb_field(sk, W_TCB_TLS_SEQ,
				 V_TCB_TLS_SEQ(M_TCB_TLS_SEQ),
				 V_TCB_TLS_SEQ(0));
		t4_set_rx_quiesce(sk, 0);
	} else {
		if ((tls_ofld->key_location ==
		     TLS_SFO_WR_CONTEXTLOC_IMMEDIATE))
			tls_ofld->tx_key_id = 1;
	}
out:
	release_sock(sk);
	return rc;
}

static void send_tls_rxmod(struct sock *sk)
{
	struct sk_buff *skb;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_data_ack *req;

	skb = alloc_ctrl_skb(cplios->ctrl_skb_cache, sizeof(*req));
	if (!skb) {
		printk("failed to alloc skb \n");
		return;
	}
	req = (struct cpl_rx_data_ack *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_RX_DATA_ACK, cplios->tid);
	req->credit_dack = htonl(F_RX_MODULATE_RX);
	set_wr_txq(skb, CPL_PRIORITY_ACK, cplios->port_id);
	cxgb4_ofld_send(cplios->egress_dev, skb);

}

/*
 * Generate the dummy ACK for rx modulation if ServerHelloDone is stuck.
 * Decrease reference count of "sk" and "cplios" in case timer restart is
 * not required.
 */
static void handshake_work(struct work_struct *work)
{
	struct tls_ofld_info *tls_ofld =
		container_of(work, struct tls_ofld_info, hsk_work.work);
	struct sock *sk = tls_ofld->sk;
	struct cpl_io_state *cplios;

	lock_sock(sk);
	/* cplios(CPL_IO_STATE(sk)) = sk->sk_prot->ptr, We hold reference on
	 * sk and ptr(cpl_io_state) but not on sk_prot. At timer expiry it may
	 * possible "sk_prot" pointer is already freed. CPL_IO_STATE(sk) macro
	 * should not be used here to get reference of "cplios"
	 * */
	cplios = container_of(tls_ofld, struct cpl_io_state, tls_ofld);
	if (cplios && (!(sk->sk_state == TCP_CLOSE ||
			sk->sk_state == TCP_TIME_WAIT ||
			tls_ofld->work_done != TLS_CLIENT_WQ_CLR))) {
		send_tls_rxmod(sk);
		schedule_delayed_work(&tls_ofld->hsk_work, TLS_SRV_HELLO_RD_TM);
	} else {
		kref_put(&cplios->kref, t4_cplios_release);
		sock_put(sk);
	}

	release_sock(sk);
}

/* Start handshake parse: Required only for Client TLS, HW BUG#30158 */
void start_hndsk_work(struct sock *sk)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	/*Increment refcount so that on expiry sk and 
	 * cplios points to valid memory.*/
	sock_hold(sk);
	kref_get(&cplios->kref);
	schedule_delayed_work(&tls_ofld->hsk_work, TLS_SRV_HELLO_BKOFF_TM);
}

void stop_hndsk_work(struct sock *sk)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	tls_ofld->work_done = TLS_CLIENT_WQ_CLR;
	/*In case Work removed successfully from Queue. Decrement the refcount
	 *Otherwise work_handler should decrement the refcount*/
	if (cancel_delayed_work(&tls_ofld->hsk_work)) {
		kref_put(&cplios->kref, t4_cplios_release);
		sock_put(sk);
	}
}

/* To be used from the initial connection establishment modules */
int is_tls_sock(struct sock *sk, struct toedev *dev)
{
	unsigned short src_port = 0, dst_port = 0;
	int *usr_tls_ports = NULL;
	int i = 0;

	/* Assuming we are inside server.Get the source port from the sk
	 * and see if it is available in the list of TLS ports
	 * configured by the application
	 */
	if (!sk || !inet_sk(sk))
		return 0;

	src_port = htons(inet_sk(sk)->inet_sport);
	dst_port = htons(inet_sk(sk)->inet_dport);
	usr_tls_ports = TOM_TUNABLE(dev, tls_ports);

	for (; i < MAX_TLS_PORTS; i++) {
		if ((src_port == *(usr_tls_ports + i)) ||
		    (dst_port == *(usr_tls_ports + i))) {
			return 1;
		}
	}
	return 0;
}

int is_tls_offload(struct sock *sk)
{
	if (TLS_IO_STATE(sk) && TLS_IO_STATE(sk)->tls_offload)
		return 1;
	return 0;
}

/* To be used from the common code areas */
int is_tls_offload_skb(struct sock *sk, const struct sk_buff *skb)
{
	if (is_tls_offload(sk) && skb_ulp_tls_skb_flags(skb))
		return 1;
	return 0;
}

void tls_offload_init(void *ctx)
{
	struct cpl_io_state *cplios = (struct cpl_io_state *)ctx;
	struct tls_ofld_info *tls_ofld = &cplios->tls_ofld;

	memset(tls_ofld, 0, sizeof(*tls_ofld));
	cplios->ulp_mode = ULP_MODE_TLS;
	skb_queue_head_init(&tls_ofld->sk_recv_queue);
	tls_ofld->key_location = TLS_SFO_WR_CONTEXTLOC_DDR;
	tls_ofld->sk = cplios->sk;
	INIT_DELAYED_WORK(&tls_ofld->hsk_work, handshake_work);
	tls_ofld->rx_key_id = -1;
	tls_ofld->tx_key_id = -1;
	tls_ofld->tls_offload = 1;
	kref_init(&tls_ofld->kref);
}

/*
 * TLS specific routines
 */
static inline __be64 tls_sequence_number(struct tls_ofld_info *tls_ofld)
{
	return (tls_ofld->tx_seq_no++);
}

struct sk_buff *alloc_tls_tx_skb(struct sock *sk, int size, bool zcopy)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct sk_buff *skb;

	skb = alloc_skb(((zcopy ? 0 : size) + TLS_TX_HEADER_LEN +
			 key_size(sk) + max_ivs_size(sk, size)),
			sk->sk_allocation);
	if (likely(skb)) {
		skb_reserve(skb, (TLS_TX_HEADER_LEN +
				  key_size(sk) + max_ivs_size(sk, size)));
		skb_entail(sk, skb, ULPCB_FLAG_NEED_HDR);
		skb_reset_transport_header(skb);
		ULP_SKB_CB(skb)->ulp.tls.type = tls_ofld->sd.type;
		ULP_SKB_CB(skb)->ulp.tls.ofld = 1;
	}

	return skb;
}

/*  Get TLS WR Size */
int tls_wr_size(struct sock *sk, const struct sk_buff *skb, bool size)
{
	int wr_size;

	wr_size = TLS_WR_CPL_LEN; 
	wr_size += key_size(sk);
	wr_size += ivs_size(sk, skb);

	if (size)
		return wr_size;

	/* frags counted for IV dsgl */
	if (!skb_ulp_tls_skb_iv(skb))
		skb_shinfo(skb)->nr_frags++;

	return wr_size;
}

/* Create TLS TX Data WR */
static inline void tls_tx_data_wr(struct sock *sk, struct sk_buff *skb,
				  int dlen, int tls_immd, u32 credits,
				  int expn, int pdus)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	unsigned char *req = NULL;
	struct fw_tlstx_data_wr *req_wr = NULL;
	struct cpl_tx_tls_sfo *req_cpl = NULL;
	unsigned char data_type = 0;
	struct tls_scmd *scmd = &tls_ofld->scmd0;
	struct tls_scmd *updated_scmd;
	unsigned int wr_ulp_mode_force;
	int immd_len;
	int len = dlen + expn;
	int iv_imm = skb_ulp_tls_skb_iv(skb);
	struct net_device *dev = cplios->egress_dev;
	struct adapter *adap = netdev2adap(dev);

	atomic_inc(&adap->tls_stats.tls_pdu_tx);

	dlen = (dlen < tls_ofld->k_ctx->frag_size) ? dlen :
		tls_ofld->k_ctx->frag_size;

	updated_scmd = scmd;
	updated_scmd->seqno_numivs &= 0xffffff80;
	updated_scmd->seqno_numivs |= V_SCMD_NUM_IVS(pdus);
	tls_ofld->scmd0 = *updated_scmd;

	req = (unsigned char *)__skb_push(skb, sizeof(struct cpl_tx_tls_sfo));
	req_cpl = (struct cpl_tx_tls_sfo *)req;
	req = (unsigned char *)__skb_push(skb, (sizeof(struct
						       fw_tlstx_data_wr)));
	req_wr = (struct fw_tlstx_data_wr *)req;

	immd_len = (tls_immd ? dlen : 0);
	req_wr->op_to_immdlen =
		htonl(V_FW_WR_OP(FW_TLSTX_DATA_WR) |
		      V_FW_TLSTX_DATA_WR_COMPL(1) |
		      V_FW_TLSTX_DATA_WR_IMMDLEN(immd_len));
	req_wr->flowid_len16 = htonl(V_FW_TLSTX_DATA_WR_FLOWID(cplios->tid) |
				     V_FW_TLSTX_DATA_WR_LEN16(credits));
	wr_ulp_mode_force = V_TX_ULP_MODE(ULP_MODE_TLS);

	if (is_ofld_sg_reqd(skb))
		wr_ulp_mode_force |= F_FW_OFLD_TX_DATA_WR_ALIGNPLD |
			((tcp_sk(sk)->nonagle & TCP_NAGLE_OFF) ? 0 :
			 F_FW_OFLD_TX_DATA_WR_ALIGNPLDSHOVE);

	req_wr->lsodisable_to_flags = htonl(V_TX_ULP_MODE(ULP_MODE_TLS) |
					    V_TX_URG(skb_urgent(skb)) |
					    F_T6_TX_FORCE |
					    wr_ulp_mode_force |
					    V_TX_SHOVE((!cplios_flag(sk,
						CPLIOS_TX_MORE_DATA)) &&
						       skb_queue_empty(
							&cplios->tx_queue)));

	req_wr->ctxloc_to_exp = htonl(V_FW_TLSTX_DATA_WR_NUMIVS(pdus) |
				      V_FW_TLSTX_DATA_WR_EXP(expn) |
				      V_FW_TLSTX_DATA_WR_CTXLOC(
						tls_ofld->key_location) |
				      V_FW_TLSTX_DATA_WR_IVDSGL(!iv_imm) |
				      V_FW_TLSTX_DATA_WR_KEYSIZE(
					tls_ofld->k_ctx->tx_key_info_size >>
					4));

	/* Fill in the length */
	req_wr->plen = htonl(len);
	req_wr->mfs = htons(tls_ofld->k_ctx->frag_size);
	req_wr->adjustedplen_pkd =
		htons(V_FW_TLSTX_DATA_WR_ADJUSTEDPLEN(tls_ofld->adjusted_plen));
	req_wr->expinplenmax_pkd =
		htons(V_FW_TLSTX_DATA_WR_EXPINPLENMAX(tls_ofld->expn_per_ulp));
	req_wr->pdusinplenmax_pkd =
		V_FW_TLSTX_DATA_WR_PDUSINPLENMAX(tls_ofld->pdus_per_ulp);
	req_wr->r10 = 0;

	data_type = tls_content_type(ULP_SKB_CB(skb)->ulp.tls.type);
	req_cpl->op_to_seg_len = htonl(V_CPL_TX_TLS_SFO_OPCODE(CPL_TX_TLS_SFO) |
				       V_CPL_TX_TLS_SFO_DATA_TYPE(data_type) |
				       V_CPL_TX_TLS_SFO_CPL_LEN(2) |
				       V_CPL_TX_TLS_SFO_SEG_LEN(dlen));
	req_cpl->pld_len = htonl(len - expn);

	req_cpl->type_protover = htonl(V_CPL_TX_TLS_SFO_TYPE(
				(data_type == CPL_TX_TLS_SFO_TYPE_HEARTBEAT) ?
				CONTENT_TYPE_HEARTBEAT : 0)|
			        V_CPL_TX_TLS_SFO_PROTOVER(0));

	/* create the s-command */
	req_cpl->r1_lo = 0;
	req_cpl->seqno_numivs  = htonl(tls_ofld->scmd0.seqno_numivs);
	req_cpl->ivgen_hdrlen = htonl(tls_ofld->scmd0.ivgen_hdrlen);
	req_cpl->scmd1 = cpu_to_be64(tls_sequence_number(tls_ofld));
}

/* WR with IV, KEY and CPL SFO added */
void make_tlstx_data_wr(struct sock *sk, struct sk_buff *skb,
			int tls_imm, int tls_len, u32 credits)
{
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	int expn_sz = 0;
	int pdus = ceil(tls_len, tls_ofld->k_ctx->frag_size);
	unsigned short pdus_per_ulp = 0;

	expn_sz = tls_expansion_size(sk, tls_len, 0, NULL);
	if(!tls_ofld->computation_done) {
		tls_ofld->expn_per_ulp = tls_expansion_size(sk,
				tls_ofld->fcplenmax, 1, &pdus_per_ulp);
		tls_ofld->pdus_per_ulp = pdus_per_ulp;
		tls_ofld->adjusted_plen = tls_ofld->pdus_per_ulp *
			((tls_ofld->expn_per_ulp/tls_ofld->pdus_per_ulp) +
			 tls_ofld->k_ctx->frag_size);
		tls_ofld->computation_done = 1;
	}
	tls_copy_ivs(sk, skb);
	tls_copy_tx_key(sk, skb);
	tls_tx_data_wr(sk, skb, tls_len, tls_imm, credits, expn_sz, pdus);
	tls_ofld->tx_seq_no += (pdus - 1);
}

/* Read TLS header to find content type and data length */
int tls_header_read(struct tls_hdr *thdr, struct iov_iter *from)
{
	if (copy_from_iter(thdr, sizeof(*thdr), from) != sizeof(*thdr))
		return -EFAULT;
	return htons(thdr->length);
}

/* TLS receive routine to process TLS CMP/Data skb and copy to user buffer */
int chelsio_tlsv4_recvmsg(struct sock *sk,
			  struct msghdr *msg, size_t len,
			  int nonblock, int flags, int *addr_len)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tls_ofld_info *tls_ofld = TLS_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0, buffers_freed = 0;
	int target;             /* Read at least this many bytes */
	long timeo;
	unsigned long avail;    /* amount of available data in current skb */
	struct net_device *dev = cplios->egress_dev;
	struct adapter *adap = netdev2adap(dev);

#if defined(CONFIG_CHELSIO_IO_SPIN)
	/*
	 * Initialize I/O spin state variables.  (We need to initialize
	 * spin_ns; the others are to avoid annoying compiler warnings.)
	 */
	unsigned int spin_us = 0;
	unsigned long long spin_ns = 0;
	unsigned long long spin_start = 0;
#endif

	timeo = sock_rcvtimeo(sk, nonblock);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	/*
	 * Check to see if we need to grow receive window.
	 */
	if (unlikely(cplios_flag(sk, CPLIOS_UPDATE_RCV_WND)))
		t4_cleanup_rbuf(sk, copied);

#if defined(CONFIG_CHELSIO_IO_SPIN)
	/*
	 * If the administrator has selected to have us spin for recvmsg()
	 * I/O, setup our I/O spin state variables.  Rather than immediately
	 * going to sleep waiting for ingress data when none is available, we
	 * keep spinning for the specified time interval (specified in
	 * microseconds) before giving up and sleeping waiting for new ingress
	 * data.  For latency-sensitive applications this can be a big win
	 * (even though it does waste CPU).
	 *
	 * Note that we can actually be called with the socket in closing
	 * state and with our offload resources released (including our TOE
	 * Device).  So we need to be paranoid here.
	 */
	if (cplios->toedev != NULL) {
		spin_us = TOM_TUNABLE(cplios->toedev, recvmsg_spin_us);
		if (spin_us) {
			spin_ns = (unsigned long long)spin_us * 1000;
			spin_start = get_ns_cycles();
		}
	}
#endif

	do {
		struct sk_buff *skb;
		u32 offset = 0;

		if (unlikely(tp->urg_data && tp->urg_seq == tp->copied_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
					-EAGAIN;
				break;
			}
		}

		skb = skb_peek(&sk->sk_receive_queue);
		if (skb)
			goto found_ok_skb;
		/*
		 * The receive queue is empty and here we are asking for more
		 * data.  Before we do anything else, check to see if we have
		 * data queued up to send and if there's available write
		 * space.  If so, push it along and free up the write space.
		 * This is a major win for request-response style
		 * communication patterns and doesn't hurt bulk data
		 * applications.
		 */
		if (cplios->wr_credits &&
		    skb_queue_len(&cplios->tx_queue) &&
		    t4_push_frames(sk, cplios->wr_credits ==
				   cplios->wr_max_credits))
			sk->sk_write_space(sk);

		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
			    sk_no_receive(sk) ||
			    signal_pending(current))
				break;

			if (!timeo)
				break;

		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}
			if (sk_no_receive(sk))
				break;
			if (sk->sk_state == TCP_CLOSE) {
				copied = -ENOTCONN; /* SOCK_DONE is off here */
				break;
			}
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		if (sk->sk_backlog.tail) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
			t4_cleanup_rbuf(sk, copied);
			continue;
		}

		if (copied >= target) {
			break;
		} else {
			t4_cleanup_rbuf(sk, copied);
#if defined(CONFIG_CHELSIO_IO_SPIN)
			/*
			 * If we're configured for spinning a bit before
			 * giving up and going to sleep to wait for ingress
			 * data, just retry to see if any data has arrived ...
			 */
			if (spin_ns &&
			    get_ns_cycles() - spin_start < spin_ns) {
				release_sock(sk);
				lock_sock(sk);
				continue;
			}
#endif
			sk_wait_data(sk, &timeo);
#if defined(CONFIG_CHELSIO_IO_SPIN)
			/*
			 * If we're configured to spin a bit and the caller
			 * has indicated that it wants to get all of the
			 * requested data length, then set up our I/O spin
			 * state to spin again.  Otherwise, turn off I/O
			 * spinning because the only reason we're back is
			 * because there's more data or we timed out.  (Mostly
			 * this just saves the call to get_ns_cycles().)
			 */
			if (spin_ns) {
				if (flags & MSG_WAITALL)
					spin_start = get_ns_cycles();
				else
					spin_ns = 0;
			}
#endif
		}
		continue;

found_ok_skb:
		if (!skb->len) {                /* ubuf dma is complete */
			tom_eat_ddp_skb(sk, skb);

			if (!copied && !timeo) {
				copied = -EAGAIN;
				break;
			}

			if (copied < target) {
				release_sock(sk);
				lock_sock(sk);
				continue;
			}

			break;
		}

		offset = tls_ofld->copied_seq;
		avail = skb->len - offset;
		if (len < avail)
			avail = len;

		/*
		 * Check if the data we are preparing to copy contains urgent
		 * data.  Either stop short of urgent data or skip it if it's
		 * first and we are not delivering urgent data inline.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;

			if (urg_offset < avail) {
				if (urg_offset) {
					/* stop short of the urgent data */
					avail = urg_offset;
				} else if (!sock_flag(sk, SOCK_URGINLINE)) {
					/* First byte is urgent, skip */
					tp->copied_seq++;
					offset++;
					avail--;
					if (!avail)
						goto skip_copy;
				}
			}
		}

		if (skb_copy_datagram_msg(skb, offset, msg, avail)) {
			if (!copied) {
				copied = -EFAULT;
				break;
			}
		}

		copied += avail;
		len -= avail;
		tls_ofld->copied_seq += avail;

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq))
			tp->urg_data = 0;

		/*
		 * If the buffer is fully consumed free it.
		 * Handle any events it indicates.
		 */
		if((avail + offset >= skb->len)) {
			if (likely(skb))
				tom_eat_skb(sk, skb);
			buffers_freed++;

			if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_TLS_HDR) {
				tp->copied_seq += skb->len;
				tls_ofld->recv_pld_len = skb->hdr_len;
			} else {
				atomic_inc(&adap->tls_stats.tls_pdu_rx);
				tp->copied_seq += tls_ofld->recv_pld_len;
			}
			tls_ofld->copied_seq = 0;
			if  (copied >= target &&
			     !skb_peek(&sk->sk_receive_queue))
				break;
		}
	} while (len > 0);

	/*
	 * If we can still receive decide what to do in preparation for the
	 * next receive.  Note that RCV_SHUTDOWN is set if the connection
	 * transitioned to CLOSE but not if it was in that state to begin with.
	 */
	if (likely(!sk_no_receive(sk))) {
		/*
		 * If we have DDP pending, turn off DDP and pull in any
		 * completed DDP skbs on the receive queue.
		 */
	}

	/* Recheck SHUTDOWN conditions as t4_cancel_ubuf
	 * can release sock lock
	 */
	if (buffers_freed)
		t4_cleanup_rbuf(sk, copied);
	release_sock(sk);
	return copied;
}
