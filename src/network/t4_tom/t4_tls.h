/*
 * Header file for socket related functionalities
 *
 * Copyright (C) 2011-2021 Chelsio Communications.  All rights reserved.
 *
 * Written By Atul Gupta (atul.gupta@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __T4_TLS_H
#define __T4_TLS_H
#include <linux/crypto.h>

#define TLSOM_SUCCESS			0
#define TLSOM_FAILURE			-1

#define TLS1_VERSION                    0x0301
#define TLS1_1_VERSION                  0x0302
#define TLS1_2_VERSION                  0x0303
#define TLS_MAX_VERSION                 TLS1_2_VERSION

#define DTLS1_VERSION                   0xFEFF
#define DTLS1_2_VERSION                 0xFEFD
#define DTLS_MAX_VERSION                DTLS1_2_VERSION
#define DTLS1_VERSION_MAJOR             0xFE

#define TLS_SRV_HELLO_DONE		9
#define TLS_SRV_HELLO_RD_TM		(msecs_to_jiffies(5*1000))
#define TLS_SRV_HELLO_BKOFF_TM		(msecs_to_jiffies(15*1000))

#define CONTENT_TYPE_CCS		20
#define CONTENT_TYPE_ALERT		21
#define CONTENT_TYPE_HANDSHAKE		22
#define CONTENT_TYPE_APP_DATA		23
#define CONTENT_TYPE_HEARTBEAT		24
#define CONTENT_TYPE_KEY_CONTEXT	32
#define CONTENT_TYPE_ERROR		127

#define TLS_RCV_ST_READ_DONE		0xF2
#define TLS_RCV_ST_READ_NOBODY		0xF3

#define IOCTL_TLSOM_SET_TLS_CONTEXT	201
#define IOCTL_TLSOM_GET_TLS_TOM		202
#define IOCTL_TLSOM_CLR_TLS_TOM		203
#define IOCTL_TLSOM_CLR_QUIES		204

#define GCM_TAG_SIZE			16
#define AEAD_EXPLICIT_DATA_SIZE		8
#define TLS_HEADER_LENGTH		5
#define DTLS_HEADER_LENGTH		13
#define TP_TX_PG_SZ			65536
#define FC_TP_PLEN_MAX			17408

#define ID_TLS_SKB			243
#define KEYS_COPIED			1
#define SKB_HAS_KEYS			1

#define SALT_SIZE			4
#define IPAD_SIZE			64
#define OPAD_SIZE			64
#define KEY_SIZE			32
#define CIPHER_BLOCK_SIZE		16
#define HDR_KCTX_SIZE   (IPAD_SIZE + OPAD_SIZE + KEY_SIZE)

#define TLS_TX_KEY_CTX_MAX		176  /* Immediate keys */
#define KEY_IN_DDR_SIZE			16
#define KEY_IN_SGL_SIZE			16
#define IV_IN_SGL_SIZE			16
#define MAX_IVS_PAGE			256 /* 16B IVs in PAGE */
#define TLS_WR_CPL_LEN \
		(sizeof(struct fw_tlstx_data_wr) + \
		 sizeof(struct cpl_tx_tls_sfo))
#define TLS_TX_HEADER_LEN \
		(TLS_WR_CPL_LEN + \
		(sizeof(struct sge_opaque_hdr)))
#define TLS_KEY_COMMON_OFST (sizeof(struct tls_tx_ctxt) + \
			     sizeof(struct tls_rx_ctxt))
#define TLS_KEY_COMMON_SZ (sizeof(struct tls_key_context) - \
			   TLS_KEY_COMMON_OFST)
#define TLS_KEY_TX_CONTEXT (sizeof(struct tls_tx_ctxt))
#define TLS_KEY_RX_CONTEXT (sizeof(struct tls_rx_ctxt))
#define TLS_KEY_CONTEXT_SZ ALIGN(TLS_KEY_TX_CONTEXT, 32)

#define DEFAULT_PRNG_KSZ		16
#define DEFAULT_BLK_SZ			16

/* Key Context Programming Operation type */
#define KEY_WRITE_RX			0x1
#define KEY_WRITE_TX			0x2
#define KEY_DELETE_RX			0x4
#define KEY_DELETE_TX			0x8

/* MAC KEY SIZE */
#define SHA_NOP				0
#define SHA_GHASH			16
#define SHA_224				28
#define SHA_256				32
#define SHA_384				48
#define SHA_512				64
#define SHA1				20

/* CIPHER KEY SIZE */
#define AES_NOP				0
#define AES_128				16
#define AES_192				24
#define AES_256				32

enum {
	KEY_SUCCESS = 1,
	KEY_FAILURE,
};

enum {
	TLS_1_2_VERSION,
	TLS_1_1_VERSION,
	DTLS_1_2_VERSION,
	TLS_VERSION_MAX,
};

enum {
	CH_EVP_CIPH_STREAM_CIPHER,
	CH_EVP_CIPH_CBC_MODE,
	CH_EVP_CIPH_GCM_MODE,
	CH_EVP_CIPH_CTR_MODE,
};

enum {
	TLS_SFO_WR_CONTEXTLOC_DSGL,
	TLS_SFO_WR_CONTEXTLOC_IMMEDIATE,
	TLS_SFO_WR_CONTEXTLOC_DDR,
};

enum {
	CPL_TX_TLS_SFO_TYPE_CCS,
	CPL_TX_TLS_SFO_TYPE_ALERT,
	CPL_TX_TLS_SFO_TYPE_HANDSHAKE,
	CPL_TX_TLS_SFO_TYPE_DATA,
	CPL_TX_TLS_SFO_TYPE_HEARTBEAT,
};

enum {
	CH_CK_SIZE_128,
	CH_CK_SIZE_192,
	CH_CK_SIZE_256,
	CH_CK_SIZE_NOP,
};

enum {
	CH_MK_SIZE_128,
	CH_MK_SIZE_160,
	CH_MK_SIZE_192,
	CH_MK_SIZE_256,
	CH_MK_SIZE_512,
	CH_MK_SIZE_NOP,
};

#define S_KEY_CLR_LOC           4
#define M_KEY_CLR_LOC           0xf
#define V_KEY_CLR_LOC(x)        ((x) << S_KEY_CLR_LOC)
#define G_KEY_CLR_LOC(x)        (((x) >> S_KEY_CLR_LOC) & M_KEY_CLR_LOC)
#define F_KEY_CLR_LOC           V_KEY_CLR_LOC(1U)

#define S_KEY_GET_LOC           0
#define M_KEY_GET_LOC           0xf
#define V_KEY_GET_LOC(x)        ((x) << S_KEY_GET_LOC)
#define G_KEY_GET_LOC(x)        (((x) >> S_KEY_GET_LOC) & M_KEY_GET_LOC)
#define F_KEY_GET_LOC           V_KEY_GET_LOC(1U)

struct tls_tx_ctxt {
	unsigned char salt[SALT_SIZE];
	unsigned char key[KEY_SIZE];
	unsigned char ipad[IPAD_SIZE];
	unsigned char opad[OPAD_SIZE];
};

struct tls_rx_ctxt {
	unsigned char salt[SALT_SIZE];
	unsigned char key[KEY_SIZE];
	unsigned char ipad[IPAD_SIZE];
	unsigned char opad[OPAD_SIZE];
};

struct tls_ofld_state {
	unsigned char enc_mode;
	unsigned char mac_mode;
	unsigned char key_loc;
	unsigned char ofld_mode;
	unsigned char auth_mode;
	unsigned char resv[3];
};

struct tls_key_context {
	struct tls_tx_ctxt tx;
	struct tls_rx_ctxt rx;

	unsigned char l_p_key;
	unsigned char hmac_ctrl;
	unsigned char mac_first;
	unsigned char iv_size;
	unsigned char iv_ctrl;
	unsigned char iv_algo;
	unsigned char tx_seq_no;
	unsigned char rx_seq_no;

	struct tls_ofld_state state;

	unsigned int tx_key_info_size;
	unsigned int rx_key_info_size;
	int frag_size;
	unsigned int mac_secret_size;
	unsigned int cipher_secret_size;
	int proto_ver;
	unsigned int sock_fd;
	unsigned short dtls_epoch;
	unsigned short rsv;
};

struct tls_key_location {
	unsigned int sock_fd;
	unsigned int key_location;
};

#define SCMD_ENCDECCTRL_ENCRYPT 0
#define SCMD_ENCDECCTRL_DECRYPT 1

#define SCMD_CIPH_MODE_NOP			0
#define SCMD_CIPH_MODE_AES_CBC			1
#define SCMD_CIPH_MODE_AES_GCM			2
#define SCMD_CIPH_MODE_AES_CTR			3
#define SCMD_CIPH_MODE_AES_GEN			4
#define SCMD_CIPH_MODE_AES_CCM			7

struct tls_scmd {
	__be32 seqno_numivs;
	__be32 ivgen_hdrlen;
};

struct tls_send_data {
	int left;
	int offset;
	int type;
};

struct key_map {
	unsigned long *addr;
	unsigned int start;
	unsigned int available;
	unsigned int size;
	spinlock_t lock;
} __packed;

struct tls_ofld_info {
	struct sock *sk;
	struct tls_key_context *k_ctx;
	struct sk_buff_head sk_recv_queue;
	struct delayed_work hsk_work;
	unsigned short key_prog;
	char tx_qid;
	char tls_offload;
	char key_location;
	char key_rqst;
	unsigned short resv;
	unsigned short key_reply;
	unsigned short pld_len;
	unsigned short recv_pld_len;
	int key_len;
	int mac_length;
	int copied_imm_ivs_size;
	int tx_key_id;
	int rx_key_id;
	unsigned int copied_seq;
	unsigned int hw_rnxt_off;
	unsigned int hw_prnxt_off;
	unsigned int hw_rxmod_cur;
	unsigned long long tx_seq_no;
	char computation_done;
#define TLS_CLIENT_WQ_CLR	0x1
	char work_done;
	unsigned short fcplenmax;
	unsigned short adjusted_plen;
	unsigned short expn_per_ulp;
	unsigned short pdus_per_ulp;
	struct tls_scmd scmd0;
	struct tls_send_data sd;
	struct kref kref;
};

struct tls_key_req {
	__be32 wr_hi;
	__be32 wr_mid;
        __be32 ftid;
        __u8   reneg_to_write_rx;
        __u8   protocol;
        __be16 mfs;
	/* master command */
	__be32 cmd;
	__be32 len16;             /* command length */
	__be32 dlen;              /* data length in 32-byte units */
	__be32 kaddr;
	/* sub-command */
	__be32 sc_more;
	__be32 sc_len;
}__packed;

struct tls_keyctx {
        union key_ctx {
                struct tx_keyctx_hdr {
                        __u8   ctxlen;
                        __u8   r2;
                        __be16 dualck_to_txvalid;
                        __u8   txsalt[4];
                        __be64 r5;
                } txhdr;
                struct rx_keyctx_hdr {
                        __u8   flitcnt_hmacctrl;
                        __u8   protover_ciphmode;
                        __u8   authmode_to_rxvalid;
                        __u8   ivpresent_to_rxmk_size;
                        __u8   rxsalt[4];
                        __be64 ivinsert_to_authinsrt;
                } rxhdr;
        } u;
        struct keys {
                __u8   edkey[32];
                __u8   ipad[64];
                __u8   opad[64];
        } keys;
};

#define S_TLS_KEYCTX_TX_WR_DUALCK    12
#define M_TLS_KEYCTX_TX_WR_DUALCK    0x1
#define V_TLS_KEYCTX_TX_WR_DUALCK(x) ((x) << S_TLS_KEYCTX_TX_WR_DUALCK)
#define G_TLS_KEYCTX_TX_WR_DUALCK(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_DUALCK) & M_TLS_KEYCTX_TX_WR_DUALCK)
#define F_TLS_KEYCTX_TX_WR_DUALCK    V_TLS_KEYCTX_TX_WR_DUALCK(1U)

#define S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT 11
#define M_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT)
#define G_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT) & \
     M_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT)
#define F_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT \
    V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_SALT_PRESENT 10
#define M_TLS_KEYCTX_TX_WR_SALT_PRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_SALT_PRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_SALT_PRESENT)
#define G_TLS_KEYCTX_TX_WR_SALT_PRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_SALT_PRESENT) & \
     M_TLS_KEYCTX_TX_WR_SALT_PRESENT)
#define F_TLS_KEYCTX_TX_WR_SALT_PRESENT \
    V_TLS_KEYCTX_TX_WR_SALT_PRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_TXCK_SIZE 6
#define M_TLS_KEYCTX_TX_WR_TXCK_SIZE 0xf
#define V_TLS_KEYCTX_TX_WR_TXCK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXCK_SIZE)
#define G_TLS_KEYCTX_TX_WR_TXCK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXCK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_TXCK_SIZE)

#define S_TLS_KEYCTX_TX_WR_TXMK_SIZE 2
#define M_TLS_KEYCTX_TX_WR_TXMK_SIZE 0xf
#define V_TLS_KEYCTX_TX_WR_TXMK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXMK_SIZE)
#define G_TLS_KEYCTX_TX_WR_TXMK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXMK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_TXMK_SIZE)

#define S_TLS_KEYCTX_TX_WR_TXVALID   0
#define M_TLS_KEYCTX_TX_WR_TXVALID   0x1
#define V_TLS_KEYCTX_TX_WR_TXVALID(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXVALID)
#define G_TLS_KEYCTX_TX_WR_TXVALID(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXVALID) & M_TLS_KEYCTX_TX_WR_TXVALID)
#define F_TLS_KEYCTX_TX_WR_TXVALID   V_TLS_KEYCTX_TX_WR_TXVALID(1U)

#define S_TLS_KEYCTX_TX_WR_FLITCNT   3
#define M_TLS_KEYCTX_TX_WR_FLITCNT   0x1f
#define V_TLS_KEYCTX_TX_WR_FLITCNT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_FLITCNT)
#define G_TLS_KEYCTX_TX_WR_FLITCNT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_FLITCNT) & M_TLS_KEYCTX_TX_WR_FLITCNT)

#define S_TLS_KEYCTX_TX_WR_HMACCTRL  0
#define M_TLS_KEYCTX_TX_WR_HMACCTRL  0x7
#define V_TLS_KEYCTX_TX_WR_HMACCTRL(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_HMACCTRL)
#define G_TLS_KEYCTX_TX_WR_HMACCTRL(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_HMACCTRL) & M_TLS_KEYCTX_TX_WR_HMACCTRL)

#define S_TLS_KEYCTX_TX_WR_PROTOVER  4
#define M_TLS_KEYCTX_TX_WR_PROTOVER  0xf
#define V_TLS_KEYCTX_TX_WR_PROTOVER(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_PROTOVER)
#define G_TLS_KEYCTX_TX_WR_PROTOVER(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_PROTOVER) & M_TLS_KEYCTX_TX_WR_PROTOVER)

#define S_TLS_KEYCTX_TX_WR_CIPHMODE  0
#define M_TLS_KEYCTX_TX_WR_CIPHMODE  0xf
#define V_TLS_KEYCTX_TX_WR_CIPHMODE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_CIPHMODE)
#define G_TLS_KEYCTX_TX_WR_CIPHMODE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_CIPHMODE) & M_TLS_KEYCTX_TX_WR_CIPHMODE)

#define S_TLS_KEYCTX_TX_WR_AUTHMODE  4
#define M_TLS_KEYCTX_TX_WR_AUTHMODE  0xf
#define V_TLS_KEYCTX_TX_WR_AUTHMODE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AUTHMODE)
#define G_TLS_KEYCTX_TX_WR_AUTHMODE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AUTHMODE) & M_TLS_KEYCTX_TX_WR_AUTHMODE)

#define S_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL 3
#define M_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL 0x1
#define V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL)
#define G_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL) & \
     M_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL)
#define F_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL \
    V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(1U)

#define S_TLS_KEYCTX_TX_WR_SEQNUMCTRL 1
#define M_TLS_KEYCTX_TX_WR_SEQNUMCTRL 0x3
#define V_TLS_KEYCTX_TX_WR_SEQNUMCTRL(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_SEQNUMCTRL)
#define G_TLS_KEYCTX_TX_WR_SEQNUMCTRL(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_SEQNUMCTRL) & \
     M_TLS_KEYCTX_TX_WR_SEQNUMCTRL)

#define S_TLS_KEYCTX_TX_WR_RXVALID   0
#define M_TLS_KEYCTX_TX_WR_RXVALID   0x1
#define V_TLS_KEYCTX_TX_WR_RXVALID(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_RXVALID)
#define G_TLS_KEYCTX_TX_WR_RXVALID(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_RXVALID) & M_TLS_KEYCTX_TX_WR_RXVALID)
#define F_TLS_KEYCTX_TX_WR_RXVALID   V_TLS_KEYCTX_TX_WR_RXVALID(1U)

#define S_TLS_KEYCTX_TX_WR_IVPRESENT 7
#define M_TLS_KEYCTX_TX_WR_IVPRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_IVPRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_IVPRESENT)
#define G_TLS_KEYCTX_TX_WR_IVPRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_IVPRESENT) & \
     M_TLS_KEYCTX_TX_WR_IVPRESENT)
#define F_TLS_KEYCTX_TX_WR_IVPRESENT V_TLS_KEYCTX_TX_WR_IVPRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT 6
#define M_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT)
#define G_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT) & \
     M_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT)
#define F_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT \
    V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_RXCK_SIZE 3
#define M_TLS_KEYCTX_TX_WR_RXCK_SIZE 0x7
#define V_TLS_KEYCTX_TX_WR_RXCK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_RXCK_SIZE)
#define G_TLS_KEYCTX_TX_WR_RXCK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_RXCK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_RXCK_SIZE)

#define S_TLS_KEYCTX_TX_WR_RXMK_SIZE 0
#define M_TLS_KEYCTX_TX_WR_RXMK_SIZE 0x7
#define V_TLS_KEYCTX_TX_WR_RXMK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_RXMK_SIZE)
#define G_TLS_KEYCTX_TX_WR_RXMK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_RXMK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_RXMK_SIZE)

#define S_TLS_KEYCTX_TX_WR_IVINSERT  55
#define M_TLS_KEYCTX_TX_WR_IVINSERT  0x1ffULL
#define V_TLS_KEYCTX_TX_WR_IVINSERT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_IVINSERT)
#define G_TLS_KEYCTX_TX_WR_IVINSERT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_IVINSERT) & M_TLS_KEYCTX_TX_WR_IVINSERT)

#define S_TLS_KEYCTX_TX_WR_AADSTRTOFST 47
#define M_TLS_KEYCTX_TX_WR_AADSTRTOFST 0xffULL
#define V_TLS_KEYCTX_TX_WR_AADSTRTOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AADSTRTOFST)
#define G_TLS_KEYCTX_TX_WR_AADSTRTOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AADSTRTOFST) & \
     M_TLS_KEYCTX_TX_WR_AADSTRTOFST)

#define S_TLS_KEYCTX_TX_WR_AADSTOPOFST 39
#define M_TLS_KEYCTX_TX_WR_AADSTOPOFST 0xffULL
#define V_TLS_KEYCTX_TX_WR_AADSTOPOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AADSTOPOFST)
#define G_TLS_KEYCTX_TX_WR_AADSTOPOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AADSTOPOFST) & \
     M_TLS_KEYCTX_TX_WR_AADSTOPOFST)

#define S_TLS_KEYCTX_TX_WR_CIPHERSRTOFST 30
#define M_TLS_KEYCTX_TX_WR_CIPHERSRTOFST 0x1ffULL
#define V_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_CIPHERSRTOFST)
#define G_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_CIPHERSRTOFST) & \
     M_TLS_KEYCTX_TX_WR_CIPHERSRTOFST)

#define S_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST 23
#define M_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST 0x7f
#define V_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST)
#define G_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST) & \
     M_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST)

#define S_TLS_KEYCTX_TX_WR_AUTHSRTOFST 14
#define M_TLS_KEYCTX_TX_WR_AUTHSRTOFST 0x1ff
#define V_TLS_KEYCTX_TX_WR_AUTHSRTOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AUTHSRTOFST)
#define G_TLS_KEYCTX_TX_WR_AUTHSRTOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AUTHSRTOFST) & \
     M_TLS_KEYCTX_TX_WR_AUTHSRTOFST)

#define S_TLS_KEYCTX_TX_WR_AUTHSTOPOFST 7
#define M_TLS_KEYCTX_TX_WR_AUTHSTOPOFST 0x7f
#define V_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AUTHSTOPOFST)
#define G_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AUTHSTOPOFST) & \
     M_TLS_KEYCTX_TX_WR_AUTHSTOPOFST)

#define S_TLS_KEYCTX_TX_WR_AUTHINSRT 0
#define M_TLS_KEYCTX_TX_WR_AUTHINSRT 0x7f
#define V_TLS_KEYCTX_TX_WR_AUTHINSRT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_AUTHINSRT)
#define G_TLS_KEYCTX_TX_WR_AUTHINSRT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_AUTHINSRT) & \
     M_TLS_KEYCTX_TX_WR_AUTHINSRT)


struct tls_hdr {
	__u8   type;
	__be16 version;
	__be16 length;
} __packed;

struct tlsrx_hdr_pkt {
	__u8   type;
	__be16 version;
	__be16 length;

	__be64 tls_seq;
	__be16 reserved1;
	__u8   res_to_mac_error;
} __packed;

struct dtls_hdr {
	__u8   type;
	__be16 version;
	__be64 epoch_seq; /* epoch [16bits] and seq [48 bits] */
	__be16 length;
} __packed;

struct dtlsrx_hdr_pkt {
	struct dtls_hdr dhdr;
	__be16 reserved1;
	__u8   res_to_mac_error;
} __packed;

/* XXX is there one of these somewhere? */
#define ceil(x, y) \
	({ unsigned long __x = (x), __y = (y); (__x + __y - 1) / __y; })

/* res_to_mac_error fields */
#define S_TLSRX_HDR_PKT_INTERNAL_ERROR   4
#define M_TLSRX_HDR_PKT_INTERNAL_ERROR   0x1
#define V_TLSRX_HDR_PKT_INTERNAL_ERROR(x) \
	((x) << S_TLSRX_HDR_PKT_INTERNAL_ERROR)
#define G_TLSRX_HDR_PKT_INTERNAL_ERROR(x) \
(((x) >> S_TLSRX_HDR_PKT_INTERNAL_ERROR) & M_TLSRX_HDR_PKT_INTERNAL_ERROR)
#define F_TLSRX_HDR_PKT_INTERNAL_ERROR   V_TLSRX_HDR_PKT_INTERNAL_ERROR(1U)

#define S_TLSRX_HDR_PKT_SPP_ERROR        3
#define M_TLSRX_HDR_PKT_SPP_ERROR        0x1
#define V_TLSRX_HDR_PKT_SPP_ERROR(x)     ((x) << S_TLSRX_HDR_PKT_SPP_ERROR)
#define G_TLSRX_HDR_PKT_SPP_ERROR(x)     \
(((x) >> S_TLSRX_HDR_PKT_SPP_ERROR) & M_TLSRX_HDR_PKT_SPP_ERROR)
#define F_TLSRX_HDR_PKT_SPP_ERROR        V_TLSRX_HDR_PKT_SPP_ERROR(1U)

#define S_TLSRX_HDR_PKT_CCDX_ERROR       2
#define M_TLSRX_HDR_PKT_CCDX_ERROR       0x1
#define V_TLSRX_HDR_PKT_CCDX_ERROR(x)    ((x) << S_TLSRX_HDR_PKT_CCDX_ERROR)
#define G_TLSRX_HDR_PKT_CCDX_ERROR(x)    \
(((x) >> S_TLSRX_HDR_PKT_CCDX_ERROR) & M_TLSRX_HDR_PKT_CCDX_ERROR)
#define F_TLSRX_HDR_PKT_CCDX_ERROR       V_TLSRX_HDR_PKT_CCDX_ERROR(1U)

#define S_TLSRX_HDR_PKT_PAD_ERROR        1
#define M_TLSRX_HDR_PKT_PAD_ERROR        0x1
#define V_TLSRX_HDR_PKT_PAD_ERROR(x)     ((x) << S_TLSRX_HDR_PKT_PAD_ERROR)
#define G_TLSRX_HDR_PKT_PAD_ERROR(x)     \
(((x) >> S_TLSRX_HDR_PKT_PAD_ERROR) & M_TLSRX_HDR_PKT_PAD_ERROR)
#define F_TLSRX_HDR_PKT_PAD_ERROR        V_TLSRX_HDR_PKT_PAD_ERROR(1U)

#define S_TLSRX_HDR_PKT_MAC_ERROR        0
#define M_TLSRX_HDR_PKT_MAC_ERROR        0x1
#define V_TLSRX_HDR_PKT_MAC_ERROR(x)     ((x) << S_TLSRX_HDR_PKT_MAC_ERROR)
#define G_TLSRX_HDR_PKT_MAC_ERROR(x)     \
(((x) >> S_TLSRX_HDR_PKT_MAC_ERROR) & M_TLSRX_HDR_PKT_MAC_ERROR)
#define F_TLSRX_HDR_PKT_MAC_ERROR        V_TLSRX_HDR_PKT_MAC_ERROR(1U)
#define M_TLSRX_HDR_PKT_ERROR		0x1F

#define S_FW_ULPTX_KEY_CTX_WR_AUTHINSRT 0
#define M_FW_ULPTX_KEY_CTX_WR_AUTHINSRT 0x7f
#define V_FW_ULPTX_KEY_CTX_WR_AUTHINSRT(x) \
	    ((x) << S_FW_ULPTX_KEY_CTX_WR_AUTHINSRT)
#define G_FW_ULPTX_KEY_CTX_WR_AUTHINSRT(x) \
	    (((x) >> S_FW_ULPTX_KEY_CTX_WR_AUTHINSRT) & \
	     M_FW_ULPTX_KEY_CTX_WR_AUTHINSRT)

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

int chelsio_tlsv4_recvmsg(struct sock *sk,
			  struct msghdr *msg, size_t len,
			  int nonblock, int flags, int *addr_len);
int is_tls_offload_skb(struct sock *sk, const struct sk_buff *skb);
int is_tls_offload(struct sock *sk);
int tls_clr_ofld_mode(struct sock *sk);
int tls_set_ofld_mode(struct sock *sk);
int tls_clr_quiesce(struct sock *sk);
int is_tls_sock(struct sock *sk, struct toedev *dev);
int tls_tx_key(struct sock *sk);
int tls_rx_key(struct sock *sk);
int program_key_context(struct sock *sk, struct tls_key_context *uk_ctx);
int release_tls_kctx(struct sock *sk);
void tls_offload_init(void *ctx);
int tls_wr_size(struct sock *sk, const struct sk_buff *skb, bool size);
struct sk_buff *alloc_tls_tx_skb(struct sock *sk, int size, bool zcopy);
void make_tlstx_data_wr(struct sock *sk, struct sk_buff *skb,
			int tls_imm, int tls_len, u32 credits);
int tls_header_read(struct tls_hdr *thdr, struct iov_iter *from);
void start_hndsk_work(struct sock *sk);
void stop_hndsk_work(struct sock *sk);
void clear_tls_keyid(struct sock *sk);

/* macros to handle TLS response */
#define S_CPL_FW4_MSG_TID    32
#define M_CPL_FW4_MSG_TID    0xFFFFFFFF
#define V_CPL_FW4_MSG_TID(x) ((x) << S_CPL_FW4_MSG_TID)
#define G_CPL_FW4_MSG_TID(x) \
	(((x) >> S_CPL_FW4_MSG_TID) & M_CPL_FW4_MSG_TID)
#define GET_TLS_TID(x)  (G_TID(G_CPL_FW4_MSG_TID(be64_to_cpu(x))))

#define S_CPL_FW4_MSG_KID    0
#define M_CPL_FW4_MSG_KID    0xFFFFFFFF
#define V_CPL_FW4_MSG_KID(x) ((x) << S_CPL_FW4_MSG_KID)
#define G_CPL_FW4_MSG_KID(x) \
	(((x) >> S_CPL_FW4_MSG_KID) & M_CPL_FW4_MSG_KID)
#define GET_TLS_KID(x)  (G_CPL_FW4_MSG_KID(be64_to_cpu(x)))

#define S_CPL_FW4_MSG_KOP    32
#define M_CPL_FW4_MSG_KOP    0xFFFFFFFF
#define V_CPL_FW4_MSG_KOP(x) ((x) << S_CPL_FW4_MSG_TOP)
#define G_CPL_FW4_MSG_KOP(x) \
	(((x) >> S_CPL_FW4_MSG_KOP) & M_CPL_FW4_MSG_KOP)
#define GET_TLS_KOP(x)  (G_CPL_FW4_MSG_KOP(be64_to_cpu(x)))

#define S_CPL_FW4_MSG_KST    16
#define M_CPL_FW4_MSG_KST    0xFFFF
#define V_CPL_FW4_MSG_KST(x) ((x) << S_CPL_FW4_MSG_KST)
#define G_CPL_FW4_MSG_KST(x) \
	(((x) >> S_CPL_FW4_MSG_KST) & M_CPL_FW4_MSG_KST)
#define GET_TLS_KST(x)  (G_CPL_FW4_MSG_KST(be64_to_cpu(x)))

#define S_CPL_FW4_MSG_FCPLEN   0
#define M_CPL_FW4_MSG_FCPLEN    0xFFFF
#define V_CPL_FW4_MSG_FCPLEN(x) ((x) << S_CPL_FW4_MSG_FCPLEN)
#define G_CPL_FW4_MSG_FCPLEN(x) \
                       (((x) >> S_CPL_FW4_MSG_FCPLEN) & M_CPL_FW4_MSG_FCPLEN)
#define GET_TLS_FCPLEN(x)  (G_CPL_FW4_MSG_FCPLEN(be64_to_cpu(x)))

#endif /* T4_TLS.H */
