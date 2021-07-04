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

#ifndef __CHCR_ALGO_H__
#define __CHCR_ALGO_H__

/* Crypto key context */
#define S_KEY_CONTEXT_CTX_LEN           24
#define M_KEY_CONTEXT_CTX_LEN           0xff
#define V_KEY_CONTEXT_CTX_LEN(x)        ((x) << S_KEY_CONTEXT_CTX_LEN)
#define G_KEY_CONTEXT_CTX_LEN(x) \
	(((x) >> S_KEY_CONTEXT_CTX_LEN) & M_KEY_CONTEXT_CTX_LEN)

#define S_KEY_CONTEXT_DUAL_CK      12
#define M_KEY_CONTEXT_DUAL_CK      0x1
#define V_KEY_CONTEXT_DUAL_CK(x)   ((x) << S_KEY_CONTEXT_DUAL_CK)
#define G_KEY_CONTEXT_DUAL_CK(x)   \
(((x) >> S_KEY_CONTEXT_DUAL_CK) & M_KEY_CONTEXT_DUAL_CK)
#define F_KEY_CONTEXT_DUAL_CK      V_KEY_CONTEXT_DUAL_CK(1U)

#define S_KEY_CONTEXT_SALT_PRESENT      10
#define M_KEY_CONTEXT_SALT_PRESENT      0x1
#define V_KEY_CONTEXT_SALT_PRESENT(x)   ((x) << S_KEY_CONTEXT_SALT_PRESENT)
#define G_KEY_CONTEXT_SALT_PRESENT(x)   \
	(((x) >> S_KEY_CONTEXT_SALT_PRESENT) & \
	 M_KEY_CONTEXT_SALT_PRESENT)
#define F_KEY_CONTEXT_SALT_PRESENT      V_KEY_CONTEXT_SALT_PRESENT(1U)

#define S_KEY_CONTEXT_VALID     0
#define M_KEY_CONTEXT_VALID     0x1
#define V_KEY_CONTEXT_VALID(x)  ((x) << S_KEY_CONTEXT_VALID)
#define G_KEY_CONTEXT_VALID(x)  \
	(((x) >> S_KEY_CONTEXT_VALID) & \
	 M_KEY_CONTEXT_VALID)
#define F_KEY_CONTEXT_VALID     V_KEY_CONTEXT_VALID(1U)

#define S_KEY_CONTEXT_CK_SIZE           6
#define M_KEY_CONTEXT_CK_SIZE           0xf
#define V_KEY_CONTEXT_CK_SIZE(x)        ((x) << S_KEY_CONTEXT_CK_SIZE)
#define G_KEY_CONTEXT_CK_SIZE(x)        \
	(((x) >> S_KEY_CONTEXT_CK_SIZE) & M_KEY_CONTEXT_CK_SIZE)

#define S_KEY_CONTEXT_MK_SIZE           2
#define M_KEY_CONTEXT_MK_SIZE           0xf
#define V_KEY_CONTEXT_MK_SIZE(x)        ((x) << S_KEY_CONTEXT_MK_SIZE)
#define G_KEY_CONTEXT_MK_SIZE(x)        \
	(((x) >> S_KEY_CONTEXT_MK_SIZE) & M_KEY_CONTEXT_MK_SIZE)

#define S_KEY_CONTEXT_OPAD_PRESENT      11
#define M_KEY_CONTEXT_OPAD_PRESENT      0x1
#define V_KEY_CONTEXT_OPAD_PRESENT(x)   ((x) << S_KEY_CONTEXT_OPAD_PRESENT)
#define G_KEY_CONTEXT_OPAD_PRESENT(x)   \
	(((x) >> S_KEY_CONTEXT_OPAD_PRESENT) & \
	 M_KEY_CONTEXT_OPAD_PRESENT)
#define F_KEY_CONTEXT_OPAD_PRESENT      V_KEY_CONTEXT_OPAD_PRESENT(1U)

#define CHCR_HASH_MAX_DIGEST_SIZE 64
#define CHCR_MAX_SHA_DIGEST_SIZE 64

#define IPSEC_TRUNCATED_ICV_SIZE 12
#define TLS_TRUNCATED_HMAC_SIZE 10
#define CBCMAC_DIGEST_SIZE 16
#define MAX_HASH_NAME 20

#define SHA1_INIT_STATE_5X4B    5
#define SHA256_INIT_STATE_8X4B  8
#define SHA512_INIT_STATE_8X8B  8
#define SHA1_INIT_STATE         SHA1_INIT_STATE_5X4B
#define SHA224_INIT_STATE       SHA256_INIT_STATE_8X4B
#define SHA256_INIT_STATE       SHA256_INIT_STATE_8X4B
#define SHA384_INIT_STATE       SHA512_INIT_STATE_8X8B
#define SHA512_INIT_STATE       SHA512_INIT_STATE_8X8B

#define DUMMY_BYTES 16

#define IPAD_DATA 0x36363636
#define OPAD_DATA 0x5c5c5c5c

#define TRANSHDR_SIZE(kctx_len)\
	(sizeof(struct chcr_wr) +\
	 kctx_len)
#define CIPHER_TRANSHDR_SIZE(kctx_len, sge_pairs) \
	(TRANSHDR_SIZE((kctx_len)) + (sge_pairs) +\
	 sizeof(struct cpl_rx_phys_dsgl) + AES_BLOCK_SIZE)
#define HASH_TRANSHDR_SIZE(kctx_len)\
	(TRANSHDR_SIZE(kctx_len) + DUMMY_BYTES)


#define FILL_SEC_CPL_OP_IVINSR(id, len, ofst)      \
	htonl( \
		V_CPL_TX_SEC_PDU_OPCODE(CPL_TX_SEC_PDU) | \
		V_CPL_TX_SEC_PDU_RXCHID((id)) | \
		V_CPL_TX_SEC_PDU_ACKFOLLOWS(0) | \
		V_CPL_TX_SEC_PDU_ULPTXLPBK(1) | \
	       V_CPL_TX_SEC_PDU_CPLLEN((len)) | \
	       V_CPL_TX_SEC_PDU_PLACEHOLDER(0) | \
	       V_CPL_TX_SEC_PDU_IVINSRTOFST((ofst)))

#define  FILL_SEC_CPL_CIPHERSTOP_HI(a_start, a_stop, c_start, c_stop_hi) \
	htonl( \
	       V_CPL_TX_SEC_PDU_AADSTART((a_start)) | \
	       V_CPL_TX_SEC_PDU_AADSTOP((a_stop)) | \
	       V_CPL_TX_SEC_PDU_CIPHERSTART((c_start)) | \
	       V_CPL_TX_SEC_PDU_CIPHERSTOP_HI((c_stop_hi)))

#define  FILL_SEC_CPL_AUTHINSERT(c_stop_lo, a_start, a_stop, a_inst) \
	htonl( \
	       V_CPL_TX_SEC_PDU_CIPHERSTOP_LO((c_stop_lo)) | \
		V_CPL_TX_SEC_PDU_AUTHSTART((a_start)) | \
		V_CPL_TX_SEC_PDU_AUTHSTOP((a_stop)) | \
		V_CPL_TX_SEC_PDU_AUTHINSERT((a_inst)))

#define  FILL_SEC_CPL_SCMD0_SEQNO(ctrl, seq, cmode, amode, opad, size)  \
		htonl( \
		V_SCMD_SEQ_NO_CTRL(0) | \
		V_SCMD_STATUS_PRESENT(0) | \
		V_SCMD_PROTO_VERSION(CHCR_SCMD_PROTO_VERSION_GENERIC) | \
		V_SCMD_ENC_DEC_CTRL((ctrl)) | \
		V_SCMD_CIPH_AUTH_SEQ_CTRL((seq)) | \
		V_SCMD_CIPH_MODE((cmode)) | \
		V_SCMD_AUTH_MODE((amode)) | \
		V_SCMD_HMAC_CTRL((opad)) | \
		V_SCMD_IV_SIZE((size)) | \
		V_SCMD_NUM_IVS(0))

#define FILL_SEC_CPL_IVGEN_HDRLEN(last, more, ctx_in, mac, ivdrop, len) htonl( \
		V_SCMD_ENB_DBGID(0) | \
		V_SCMD_IV_GEN_CTRL(0) | \
		V_SCMD_LAST_FRAG((last)) | \
		V_SCMD_MORE_FRAGS((more)) | \
		V_SCMD_TLS_COMPPDU(0) | \
		V_SCMD_KEY_CTX_INLINE((ctx_in)) | \
		V_SCMD_TLS_FRAG_ENABLE(0) | \
		V_SCMD_MAC_ONLY((mac)) |  \
		V_SCMD_AADIVDROP((ivdrop)) | \
		V_SCMD_HDR_LEN((len)))

#define  FILL_KEY_CTX_HDR(ck_size, mk_size, d_ck, opad, ctx_len) \
		htonl(V_KEY_CONTEXT_VALID(1) | \
		      V_KEY_CONTEXT_CK_SIZE((ck_size)) | \
		      V_KEY_CONTEXT_MK_SIZE(mk_size) | \
		      V_KEY_CONTEXT_DUAL_CK((d_ck)) | \
		      V_KEY_CONTEXT_OPAD_PRESENT((opad)) | \
		      V_KEY_CONTEXT_SALT_PRESENT(1) | \
		      V_KEY_CONTEXT_CTX_LEN((ctx_len)))

#define FILL_WR_OP_CCTX_SIZE \
		htonl( \
			V_FW_CRYPTO_LOOKASIDE_WR_OPCODE( \
			FW_CRYPTO_LOOKASIDE_WR) | \
			V_FW_CRYPTO_LOOKASIDE_WR_COMPL(0) | \
			V_FW_CRYPTO_LOOKASIDE_WR_IMM_LEN((0)) | \
			V_FW_CRYPTO_LOOKASIDE_WR_CCTX_LOC(0) | \
			V_FW_CRYPTO_LOOKASIDE_WR_CCTX_SIZE(0))

#define FILL_WR_RX_Q_ID(cid, qid, lcb, fid) \
		htonl( \
			V_FW_CRYPTO_LOOKASIDE_WR_RX_CHID((cid)) | \
			V_FW_CRYPTO_LOOKASIDE_WR_RX_Q_ID((qid)) | \
			V_FW_CRYPTO_LOOKASIDE_WR_LCB((lcb)) | \
			V_FW_CRYPTO_LOOKASIDE_WR_IV((IV_NOP)) | \
			V_FW_CRYPTO_LOOKASIDE_WR_FQIDX(fid))

#define FILL_ULPTX_CMD_DEST(cid, qid) \
	htonl(V_ULPTX_CMD(ULP_TX_PKT) | \
			V_ULP_TXPKT_DEST(0) | \
			V_ULP_TXPKT_DATAMODIFY(0) | \
			V_ULP_TXPKT_CHANNELID((cid)) | \
			V_ULP_TXPKT_RO(1) | \
			V_ULP_TXPKT_FID(qid))

#define KEYCTX_ALIGN_PAD(bs) ({unsigned int _bs = (bs);\
			_bs == SHA1_DIGEST_SIZE ? 12 : 0; })

#define FILL_PLD_SIZE_HASH_SIZE(payload_sgl_len, sgl_lengths, total_frags) \
	htonl(V_FW_CRYPTO_LOOKASIDE_WR_PLD_SIZE(payload_sgl_len ? \
						sgl_lengths[total_frags] : 0) |\
	      V_FW_CRYPTO_LOOKASIDE_WR_HASH_SIZE(0))

#define FILL_LEN_PKD(calc_tx_flits_ofld, skb) \
	htonl(V_FW_CRYPTO_LOOKASIDE_WR_LEN16(DIV_ROUND_UP((\
					   calc_tx_flits_ofld(skb) * 8), 16)))

#define FILL_CMD_MORE(immdatalen) htonl(V_ULPTX_CMD(ULP_TX_SC_IMM) |\
					V_ULP_TX_SC_MORE((immdatalen)))
#define MAX_NK 8
#define MAX_DSGL_ENT			32
#define MIN_AUTH_SG			1 /* IV */
#define MIN_GCM_SG			1 /* IV */
#define MIN_DIGEST_SG			1 /*Partial Buffer*/
#define MIN_CCM_SG			1 /*IV+B0*/
#define CIP_SPACE_LEFT(len) \
	((SGE_MAX_WR_LEN - CIP_WR_MIN_LEN - (len)))
#define HASH_SPACE_LEFT(len) \
	((SGE_MAX_WR_LEN - HASH_WR_MIN_LEN - (len)))

struct algo_param {
	unsigned int auth_mode;
	unsigned int mk_size;
	unsigned int result_size;
};

struct hash_wr_param {
	struct algo_param alg_prm;
	unsigned int opad_needed;
	unsigned int more;
	unsigned int last;
	unsigned int kctx_len;
	unsigned int sg_len;
	unsigned int bfr_len;
	unsigned int hash_size;
	u64 scmd1;
};

struct cipher_wr_param {
	struct skcipher_request *req;
	char *iv;
	int bytes;
	unsigned short qid;
};
enum {
	AES_KEYLENGTH_128BIT = 128,
	AES_KEYLENGTH_192BIT = 192,
	AES_KEYLENGTH_256BIT = 256
};

enum {
	KEYLENGTH_3BYTES = 3,
	KEYLENGTH_4BYTES = 4,
	KEYLENGTH_6BYTES = 6,
	KEYLENGTH_8BYTES = 8
};

enum {
	NUMBER_OF_ROUNDS_10 = 10,
	NUMBER_OF_ROUNDS_12 = 12,
	NUMBER_OF_ROUNDS_14 = 14,
};

/*
 * CCM defines values of 4, 6, 8, 10, 12, 14, and 16 octets,
 * where they indicate the size of the integrity check value (ICV)
 */
enum {
	ICV_4  = 4,
	ICV_6  = 6,
	ICV_8  = 8,
	ICV_10 = 10,
	ICV_12 = 12,
	ICV_13 = 13,
	ICV_14 = 14,
	ICV_15 = 15,
	ICV_16 = 16
};

struct phys_sge_pairs {
	__be16 len[8];
	__be64 addr[8];
};


static const u32 chcr_sha1_init[SHA1_DIGEST_SIZE / 4] = {
		SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4,
};

static const u32 chcr_sha224_init[SHA256_DIGEST_SIZE / 4] = {
		SHA224_H0, SHA224_H1, SHA224_H2, SHA224_H3,
		SHA224_H4, SHA224_H5, SHA224_H6, SHA224_H7,
};

static const u32 chcr_sha256_init[SHA256_DIGEST_SIZE / 4] = {
		SHA256_H0, SHA256_H1, SHA256_H2, SHA256_H3,
		SHA256_H4, SHA256_H5, SHA256_H6, SHA256_H7,
};

static const u64 chcr_sha384_init[SHA512_DIGEST_SIZE / 8] = {
		SHA384_H0, SHA384_H1, SHA384_H2, SHA384_H3,
		SHA384_H4, SHA384_H5, SHA384_H6, SHA384_H7,
};

static const u64 chcr_sha512_init[SHA512_DIGEST_SIZE / 8] = {
		SHA512_H0, SHA512_H1, SHA512_H2, SHA512_H3,
		SHA512_H4, SHA512_H5, SHA512_H6, SHA512_H7,
};

static inline void copy_hash_init_values(char *key, int digestsize)
{
	u8 i;
	__be32 *dkey = (__be32 *)key;
	u64 *ldkey = (u64 *)key;
	__be64 *sha384 = (__be64 *)chcr_sha384_init;
	__be64 *sha512 = (__be64 *)chcr_sha512_init;

	switch (digestsize) {
	case SHA1_DIGEST_SIZE:
		for (i = 0; i < SHA1_INIT_STATE; i++)
			dkey[i] = cpu_to_be32(chcr_sha1_init[i]);
		break;
	case SHA224_DIGEST_SIZE:
		for (i = 0; i < SHA224_INIT_STATE; i++)
			dkey[i] = cpu_to_be32(chcr_sha224_init[i]);
		break;
	case SHA256_DIGEST_SIZE:
		for (i = 0; i < SHA256_INIT_STATE; i++)
			dkey[i] = cpu_to_be32(chcr_sha256_init[i]);
		break;
	case SHA384_DIGEST_SIZE:
		for (i = 0; i < SHA384_INIT_STATE; i++)
			ldkey[i] = be64_to_cpu(sha384[i]);
		break;
	case SHA512_DIGEST_SIZE:
		for (i = 0; i < SHA512_INIT_STATE; i++)
			ldkey[i] = be64_to_cpu(sha512[i]);
		break;
	}
}

static const u8 sgl_lengths[20] = {
	0, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 12, 13, 13, 14, 15
};

/* Number of len fields(8) * size of one addr field */
#define PHYSDSGL_MAX_LEN_SIZE 16

static inline u16 get_space_for_phys_dsgl(unsigned int sgl_entr)
{
	/* len field size + addr field size */
	return ((sgl_entr >> 3) + ((sgl_entr % 8) ?
				   1 : 0)) * PHYSDSGL_MAX_LEN_SIZE +
		(sgl_entr << 3) + ((sgl_entr % 2 ? 1 : 0) << 3);
}

/* The AES s-transform matrix (s-box). */
static const u8 aes_sbox[256] = {
	99,  124, 119, 123, 242, 107, 111, 197, 48,  1,   103, 43,  254, 215,
	171, 118, 202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175,
	156, 164, 114, 192, 183, 253, 147, 38,  54,  63,  247, 204, 52,  165,
	229, 241, 113, 216, 49,  21, 4,   199, 35,  195, 24,  150, 5, 154, 7,
	18,  128, 226, 235, 39,  178, 117, 9,   131, 44,  26,  27,  110, 90,
	160, 82,  59,  214, 179, 41,  227, 47,  132, 83,  209, 0,   237, 32,
	252, 177, 91,  106, 203, 190, 57,  74,  76,  88,  207, 208, 239, 170,
	251, 67,  77,  51,  133, 69,  249, 2,   127, 80,  60,  159, 168, 81,
	163, 64,  143, 146, 157, 56,  245, 188, 182, 218, 33,  16,  255, 243,
	210, 205, 12,  19,  236, 95,  151, 68,  23,  196, 167, 126, 61,  100,
	93,  25,  115, 96,  129, 79,  220, 34,  42,  144, 136, 70,  238, 184,
	20,  222, 94,  11,  219, 224, 50,  58,  10,  73,  6,   36,  92,  194,
	211, 172, 98,  145, 149, 228, 121, 231, 200, 55,  109, 141, 213, 78,
	169, 108, 86,  244, 234, 101, 122, 174, 8, 186, 120, 37,  46,  28, 166,
	180, 198, 232, 221, 116, 31,  75,  189, 139, 138, 112, 62,  181, 102,
	72,  3,   246, 14,  97,  53,  87,  185, 134, 193, 29,  158, 225, 248,
	152, 17,  105, 217, 142, 148, 155, 30,  135, 233, 206, 85,  40,  223,
	140, 161, 137, 13,  191, 230, 66,  104, 65,  153, 45,  15,  176, 84,
	187, 22
};

static inline u32 aes_ks_subword(const u32 w)
{
	u8 bytes[4];

	*(u32 *)(&bytes[0]) = w;
	bytes[0] = aes_sbox[bytes[0]];
	bytes[1] = aes_sbox[bytes[1]];
	bytes[2] = aes_sbox[bytes[2]];
	bytes[3] = aes_sbox[bytes[3]];
	return *(u32 *)(&bytes[0]);
}

#endif /* __CHCR_ALGO_H__ */
