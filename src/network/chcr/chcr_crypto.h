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

#ifndef __CHCR_CRYPTO_H__
#define __CHCR_CRYPTO_H__

#define GHASH_BLOCK_SIZE    16
#define GHASH_DIGEST_SIZE   16

#define CCM_B0_SIZE             16
#define CCM_AAD_FIELD_SIZE      2
// 511 - 16(For IV)
#define T6_MAX_AAD_SIZE 495


/* Define following if h/w is not dropping the AAD and IV data before
 * giving the processed data
 */

#define CHCR_CRA_PRIORITY 500
#define CHCR_AEAD_PRIORITY 6000
#define CHCR_AES_MAX_KEY_LEN  (2 * (AES_MAX_KEY_SIZE)) /* consider xts */
#define CHCR_MAX_CRYPTO_IV_LEN 16 /* AES IV len */

#define CHCR_MAX_AUTHENC_AES_KEY_LEN 32 /* max aes key length*/
#define CHCR_MAX_AUTHENC_SHA_KEY_LEN 128 /* max sha key length*/

#define CHCR_GIVENCRYPT_OP 2
/* CPL/SCMD parameters */

#define CHCR_ENCRYPT_OP 0
#define CHCR_DECRYPT_OP 1

#define CHCR_SCMD_SEQ_NO_CTRL_32BIT     1
#define CHCR_SCMD_SEQ_NO_CTRL_48BIT     2
#define CHCR_SCMD_SEQ_NO_CTRL_64BIT     3

#define CHCR_SCMD_PROTO_VERSION_GENERIC 4

#define CHCR_SCMD_AUTH_CTRL_AUTH_CIPHER 0
#define CHCR_SCMD_AUTH_CTRL_CIPHER_AUTH 1

#define CHCR_SCMD_CIPHER_MODE_NOP               0
#define CHCR_SCMD_CIPHER_MODE_AES_CBC           1
#define CHCR_SCMD_CIPHER_MODE_AES_GCM           2
#define CHCR_SCMD_CIPHER_MODE_AES_CTR           3
#define CHCR_SCMD_CIPHER_MODE_GENERIC_AES       4
#define CHCR_SCMD_CIPHER_MODE_AES_XTS           6
#define CHCR_SCMD_CIPHER_MODE_AES_CCM           7

#define CHCR_SCMD_AUTH_MODE_NOP             0
#define CHCR_SCMD_AUTH_MODE_SHA1            1
#define CHCR_SCMD_AUTH_MODE_SHA224          2
#define CHCR_SCMD_AUTH_MODE_SHA256          3
#define CHCR_SCMD_AUTH_MODE_GHASH           4
#define CHCR_SCMD_AUTH_MODE_SHA512_224      5
#define CHCR_SCMD_AUTH_MODE_SHA512_256      6
#define CHCR_SCMD_AUTH_MODE_SHA512_384      7
#define CHCR_SCMD_AUTH_MODE_SHA512_512      8
#define CHCR_SCMD_AUTH_MODE_CBCMAC          9
#define CHCR_SCMD_AUTH_MODE_CMAC            10

#define CHCR_SCMD_HMAC_CTRL_NOP             0
#define CHCR_SCMD_HMAC_CTRL_NO_TRUNC        1
#define CHCR_SCMD_HMAC_CTRL_TRUNC_RFC4366   2
#define CHCR_SCMD_HMAC_CTRL_IPSEC_96BIT     3
#define CHCR_SCMD_HMAC_CTRL_PL1		    4
#define CHCR_SCMD_HMAC_CTRL_PL2		    5
#define CHCR_SCMD_HMAC_CTRL_PL3		    6
#define CHCR_SCMD_HMAC_CTRL_DIV2	    7
#define VERIFY_HW 0
#define VERIFY_SW 1

#define CHCR_SCMD_IVGEN_CTRL_HW             0
#define CHCR_SCMD_IVGEN_CTRL_SW             1
/* This are not really mac key size. They are intermediate values
 * of sha engine and its size
 */
#define CHCR_KEYCTX_MAC_KEY_SIZE_128        0
#define CHCR_KEYCTX_MAC_KEY_SIZE_160        1
#define CHCR_KEYCTX_MAC_KEY_SIZE_192        2
#define CHCR_KEYCTX_MAC_KEY_SIZE_256        3
#define CHCR_KEYCTX_MAC_KEY_SIZE_512        4
#define CHCR_KEYCTX_CIPHER_KEY_SIZE_128     0
#define CHCR_KEYCTX_CIPHER_KEY_SIZE_192     1
#define CHCR_KEYCTX_CIPHER_KEY_SIZE_256     2
#define CHCR_KEYCTX_NO_KEY                  15

#define CHCR_CPL_FW4_PLD_IV_OFFSET          (5 * 64) /* bytes. flt #5 and #6 */
#define CHCR_CPL_FW4_PLD_HASH_RESULT_OFFSET (7 * 64) /* bytes. flt #7 */
#define CHCR_CPL_FW4_PLD_DATA_SIZE          (4 * 64) /* bytes. flt #4 to #7 */

#define KEY_CONTEXT_HDR_SALT_AND_PAD	    16
#define flits_to_bytes(x)  (x * 8)

#define IV_NOP                  0
#define IV_IMMEDIATE            1
#define IV_DSGL			2

#define AEAD_H_SIZE             16

#define CRYPTO_ALG_SUB_TYPE_MASK            0x0f000000
#define CRYPTO_ALG_SUB_TYPE_HASH_HMAC       0x01000000
#define CRYPTO_ALG_SUB_TYPE_AEAD_RFC4106    0x02000000
#define CRYPTO_ALG_SUB_TYPE_AEAD_GCM	    0x03000000
#define CRYPTO_ALG_SUB_TYPE_CBC_SHA	    0x04000000
#define CRYPTO_ALG_SUB_TYPE_AEAD_CCM        0x05000000
#define CRYPTO_ALG_SUB_TYPE_AEAD_RFC4309    0x06000000
#define CRYPTO_ALG_SUB_TYPE_CBC_NULL	    0x07000000
#define CRYPTO_ALG_SUB_TYPE_CTR             0x08000000
#define CRYPTO_ALG_SUB_TYPE_CTR_RFC3686     0x09000000
#define CRYPTO_ALG_SUB_TYPE_XTS		    0x0a000000
#define CRYPTO_ALG_SUB_TYPE_CBC		    0x0b000000
#define CRYPTO_ALG_SUB_TYPE_CTR_SHA	    0x0c000000
#define CRYPTO_ALG_SUB_TYPE_CTR_NULL   0x0d000000
#define CRYPTO_ALG_TYPE_HMAC (CRYPTO_ALG_TYPE_AHASH |\
			CRYPTO_ALG_SUB_TYPE_HASH_HMAC)

#define MAX_SCRATCH_PAD_SIZE    32
#define CHCR_HASH_MAX_BLOCK_SIZE_64  64
#define CHCR_HASH_MAX_BLOCK_SIZE_128 128
#define CHCR_SRC_SG_SIZE (0x10000 - sizeof(int))
#define CHCR_DST_SG_SIZE 2048

/* Aligned to 128 bit boundary */
/* Copied fro gf128mul.c */
#define gf128mul_dat(q) { \
	q(0x00), q(0x01), q(0x02), q(0x03), q(0x04), q(0x05), q(0x06), q(0x07),\
	q(0x08), q(0x09), q(0x0a), q(0x0b), q(0x0c), q(0x0d), q(0x0e), q(0x0f),\
	q(0x10), q(0x11), q(0x12), q(0x13), q(0x14), q(0x15), q(0x16), q(0x17),\
	q(0x18), q(0x19), q(0x1a), q(0x1b), q(0x1c), q(0x1d), q(0x1e), q(0x1f),\
	q(0x20), q(0x21), q(0x22), q(0x23), q(0x24), q(0x25), q(0x26), q(0x27),\
	q(0x28), q(0x29), q(0x2a), q(0x2b), q(0x2c), q(0x2d), q(0x2e), q(0x2f),\
	q(0x30), q(0x31), q(0x32), q(0x33), q(0x34), q(0x35), q(0x36), q(0x37),\
	q(0x38), q(0x39), q(0x3a), q(0x3b), q(0x3c), q(0x3d), q(0x3e), q(0x3f),\
	q(0x40), q(0x41), q(0x42), q(0x43), q(0x44), q(0x45), q(0x46), q(0x47),\
	q(0x48), q(0x49), q(0x4a), q(0x4b), q(0x4c), q(0x4d), q(0x4e), q(0x4f),\
	q(0x50), q(0x51), q(0x52), q(0x53), q(0x54), q(0x55), q(0x56), q(0x57),\
	q(0x58), q(0x59), q(0x5a), q(0x5b), q(0x5c), q(0x5d), q(0x5e), q(0x5f),\
	q(0x60), q(0x61), q(0x62), q(0x63), q(0x64), q(0x65), q(0x66), q(0x67),\
	q(0x68), q(0x69), q(0x6a), q(0x6b), q(0x6c), q(0x6d), q(0x6e), q(0x6f),\
	q(0x70), q(0x71), q(0x72), q(0x73), q(0x74), q(0x75), q(0x76), q(0x77),\
	q(0x78), q(0x79), q(0x7a), q(0x7b), q(0x7c), q(0x7d), q(0x7e), q(0x7f),\
	q(0x80), q(0x81), q(0x82), q(0x83), q(0x84), q(0x85), q(0x86), q(0x87),\
	q(0x88), q(0x89), q(0x8a), q(0x8b), q(0x8c), q(0x8d), q(0x8e), q(0x8f),\
	q(0x90), q(0x91), q(0x92), q(0x93), q(0x94), q(0x95), q(0x96), q(0x97),\
	q(0x98), q(0x99), q(0x9a), q(0x9b), q(0x9c), q(0x9d), q(0x9e), q(0x9f),\
	q(0xa0), q(0xa1), q(0xa2), q(0xa3), q(0xa4), q(0xa5), q(0xa6), q(0xa7),\
	q(0xa8), q(0xa9), q(0xaa), q(0xab), q(0xac), q(0xad), q(0xae), q(0xaf),\
	q(0xb0), q(0xb1), q(0xb2), q(0xb3), q(0xb4), q(0xb5), q(0xb6), q(0xb7),\
	q(0xb8), q(0xb9), q(0xba), q(0xbb), q(0xbc), q(0xbd), q(0xbe), q(0xbf),\
	q(0xc0), q(0xc1), q(0xc2), q(0xc3), q(0xc4), q(0xc5), q(0xc6), q(0xc7),\
	q(0xc8), q(0xc9), q(0xca), q(0xcb), q(0xcc), q(0xcd), q(0xce), q(0xcf),\
	q(0xd0), q(0xd1), q(0xd2), q(0xd3), q(0xd4), q(0xd5), q(0xd6), q(0xd7),\
	q(0xd8), q(0xd9), q(0xda), q(0xdb), q(0xdc), q(0xdd), q(0xde), q(0xdf),\
	q(0xe0), q(0xe1), q(0xe2), q(0xe3), q(0xe4), q(0xe5), q(0xe6), q(0xe7),\
	q(0xe8), q(0xe9), q(0xea), q(0xeb), q(0xec), q(0xed), q(0xee), q(0xef),\
	q(0xf0), q(0xf1), q(0xf2), q(0xf3), q(0xf4), q(0xf5), q(0xf6), q(0xf7),\
	q(0xf8), q(0xf9), q(0xfa), q(0xfb), q(0xfc), q(0xfd), q(0xfe), q(0xff) \
}

/* Given the value i in 0..255 as the byte overflow when a field element
    in GHASH is multiplied by x^8, this function will return the values that
    are generated in the lo 16-bit word of the field value by applying the
    modular polynomial. The values lo_byte and hi_byte are returned via the
    macro xp_fun(lo_byte, hi_byte) so that the values can be assembled into
    memory as required by a suitable definition of this macro operating on
    the table above
*/

#define xx(p, q)	0x##p##q

#define xda_bbe(i) ( \
	(i & 0x80 ? xx(43, 80) : 0) ^ (i & 0x40 ? xx(21, c0) : 0) ^ \
	(i & 0x20 ? xx(10, e0) : 0) ^ (i & 0x10 ? xx(08, 70) : 0) ^ \
	(i & 0x08 ? xx(04, 38) : 0) ^ (i & 0x04 ? xx(02, 1c) : 0) ^ \
	(i & 0x02 ? xx(01, 0e) : 0) ^ (i & 0x01 ? xx(00, 87) : 0) \
)

#define xda_lle(i) ( \
	(i & 0x80 ? xx(e1, 00) : 0) ^ (i & 0x40 ? xx(70, 80) : 0) ^ \
	(i & 0x20 ? xx(38, 40) : 0) ^ (i & 0x10 ? xx(1c, 20) : 0) ^ \
	(i & 0x08 ? xx(0e, 10) : 0) ^ (i & 0x04 ? xx(07, 08) : 0) ^ \
	(i & 0x02 ? xx(03, 84) : 0) ^ (i & 0x01 ? xx(01, c2) : 0) \
)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,17)
#define GCM_AES_IV_SIZE 12
#define GCM_RFC4106_IV_SIZE 8
#define GCM_RFC4543_IV_SIZE 8
#else
#include <crypto/gcm.h>
#endif

static const u16 gf128mul_table_lle[256] = gf128mul_dat(xda_lle);
static const u16 gf128mul_table_bbe[256] = gf128mul_dat(xda_bbe);

/*Copy End*/

static inline struct chcr_context *a_ctx(struct crypto_aead *tfm)
{
	return crypto_aead_ctx(tfm);
}

static inline struct chcr_context *c_ctx(struct crypto_skcipher *tfm)
{
	return crypto_skcipher_ctx(tfm);
}

static inline struct chcr_context *h_ctx(struct crypto_ahash *tfm)
{
	return crypto_tfm_ctx(crypto_ahash_tfm(tfm));
}

struct ablk_ctx {
	struct crypto_sync_skcipher *sw_cipher;
	struct crypto_cipher *aes_generic;
	__be32 key_ctx_hdr;
	unsigned int enckey_len;
	unsigned char ciph_mode;
	u8 key[CHCR_AES_MAX_KEY_LEN];
	u8 nonce[4];
	u8 rrkey[AES_MAX_KEY_SIZE];
};

struct chcr_aead_reqctx {
	struct	sk_buff	*skb;
	dma_addr_t iv_dma;
	dma_addr_t b0_dma;
	unsigned int b0_len;
	unsigned int op;
	u16 imm;
	u16 verify;
	u16 txqidx;
	u16 rxqidx;
	u8 iv[CHCR_MAX_CRYPTO_IV_LEN + MAX_SCRATCH_PAD_SIZE];
	u8 *scratch_pad;
};

struct ulptx_walk {
	struct ulptx_sgl *sgl;
	unsigned int nents;
	unsigned int pair_idx;
	unsigned int last_sg_len;
	struct scatterlist *last_sg;
	struct ulptx_sge_pair *pair;

};

struct dsgl_walk {
	unsigned int nents;
	unsigned int last_sg_len;
	struct scatterlist *last_sg;
	struct cpl_rx_phys_dsgl *dsgl;
	struct phys_sge_pairs *to;
};



struct chcr_gcm_ctx {
	u8 ghash_h[AEAD_H_SIZE];
};

struct chcr_authenc_ctx {
	u8 dec_rrkey[AES_MAX_KEY_SIZE];
	u8 h_iopad[2 * CHCR_HASH_MAX_DIGEST_SIZE];
	unsigned char auth_mode;
};

struct __aead_ctx {
	struct chcr_gcm_ctx gcm[0];
	struct chcr_authenc_ctx authenc[0];
};



struct chcr_aead_ctx {
	__be32 key_ctx_hdr;
	unsigned int enckey_len;
	struct crypto_aead *sw_cipher;
	u8 salt[MAX_SALT];
	u8 key[CHCR_AES_MAX_KEY_LEN];
	u8 nonce[4];
	u16 hmac_ctrl;
	u16 mayverify;
	struct	__aead_ctx ctx[0];
};



struct hmac_ctx {
	struct crypto_shash *base_hash;
	u8 ipad[CHCR_HASH_MAX_BLOCK_SIZE_128];
	u8 opad[CHCR_HASH_MAX_BLOCK_SIZE_128];
};

struct __crypto_ctx {
	struct hmac_ctx hmacctx[0];
	struct ablk_ctx ablkctx[0];
	struct chcr_aead_ctx aeadctx[0];
};

struct chcr_context {
	struct chcr_dev *dev;
	unsigned char rxq_perchan;
	unsigned char txq_perchan;
        struct completion cbc_aes_aio_done;
	unsigned int  ntxq;
	unsigned int  nrxq;
	struct __crypto_ctx crypto_ctx[0];
};

struct chcr_hctx_per_wr {
	struct scatterlist *srcsg;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	u32 dma_len;
	unsigned int src_ofst;
	unsigned int processed;
	u32 result;
	u8 is_sg_map;
	u8 imm;
	/*Final callback called. Driver cannot rely on nbytes to decide
	 * final call
	 */
	u8 isfinal;
};

struct chcr_ahash_req_ctx {
	struct chcr_hctx_per_wr hctx_wr;
	u8 *reqbfr;
	u8 *skbfr;
	/* SKB which is being sent to the hardware for processing */
	u64 data_len;  /* Data len till time */
	u16 txqidx;
	u16 rxqidx;
	u8 reqlen;
	u8 partial_hash[CHCR_HASH_MAX_DIGEST_SIZE];
	u8 bfr1[CHCR_HASH_MAX_BLOCK_SIZE_128];
	u8 bfr2[CHCR_HASH_MAX_BLOCK_SIZE_128];
};

struct chcr_skcipher_req_ctx {
	struct sk_buff *skb;
	struct scatterlist *dstsg;
	unsigned int processed;
	unsigned int last_req_len;
	unsigned int partial_req;
	struct scatterlist *srcsg;
	unsigned int src_ofst;
	unsigned int dst_ofst;
	unsigned int op;
	u16 imm;
	u8 iv[CHCR_MAX_CRYPTO_IV_LEN];
	u8 init_iv[CHCR_MAX_CRYPTO_IV_LEN];
	u16 txqidx;
	u16 rxqidx;
};

struct chcr_alg_template {
	u32 type;
	u32 is_registered;
	union {
		struct skcipher_alg skcipher;
		struct ahash_alg hash;
		struct aead_alg aead;
	} alg;
};

typedef struct sk_buff *(*create_wr_t)(struct aead_request *req,
				       unsigned short qid,
				       int size);

int chcr_aead_dma_map(struct device *dev, struct aead_request *req,
		     unsigned short op_type);
void chcr_aead_dma_unmap(struct device *dev, struct aead_request
			*req, unsigned short op_type);
void chcr_add_aead_dst_ent(struct aead_request *req,
		    struct cpl_rx_phys_dsgl *phys_cpl,
		    unsigned short qid, unsigned int esp_iv_size);
void chcr_add_aead_src_ent(struct aead_request *req,
		    struct ulptx_sgl *ulptx);
void chcr_add_cipher_src_ent(struct skcipher_request *req,
			     void *ulptx,
			     struct  cipher_wr_param *wrparam);
int chcr_cipher_dma_map(struct device *dev,
		       struct skcipher_request *req);
void chcr_cipher_dma_unmap(struct device *dev,
			  struct skcipher_request *req);
inline void chcr_add_cipher_dst_ent(struct skcipher_request *req,
				   struct cpl_rx_phys_dsgl *phys_cpl,
				   struct  cipher_wr_param *wrparam,
				   unsigned short qid);
int sg_nents_len_skip(struct scatterlist *sg, u64 len, u64 skip);
void chcr_add_hash_src_ent(struct ahash_request *req,
			 struct ulptx_sgl *ulptx,
			 struct hash_wr_param *param);
int chcr_hash_dma_map(struct device *dev,
		    struct ahash_request *req);
void chcr_hash_dma_unmap(struct device *dev,
		       struct ahash_request *req);
int chcr_ahash_continue(struct ahash_request *req);
void chcr_aead_common_exit(struct aead_request *req);
#endif /* __CHCR_CRYPTO_H__ */
