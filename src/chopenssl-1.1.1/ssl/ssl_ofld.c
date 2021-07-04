/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/comp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include "ssl_locl.h"
#include "ssl_ofld.h"

void program_tls_ofld_keys(SSL *s, unsigned int st, unsigned int ops)
{
    unsigned int cipher_key_size, iv_size;
    union crypto_context_tls crypto_context;
    struct tls12_crypto_info_aes_gcm_128 *gcm_128 = NULL;
    struct tls12_crypto_info_aes_gcm_256 *gcm_256 = NULL;
    const EVP_CIPHER *c;
    unsigned char *key;
    BIO *wbio;

    unsigned char s_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char s_iv[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_iv[MAX_CIPHER_KSZ] = {0x0};

    c = s->s3->tmp.new_sym_enc;
    if (EVP_CIPHER_mode(c) != EVP_CIPH_GCM_MODE)
	    return;

    if (s->version != TLS1_2_VERSION)
        return;

    memset(&crypto_context, 0, sizeof(crypto_context));

    key = s->s3->tmp.key_block;
    cipher_key_size = EVP_CIPHER_key_length(c);

    iv_size = (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) ?
	    EVP_GCM_TLS_FIXED_IV_LEN:
	    EVP_CIPHER_iv_length(c);

    memcpy(c_key, key, cipher_key_size);
    key += cipher_key_size;
    memcpy(s_key, key, cipher_key_size);
    key += cipher_key_size;

    memcpy(c_iv, key, iv_size);
    key += iv_size;
    memcpy(s_iv, key, iv_size);

    if (cipher_key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
	    gcm_128 = (struct tls12_crypto_info_aes_gcm_128 *) &crypto_context;

        if (st == SSL3_CC_SERVER) {
            if (ops == SSL3_CC_WRITE)
                memcpy(gcm_128->key, s_key, cipher_key_size);
            else
                memcpy(gcm_128->key, c_key, cipher_key_size);
        } else {
            if (ops  == SSL3_CC_WRITE)
                memcpy(gcm_128->key, c_key, cipher_key_size);
            else
                memcpy(gcm_128->key, s_key, cipher_key_size);
        }

        if (st == SSL3_CC_SERVER)  {
            if (ops == SSL3_CC_WRITE)
                memcpy(gcm_128->salt, s_iv, SALT_SIZE);
            else
                memcpy(gcm_128->salt, c_iv, SALT_SIZE);
         } else {
             if (ops == SSL3_CC_WRITE)
                memcpy(gcm_128->salt, c_iv, SALT_SIZE);
             else
                memcpy(gcm_128->salt, s_iv, SALT_SIZE);
         }

        gcm_128->info.cipher_type = TLS_CIPHER_AES_GCM_128;
        gcm_128->info.version = s->version;
    } else if (cipher_key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) {
        if (st == SSL3_CC_SERVER) {
	    gcm_256 = (struct tls12_crypto_info_aes_gcm_256 *) &crypto_context;
            if (ops == SSL3_CC_WRITE)
                memcpy(gcm_256->key, s_key, cipher_key_size);
            else
                memcpy(gcm_256->key, c_key, cipher_key_size);
        } else {
            if (ops  == SSL3_CC_WRITE)
                memcpy(gcm_256->key, c_key, cipher_key_size);
            else
                memcpy(gcm_256->key, s_key, cipher_key_size);
        }

        if (st == SSL3_CC_SERVER)  {
            if (ops == SSL3_CC_WRITE)
                memcpy(gcm_256->salt, s_iv, SALT_SIZE);
            else
                memcpy(gcm_256->salt, c_iv, SALT_SIZE);
         } else {
             if (ops == SSL3_CC_WRITE)
                memcpy(gcm_256->salt, c_iv, SALT_SIZE);
             else
                memcpy(gcm_256->salt, s_iv, SALT_SIZE);
         }

        gcm_256->info.cipher_type = TLS_CIPHER_AES_GCM_256;
        gcm_256->info.version = s->version;
    }

    wbio = s->wbio;
    if (!wbio) {
        return;
    }
    (void)BIO_flush(wbio);
     if (ops == SSL3_CC_WRITE) {
        BIO_set_offload_tx(wbio, &crypto_context);
     } else {
        BIO_set_offload_rx(wbio, &crypto_context);
    }
}

#ifdef CHELSIO_TLS_OFFLOAD
int CHSSL_EVP_Digest(const void *data,
                     void *md, unsigned long algorithm_mac)
{
    int ret = 1, i;
    unsigned char *temp = md;

   if (algorithm_mac == SSL_SHA1){
        SHA_CTX sha1ctx;

        SHA1_Init(&sha1ctx);
        SHA1_Update(&sha1ctx, data, SHA_CBLOCK);
        l2n(sha1ctx.h0, temp);
        l2n(sha1ctx.h1, temp);
        l2n(sha1ctx.h2, temp);
        l2n(sha1ctx.h3, temp);
        l2n(sha1ctx.h4, temp);
   } else if (algorithm_mac == SSL_SHA256) {
        SHA256_CTX sha256ctx;
        SHA256_Init(&sha256ctx);
        SHA256_Update(&sha256ctx, data, SHA256_CBLOCK);

        for (i = 0; i < SHA256_DIGEST_LENGTH / 4; i++)
                l2n(sha256ctx.h[i], temp);    
   } else if (algorithm_mac == SSL_SHA384) {
        SHA512_CTX sha384ctx;

        SHA384_Init(&sha384ctx);
        SHA384_Update(&sha384ctx, data, SHA512_BLOCK);

        for (i = 0; i < SHA512_DIGEST_LENGTH / 8; i++)
            l2n8(sha384ctx.h[i], temp);
   }

   return ret;
}

static int tls_ofld_enc_mac(SSL *s)
{
    const EVP_CIPHER *p;
    const SSL_CIPHER *c;

    c = s->s3->tmp.new_cipher;
    p = s->s3->tmp.new_sym_enc;

    switch(c->algorithm_enc) {
    case SSL_AES128GCM:
    case SSL_AES256GCM:
        return TLS_OFLD_TRUE;

    case SSL_AES128 :
    case SSL_AES256 :
        switch(EVP_CIPHER_mode(p)) {
        case EVP_CIPH_CTR_MODE:
        case EVP_CIPH_CBC_MODE:
            break;
        default:
           return TLS_OFLD_FALSE;
        }
    break;

    case SSL_eNULL:
        break;

    default:
        return TLS_OFLD_FALSE;
    }

    switch(c->algorithm_mac) {
    case SSL_SHA1:
    case SSL_SHA256:
    case SSL_SHA384:
        break;

    default:
        /* Revert enc mode to non-offload */
        return TLS_OFLD_FALSE;
    }
    return TLS_OFLD_TRUE;
}

static unsigned char get_auth_mode(SSL *s)
{
    const SSL_CIPHER *c = s->s3->tmp.new_cipher;

    if(c==NULL) return CHSSL_SHA_NOP;

    switch(c->algorithm_mac) {
    case SSL_SHA1:
        return CHSSL_SHA1;
    case SSL_SHA256:
       return CHSSL_SHA256;
    case SSL_SHA384:
       return CHSSL_SHA512_384;
    case SSL_AEAD:
        return CHSSL_GHASH;
    default:
        return CHSSL_SHA_NOP;
    }
}

/*
 * Cipher Mode expected by HW
 */
static unsigned char get_cipher_mode(SSL *s)
{
    const EVP_CIPHER *c = s->s3->tmp.new_sym_enc;

    switch(EVP_CIPHER_mode(c)) {
    case EVP_CIPH_CBC_MODE:
        return CHSSL_AES_CBC;
    case EVP_CIPH_GCM_MODE:
        return CHSSL_AES_GCM;
    case EVP_CIPH_CTR_MODE:
        return CHSSL_AES_CTR;
    case EVP_CIPH_STREAM_CIPHER:
        return CHSSL_CIPH_NOP;
    default:
        return CHSSL_CIPH_NOP;
    }
}

/*
 * H/W requires Partial Hash of opad and ipad. This function create
 * ipad, opad block using key and generates partial result
 */
static void chssl_compute_ipad_opad(unsigned char *key,
                                 unsigned char *ipad,
                                 unsigned char *opad,
                                 int k, unsigned long algorithm_mac)
{
    int i, blksize;
    char iblock[SHA512_BLOCK] = {0};
    char oblock[SHA512_BLOCK] = {0};

    if (algorithm_mac == SSL_SHA384)
            blksize = SHA512_CBLOCK;
    else
            blksize = SHA256_CBLOCK;
    memset (iblock + k, 0x36, blksize - k);
    memset (oblock + k, 0x5c, blksize - k);
    for(i = 0; i < k; i++) {
        iblock[i] = key[i] ^ 0x36;
        oblock[i] = key[i] ^ 0x5c;
    }
    CHSSL_EVP_Digest(iblock, ipad, algorithm_mac);
    CHSSL_EVP_Digest(oblock, opad, algorithm_mac);
}

static void chssl_compute_cipher_key(unsigned char *key,
                                     int key_len,
                                     unsigned char *ghash)
{
    int len,len1;
    EVP_CIPHER_CTX *ctx;
    unsigned char plaintext[GHASH_SIZE] = {0};

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_reset(ctx);
    if(key_len == 16)
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL);
    else
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ghash, &len, plaintext, 16);
    EVP_EncryptFinal_ex(ctx, ghash+len, &len1);
    EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

/*
 * Create key Context for receive/transmit and program on HW
 */
static int ssl_key_context(SSL *s, struct tls_key_context *kctx, int rw, int state)
{
    const EVP_CIPHER *c;
    unsigned int  mac_key_size = 0, cipher_key_size, iv_size;
    unsigned char *key;
    unsigned char s_ipad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char s_opad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char c_ipad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char c_opad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */

    unsigned char s_mac_key[MAX_MAC_KSZ] = {0x0};
    unsigned char c_mac_key[MAX_MAC_KSZ] = {0x0};
    unsigned char s_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char s_iv[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_iv[MAX_CIPHER_KSZ] = {0x0};
    unsigned char ghash[GHASH_SIZE] = {0x0};
    int pad = 12;
    int index = 0;
    int ret = 0;

    if (!tls_ofld_enc_mac(s) || s->version < TLS1_VERSION) {
        return ret;
    }

    if (rw == SSL3_CC_READ && SSL_READ_ETM(s))
        return ret;
    else if (rw == SSL3_CC_WRITE && SSL_WRITE_ETM(s))
        return ret;

    c = s->s3->tmp.new_sym_enc;
    kctx->l_p_key = rw;

    if (s->new_session)
    kctx->l_p_key |= F_KEY_CLR_LOC;
    key = s->s3->tmp.key_block;

    mac_key_size = s->s3->tmp.new_mac_secret_size;

    kctx->mac_secret_size = mac_key_size;

    cipher_key_size = EVP_CIPHER_key_length(c);
    kctx->cipher_secret_size = cipher_key_size;

    iv_size = (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) ?
    EVP_GCM_TLS_FIXED_IV_LEN:
    EVP_CIPHER_iv_length(c);
    kctx->iv_size = iv_size;
    kctx->iv_ctrl = 1;
    kctx->iv_algo = 0;

    if ((mac_key_size == SHA256_DIGEST_LENGTH) ||
        (mac_key_size == SHA384_DIGEST_LENGTH))
        pad = 0;

    if (mac_key_size) {
        memcpy(c_mac_key, key, mac_key_size);
        key += mac_key_size;
        memcpy(s_mac_key, key, mac_key_size);
        key += mac_key_size;
    }
    memcpy(c_key, key, cipher_key_size);
    key += cipher_key_size;
    memcpy(s_key, key, cipher_key_size);
    key += cipher_key_size;

    memcpy(c_iv, key, iv_size);
    key += iv_size;
    memcpy(s_iv, key, iv_size);

    if ((EVP_CIPHER_mode(c) != EVP_CIPH_GCM_MODE)) {
        /* IPAD/OPAD for SHA384/512 calculated over 128B block */
            chssl_compute_ipad_opad(c_mac_key, c_ipad_hash,
                                    c_opad_hash, mac_key_size,
                                    s->s3->tmp.new_cipher->algorithm_mac);
            chssl_compute_ipad_opad(s_mac_key, s_ipad_hash,
                                    s_opad_hash, mac_key_size,
                                    s->s3->tmp.new_cipher->algorithm_mac);
    }

    if (state == SSL_ST_ACCEPT) {
        memcpy(kctx->tx.key, s_key, cipher_key_size);
        memcpy(kctx->rx.key, c_key, cipher_key_size);
    } else {
        memcpy(kctx->tx.key, c_key, cipher_key_size);
        memcpy(kctx->rx.key, s_key, cipher_key_size);
    }

    if (mac_key_size == SHA384_DIGEST_LENGTH) mac_key_size = MAX_MAC_KSZ;
    index = cipher_key_size;
        if (mac_key_size) {
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->tx.key+index, s_ipad_hash, mac_key_size);
            else
                memcpy(kctx->tx.key+index, c_ipad_hash, mac_key_size);

            index += (mac_key_size + pad);
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->tx.key+index, s_opad_hash, mac_key_size);
            else
                memcpy(kctx->tx.key+index, c_opad_hash, mac_key_size);

            index += (mac_key_size + pad);
        } else {
            if (state == SSL_ST_ACCEPT) {
               chssl_compute_cipher_key(s_key, cipher_key_size, ghash);
               memcpy(kctx->tx.key+index, ghash, GHASH_SIZE);
            } else {
               chssl_compute_cipher_key(c_key, cipher_key_size, ghash);
               memcpy(kctx->tx.key+index, ghash, GHASH_SIZE);
            }
            index += GHASH_SIZE;
        }
    kctx->tx_key_info_size = TLS_TX_HDR_SZ + index;
    index = cipher_key_size;
        if (mac_key_size) {
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->rx.key+index, c_ipad_hash, mac_key_size);
            else
                memcpy(kctx->rx.key+index, s_ipad_hash, mac_key_size);

        index += (mac_key_size + pad);
        if (state == SSL_ST_ACCEPT)
            memcpy(kctx->rx.key+index, c_opad_hash, mac_key_size);
        else
            memcpy(kctx->rx.key+index, s_opad_hash, mac_key_size);

        index += (mac_key_size + pad);
        } else {
            if (state == SSL_ST_ACCEPT)  {
                chssl_compute_cipher_key(c_key, cipher_key_size, ghash);
                memcpy(kctx->rx.key+index, ghash, GHASH_SIZE);
            } else {
                chssl_compute_cipher_key(s_key, cipher_key_size, ghash);
                memcpy(kctx->rx.key+index, ghash, GHASH_SIZE);
            }
        index += GHASH_SIZE;
        }

    kctx->tx_key_info_size = TLS_RX_HDR_SZ + index;

    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
        if (state == SSL_ST_ACCEPT)  {
            memcpy(kctx->tx.salt, s_iv, SALT_SIZE);
            memcpy(kctx->rx.salt, c_iv, SALT_SIZE);
        } else {
            memcpy(kctx->tx.salt, c_iv, SALT_SIZE);
            memcpy(kctx->rx.salt, s_iv, SALT_SIZE);
        }
    }

    kctx->proto_ver = s->version;
    kctx->state.auth_mode = get_auth_mode(s);
    kctx->state.enc_mode = get_cipher_mode(s);

    if (s->max_send_fragment)
        kctx->frag_size = s->max_send_fragment;
    else
        kctx->frag_size = SSL3_RT_MAX_PLAIN_LENGTH;

    /* handle renegotiation here */
    if(!BIO_get_offload_tx(s->wbio))
        kctx->tx_seq_no = 0;
    else
        kctx->tx_seq_no = 1;

    if(!BIO_get_offload_rx(s->rbio))
        kctx->rx_seq_no = 0;
    else
        kctx->rx_seq_no = 1;

    if(EVP_CIPHER_mode(c) != EVP_CIPH_GCM_MODE) {
            kctx->hmac_ctrl = 1;
    }

    return 1;
}

void chssl_program_hwkey_context(SSL *s, int rw, int state)
{
    int ret = 0;
    BIO *wbio;
    BIO *rbio;
    struct tls_key_context *key_context;

    wbio = s->wbio;
    rbio = s->rbio;
    if (!BIO_get_chofld_flag(rbio))
        return;

    key_context = (struct tls_key_context *)
    OPENSSL_malloc(sizeof(struct tls_key_context));
    if (key_context == NULL)
        return;

    memset(key_context, 0, sizeof(struct tls_key_context));
    if((ret = ssl_key_context(s, key_context, rw, state)) <=0) {
        /* Clear quiesce after CCS receive */
        if (rw == KEY_WRITE_RX)
            BIO_set_offload_clear_key(wbio);
        goto end;
    }

    /* flush outstanding BIO before key is programmed */
    statem_flush(s);
    ret = BIO_set_offload_key(wbio, key_context);
    if (ret)
        goto end;
    if (rw & KEY_WRITE_TX) {
        BIO_set_offload_tx_flag(rbio);
    } else {
        BIO_set_offload_rx_flag(rbio);
    }
end:
    free(key_context);
    return;
}
#endif
