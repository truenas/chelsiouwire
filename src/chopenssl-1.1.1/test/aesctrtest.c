/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "testutil.h"

/* Use a buffer size which is not aligned to block size */
#define BUFFER_SIZE     17

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
#endif


#ifndef OPENSSL_NO_AFALGENG
# include <linux/version.h>
# define K_MAJ   3
# define K_MIN1  1
# define K_MIN2  0
# if LINUX_VERSION_CODE < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)
/*
 * If we get here then it looks like there is a mismatch between the linux
 * headers and the actual kernel version, so we have tried to compile with
 * afalg support, but then skipped it in e_afalg.c. As far as this test is
 * concerned we behave as if we had been configured without support
 */
#  define OPENSSL_NO_AFALGENG
# endif
#endif

#ifndef OPENSSL_NO_AFALGENG
static const unsigned char ctr_pt[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
    0x73, 0x93, 0x17, 0x2a
};
static const unsigned char ctr_ip_b[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff
};
static const unsigned char ctr_key128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char ctr_key192[] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
    0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
static const unsigned char ctr_key256[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
    0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const unsigned char ctr_ct128[] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64,
    0x99, 0x0d, 0xb6, 0xce
};
static const unsigned char ctr_ct192[] = {
    0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59,
    0xfe, 0x7e, 0x6e, 0x0b
};
static const unsigned char ctr_ct256[] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04,
    0xbb, 0xf3, 0xd2, 0x28
};
static int aes_ctr_encrypt(const unsigned char *ctr_key, unsigned char *ctr_ct, int *ct_len,
                      const EVP_CIPHER *cipher)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen;
    unsigned char outbuf[32];

    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
          && TEST_true(EVP_EncryptInit_ex(ctx, cipher, e, ctr_key,
                                          ctr_ip_b) > 0)
          && TEST_true(EVP_EncryptUpdate(ctx, ctr_ct, ct_len, ctr_pt,
                                         sizeof(ctr_pt)) > 0)
          && TEST_true(EVP_EncryptFinal_ex(ctx, outbuf, &outlen) > 0);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int aes_ctr_decrypt(const unsigned char *ctr_key, const unsigned char *ct,
                      int ct_len, const EVP_CIPHER *cipher)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen, ptlen;
    unsigned char pt[32];
    unsigned char outbuf[32];

    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
              && TEST_true(EVP_DecryptInit_ex(ctx, cipher, e, ctr_key,
						 ctr_ip_b) > 0)
	      && TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0) > 0)
              && TEST_true(EVP_DecryptUpdate(ctx, pt, &ptlen, ct, ct_len) > 0)
              && TEST_true(EVP_DecryptFinal_ex(ctx, outbuf, &outlen) > 0)
              && TEST_mem_eq(ctr_pt, sizeof(ctr_pt), pt, ptlen);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
static int test_aes_ctr(int keysize_idx)
{
    unsigned char ct[32];
    int ctlen = 0;
    const EVP_CIPHER *cipher;
	
    switch (keysize_idx) {
	case 0:
	    cipher = EVP_aes_128_ctr();
	    return aes_ctr_encrypt(ctr_key128, ct, &ctlen, cipher)
		   && TEST_mem_eq(ctr_ct128, sizeof(ctr_ct128), ct, ctlen)
		   && aes_ctr_decrypt(ctr_key128, ct, ctlen, cipher);
	    break;
	case 1:
	    cipher = EVP_aes_192_ctr();
	    return aes_ctr_encrypt(ctr_key192, ct, &ctlen, cipher)
		   && TEST_mem_eq(ctr_ct192, sizeof(ctr_ct192), ct, ctlen)
		   && aes_ctr_decrypt(ctr_key192, ct, ctlen, cipher);
	    break;
	case 2:
	    cipher = EVP_aes_256_ctr();
	    return aes_ctr_encrypt(ctr_key256, ct, &ctlen, cipher)
		   && TEST_mem_eq(ctr_ct256, sizeof(ctr_ct256), ct, ctlen)
		   && aes_ctr_decrypt(ctr_key256, ct, ctlen, cipher);
	    break;
	default:
	    cipher = NULL;
	    return -1;
	}
}
#endif

#ifndef OPENSSL_NO_ENGINE
int global_init(void)
{
    ENGINE_load_builtin_engines();
# ifndef OPENSSL_NO_STATIC_ENGINE
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);
# endif
    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ENGINE
    if ((e = ENGINE_by_id("afalg")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load AFALG engine");
    } else {
# ifndef OPENSSL_NO_AFALGENG
        ADD_ALL_TESTS(test_aes_ctr, 3);
# endif
    }
#endif

    return 1;
}

#ifndef OPENSSL_NO_ENGINE
void cleanup_tests(void)
{
    ENGINE_free(e);
}
#endif
