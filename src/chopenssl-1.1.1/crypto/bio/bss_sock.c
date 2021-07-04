/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"
#include "ssl/ssl_ofld.h"

#ifndef OPENSSL_NO_SOCK

# include <openssl/bio.h>

# ifdef WATT32
/* Watt-32 uses same names */
#  undef sock_write
#  undef sock_read
#  undef sock_puts
#  define sock_write SockWrite
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

#if defined(OPENSSL_LINUX_TLS)
    #include "netinet/tcp.h"
#endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static const BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    /* TODO: Convert to new style write function */
    bwrite_conv,
    sock_write,
    /* TODO: Convert to new style read function */
    bread_conv,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets,         */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,                       /* sock_callback_ctrl */
};

const BIO_METHOD *BIO_s_socket(void)
{
    return &methods_sockp;
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return NULL;
    BIO_set_fd(ret, fd, close_flag);

    return ret;
}

static int sock_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return 1;
}

static int sock_free(BIO *a)
{
    if (a == NULL)
        return 0;
    if (a->shutdown) {
        if (a->init) {
            BIO_closesocket(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return 1;
}

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return ret;
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret;

    clear_socket_error();
    ret = writesocket(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
# ifdef OPENSSL_LINUX_TLS
    union crypto_context_tls *crypto_context;
# endif
#ifdef CHELSIO_TLS_OFFLOAD
    struct tls_key_context *key_context;
#endif
    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
#ifdef OPENSSL_LINUX_TLS
        ret = setsockopt(b->num, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
#ifdef SSL_DEBUG
        if (ret) {
             printf("setsockopt failed %d\n", errno);
        }
#endif
#endif
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
# if defined(OPENSSL_LINUX_TLS)
    case BIO_CTRL_SET_OFFLOAD_TX:
	crypto_context = (union crypto_context_tls *)ptr;
	if (crypto_context->info.cipher_type == TLS_CIPHER_AES_GCM_128) {
            struct tls12_crypto_info_aes_gcm_128 *crypto_info = (struct tls12_crypto_info_aes_gcm_128 *)ptr;
            ret = setsockopt(b->num, SOL_TLS, TLS_TX, crypto_info,
			      sizeof(*crypto_info));
	} else if (crypto_context->info.cipher_type == TLS_CIPHER_AES_GCM_256) {
            struct tls12_crypto_info_aes_gcm_256 *crypto_info = (struct tls12_crypto_info_aes_gcm_256 *)ptr;
            ret = setsockopt(b->num, SOL_TLS, TLS_TX, crypto_info,
			      sizeof(*crypto_info));
	}

#ifdef SSL_DEBUG
	printf("\nAttempt to offload...");
#endif
	if (!ret) {
            BIO_set_offload_tx_flag(b);
#ifdef SSL_DEBUG
        printf("Success %p %p\n", b, &(b->flags));
#endif
        } else {
#ifdef SSL_DEBUG
         printf("Failed ret=%ld\n", ret);
#endif
        }
        break;
    case BIO_CTRL_SET_OFFLOAD_RX:
 	crypto_context = (union crypto_context_tls *)ptr;
	if (crypto_context->info.cipher_type == TLS_CIPHER_AES_GCM_128) {
            struct tls12_crypto_info_aes_gcm_128 *crypto_info = (struct tls12_crypto_info_aes_gcm_128 *)ptr;
            ret = setsockopt(b->num, SOL_TLS, TLS_RX, crypto_info,
                              sizeof(*crypto_info));
	} else if (crypto_context->info.cipher_type == TLS_CIPHER_AES_GCM_256) {
            struct tls12_crypto_info_aes_gcm_256 *crypto_info = (struct tls12_crypto_info_aes_gcm_256 *)ptr;
            ret = setsockopt(b->num, SOL_TLS, TLS_RX, crypto_info,
                              sizeof(*crypto_info));
	}
#ifdef SSL_DEBUG
	printf("\nAttempt to offload...");
#endif
	if (!ret) {
            BIO_set_offload_rx_flag(b);
#ifdef SSL_DEBUG
        printf("Success %p %p\n", b, &(b->flags));
#endif
        } else {
#ifdef SSL_DEBUG
         printf("Failed ret=%ld\n", ret);
#endif
        }
        break;
#endif
     case BIO_CTRL_GET_OFFLOAD_TX:
         return BIO_should_offload_tx_flag(b);
     case BIO_CTRL_SET_OFFLOAD_TX_CTRL_MSG:
         BIO_set_offload_tx_ctrl_msg_flag(b);
	 b->ptr = (void *)num;
         ret = 0;
         break;
     case BIO_CTRL_CLEAR_OFFLOAD_TX_CTRL_MSG:
         BIO_clear_offload_tx_ctrl_msg_flag(b);
         ret = 0;
         break;
     case BIO_CTRL_GET_OFFLOAD_RX:
         return BIO_should_offload_rx_flag(b);
#ifdef CHELSIO_TLS_OFFLOAD
    case BIO_CTRL_SET_OFFLOAD_KEY:
        key_context = (struct tls_key_context *)ptr;
        ret = ioctl(b->num, IOCTL_TLSOM_SET_TLS_CONTEXT, key_context);
        break;
    case BIO_CTRL_SET_OFFLOAD_CLEAR_KEY:
        ret = ioctl(b->num, IOCTL_TLSOM_CLR_TLS_TOM);
        break;
#endif
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = sock_write(bp, str, n);
    return ret;
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

        return BIO_sock_non_fatal_error(err);
    }
    return 0;
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return 1;
    default:
        break;
    }
    return 0;
}

#endif                          /* #ifndef OPENSSL_NO_SOCK */
