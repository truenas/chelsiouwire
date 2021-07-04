#ifndef _SSL_OFLD_H
#define _SSL_OFLD_H 

#define TCP_ULP                 31

#define SOL_TLS                 282
#define TLS_TX                  1
#define TLS_RX                  2
#define MAX_CIPHER_KSZ          32      /* 256 bits */
#define CIPHER_BLOCK_SZ         16
#define IV_SIZE                 (4+8)   /*reserved 8 bytes */
#define SALT_SIZE               4

/* Supported versions */
#define TLS_VERSION_MINOR(ver) ((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver) (((ver) >> 8) & 0xFF)
#define TLS_VERSION_NUMBER(id) ((((id##_VERSION_MAJOR) & 0xFF) << 8) | \
   ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR 0x3
#define TLS_1_2_VERSION_MINOR 0x3
#define TLS_1_2_VERSION TLS_VERSION_NUMBER(TLS_1_2)

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128 51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE ((size_t)8)
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE ((size_t)16)
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE ((size_t)4)
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE ((size_t)16)
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE ((size_t)8)

#define TLS_CIPHER_AES_GCM_256                          52
#define TLS_CIPHER_AES_GCM_256_IV_SIZE                  8
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE         32
#define TLS_CIPHER_AES_GCM_256_SALT_SIZE                4
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE         16
#define TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE             8

#define TLS_SET_RECORD_TYPE 1

struct tls_crypto_info {
    unsigned short version;
    unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

struct tls12_crypto_info_aes_gcm_256 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_256_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE];
};

union crypto_context_tls {
	struct tls_crypto_info info;
        union {
                struct tls12_crypto_info_aes_gcm_128 aes_gcm_128;
	        struct tls12_crypto_info_aes_gcm_256 aes_gcm_256;
	};
};

/****************************************************/
void program_tls_ofld_keys(SSL *s, unsigned int st, unsigned int ops);
void chssl_program_hwkey_context(SSL *s, int rw, int state);

#ifdef CHELSIO_TLS_OFFLOAD

#define MAX_MAC_KSZ             64      /*512 bits */
#define SHA512_BLOCK            128     /* Block size for 512 */
#define MAX_CIPHER_KSZ          32      /* 256 bits */
#define CIPHER_BLOCK_SZ         16
#define IV_SIZE                 (4+8)   /*reserved 8 bytes */
#define SALT_SIZE               4
#define TLS_TX_HDR_SZ           16
#define TLS_RX_HDR_SZ           16
#define GHASH_SIZE              16
#define MAX_TLS_KSZ     (2*MAX_MAC_KSZ + MAX_CIPHER_KSZ)

#define IOCTL_TLSOM_SET_TLS_CONTEXT 201 /* Program Key Context on HW */
#define IOCTL_TLSOM_GET_TLS_TOM     202 /* Query the TLS offload mode */
#define IOCTL_TLSOM_CLR_TLS_TOM     203 /* Clear the Key */
#define IOCTL_TLSOM_CLR_QUIES     204   /* Clear the Quiesec */

enum {
    TLS_OFLD_FALSE = 0,
    TLS_OFLD_TRUE,
};

/* Can accomodate 16, 11-15 are reserved */
enum {
    CHSSL_SHA_NOP,
    CHSSL_SHA1,
    CHSSL_SHA224,
    CHSSL_SHA256,
    CHSSL_GHASH,
    CHSSL_SHA512_224,
    CHSSL_SHA512_256,
    CHSSL_SHA512_384,
    CHSSL_SHA512_512,
    CHSSL_CBCMAC,
    CHSSL_CMAC,
};

/* Can accomodate 16, 8-15 are reserved */
enum {
    CHSSL_CIPH_NOP,
    CHSSL_AES_CBC,
    CHSSL_AES_GCM,
    CHSSL_AES_CTR,
    CHSSL_AES_GEN,
    CHSSL_IPSEC_ESP,
    CHSSL_AES_XTS,
    CHSSL_AES_CCM,
};

#define KEY_WRITE_RX    0x1     /* Program Receive Key */
#define KEY_WRITE_TX    0x2     /* Program Transmit Key */
#define KEY_DELETE_RX   0x4     /* Delete Receive Key */
#define KEY_DELETE_TX   0x8     /* Delete Transmit Key */

#define S_KEY_CLR_LOC           4
#define M_KEY_CLR_LOC           0xf
#define V_KEY_CLR_LOC(x)        ((x) << S_KEY_CLR_LOC)
#define G_FW_WR_EQUIQ(s)        (((x) >> S_KEY_CLR_LOC) & M_KEY_CLR_LOC)
#define F_KEY_CLR_LOC           V_KEY_CLR_LOC(1U)

#define S_KEY_GET_LOC           0
#define M_KEY_GET_LOC           0xf
#define V_KEY_GET_LOC(x)        ((x) << S_KEY_GET_LOC)
#define G_KEY_GET_LOC(s)        (((x) >> S_KEY_GET_LOC) & M_KEY_GET_LOC)

struct tls_ofld_state {
    unsigned char enc_mode;
    unsigned char mac_mode;
    unsigned char key_loc;
    unsigned char ofld_mode;
    unsigned char auth_mode;
    unsigned char resv[3];
};

struct tls_tx_ctxt {
    unsigned char   salt[SALT_SIZE];
    unsigned char key[MAX_CIPHER_KSZ];
    unsigned char ipad[MAX_MAC_KSZ];
    unsigned char opad[MAX_MAC_KSZ];
};

struct tls_rx_ctxt {
    unsigned char   salt[SALT_SIZE];
    unsigned char key[MAX_CIPHER_KSZ];
    unsigned char ipad[MAX_MAC_KSZ];
    unsigned char opad[MAX_MAC_KSZ];
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
    unsigned int frag_size;
    unsigned int mac_secret_size;
    unsigned int cipher_secret_size;
    int proto_ver;
    unsigned int sock_fd;
    unsigned short dtls_epoch;
    unsigned short rsv;
};
#endif

#endif /* ssl_ofld.h  */
