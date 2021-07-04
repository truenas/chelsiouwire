#define	DECLARE_AES_EVP(ksize,lmode,umode)                  \
const EVP_CIPHER af_alg_aes_##ksize##_##lmode = {    		\
	.nid = NID_aes_##ksize##_##lmode,                       \
	.block_size = EVP_CIPHER_block_size_##umode,            \
	.key_len = AES_KEY_SIZE_##ksize,                        \
	.iv_len = AES_BLOCK_SIZE,                               \
	.flags = 0 | EVP_CIPH_##umode##_MODE,                   \
	.init = af_alg_##lmode##_init_key,                            \
	.do_cipher = af_alg_##lmode##_do_cipher,                      \
	.cleanup = af_alg_##lmode##_cleanup_key,                      \
	.ctx_size = sizeof(struct af_alg_cipher_data),          \
	.ctrl = NULL,                                           \
	.app_data = NULL                                        \
};

#define	DEFINE_AES_EVP(ksize,lmode,umode)                  \
extern const EVP_CIPHER af_alg_aes_##ksize##_##lmode;

# define CUSTOM_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY)

#define	DECLARE_AES_GCM_EVP(ksize)		                \
const EVP_CIPHER af_alg_aes_##ksize##_gcm = {    		\
	.nid = NID_aes_##ksize##_gcm,                       \
	.block_size = 1,            \
	.key_len = AES_KEY_SIZE_##ksize,                        \
	.iv_len = 12,                               \
	.flags = EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS | \
	 EVP_CIPH_GCM_MODE,                   \
	.init = af_alg_aes_gcm_init_key,                            \
	.do_cipher = af_alg_aes_gcm_do_cipher,                      \
	.cleanup = af_alg_aes_gcm_cleanup_key,                      \
	.ctx_size = sizeof(struct af_alg_aead_data),          \
	.ctrl = af_alg_aes_gcm_ctrl,                                           \
	.app_data = NULL                                        \
};

#define	DEFINE_AES_GCM_EVP(ksize)                  \
extern const EVP_CIPHER af_alg_aes_##ksize##_##gcm;

#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32

DEFINE_AES_EVP(128,cbc,CBC);
DEFINE_AES_EVP(192,cbc,CBC);
DEFINE_AES_EVP(256,cbc,CBC);
DEFINE_AES_EVP(128,ctr,CTR);
DEFINE_AES_EVP(192,ctr,CTR);
DEFINE_AES_EVP(256,ctr,CTR);
DEFINE_AES_EVP(128,xts,XTS);
DEFINE_AES_EVP(256,xts,XTS);
DEFINE_AES_GCM_EVP(128);
DEFINE_AES_GCM_EVP(192);
DEFINE_AES_GCM_EVP(256);
DEFINE_AES_EVP(128,ccm,CCM);
DEFINE_AES_EVP(192,ccm,CCM);
DEFINE_AES_EVP(256,ccm,CCM);

