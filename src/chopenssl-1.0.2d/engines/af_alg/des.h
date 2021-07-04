#define	DECLARE_DES_EVP(name, keylen)  		 	\
const EVP_CIPHER af_alg_##name##_cbc = {		 	\
	.nid = NID_##name##_cbc,					 	\
	.block_size = 8,							 	\
	.key_len = keylen, 						 	\
	.iv_len = 8,								 	\
	.flags = 0 | EVP_CIPH_CBC_MODE, 			 	\
	.init = af_alg_##name##_init_key,   		 	\
	.do_cipher = af_alg_##name##_do_cipher, 	 	\
	.cleanup = af_alg_##name##_cleanup_key, 	 	\
	.ctx_size = sizeof(struct af_alg_cipher_data), 	\
	.set_asn1_parameters = EVP_CIPHER_set_asn1_iv, 	\
	.get_asn1_parameters = EVP_CIPHER_get_asn1_iv, 	\
	.ctrl = NULL,   							   	\
	.app_data = NULL							   	\
};

#define	DEFINE_DES_EVP(name)                  \
extern const EVP_CIPHER af_alg_##name##_cbc;


DEFINE_DES_EVP(des)
DEFINE_DES_EVP(des_ede3)
