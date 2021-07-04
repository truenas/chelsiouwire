#define EVP_AEAD_TLS1_AAD_LEN 13
struct af_alg_data {
	int tfmfd;
        int op;
        uint32_t type;
};

struct af_alg_cipher_data
{
	/*Should be First Element in structure*/
	struct af_alg_data afdata;
	unsigned char part_buf[16];
};

struct af_alg_aead_data
{
/*Should be First Element in structure. initialise all in af_alg_AEAD_ctrl
 * function*/
	struct af_alg_data afdata;
	int key_set;
	int iv_set;
	unsigned char *iv;
	int ivlen;
	int taglen;
	int iv_gen;
	int tls_aad_len;
	int result_pending;
	int iovlen;
	int aadlen;
	int len;
	struct iovec iov[16];

};

#define AFALG_DATA(ctx) ((struct af_alg_data *)(ctx->cipher_data))
#define CIPHER_DATA(ctx) ((struct af_alg_cipher_data*)(ctx->cipher_data))
#define AEAD_DATA(ctx) ((struct af_alg_aead_data*)(ctx->cipher_data))


#define DECLARE_CIPHER_INIT_KEY(alias, name)\
static int af_alg_##alias##_init_key (EVP_CIPHER_CTX *ctx,	\
	const unsigned char *key,   				\
	const unsigned char *iv __U__,  			\
	int enc __U__)  					\
{								\
	static struct sockaddr_alg sa = {  			\
		.salg_family = AF_ALG,  			\
		.salg_type = "skcipher",			\
		.salg_name = #name,  				\
	};							\
	return af_alg_CIPHER_init_key(ctx, &sa, key, iv, enc);	\
}

#define DECLARE_AEAD_INIT_KEY(alias, name)\
static int af_alg_##alias##_init_key (EVP_CIPHER_CTX *ctx,	\
	const unsigned char *key,				\
	const unsigned char *iv __U__,				\
	int enc __U__)					\
{								\
	static struct sockaddr_alg sa = {			\
		.salg_family = AF_ALG,			\
		.salg_type = "aead",			\
		.salg_name = #name,				\
	};							\
	return af_alg_AEAD_init_key(ctx, &sa, key, iv, enc);	\
}

#define DEFINE_CIPHER_INIT_KEY(alias, name)\
static int af_alg_##alias##_init_key (EVP_CIPHER_CTX *ctx,	\
	const unsigned char *key,   							\
	const unsigned char *iv __U__,  						\
	int enc __U__);

#define DEFINE_AEAD_INIT_KEY(alias, name)\
static int af_alg_##alias##_init_key (EVP_CIPHER_CTX *ctx,	\
	const unsigned char *key,   							\
	const unsigned char *iv __U__,  						\
	int enc __U__);


#define DECLARE_CIPHER_CLEANUP_KEY(name)					\
static int af_alg_##name##_cleanup_key(EVP_CIPHER_CTX *ctx)	\
{   														\
	return af_alg_CIPHER_cleanup_key(ctx);					\
}

#define DECLARE_AEAD_CLEANUP_KEY(name)					\
static int af_alg_##name##_cleanup_key(EVP_CIPHER_CTX *ctx)	\
{   														\
	return af_alg_AEAD_cleanup_key(ctx);					\
}


#define DEFINE_CIPHER_CLEANUP_KEY(name)						\
int af_alg_##name##_cleanup_key(EVP_CIPHER_CTX *ctx);

#define DEFINE_AEAD_CLEANUP_KEY(name)						\
int af_alg_##name##_cleanup_key(EVP_CIPHER_CTX *ctx);



#define DECLARE_CIPHER_DO_CIPHER(name)						\
int af_alg_##name##_do_cipher(EVP_CIPHER_CTX *ctx, 	\
unsigned char *out_arg, 									\
const unsigned char *in_arg, size_t nbytes);
#define DECLARE_AEAD_DO_CIPHER(name)						\
static int af_alg_##name##_do_cipher(EVP_CIPHER_CTX *ctx, 	\
unsigned char *out_arg, 									\
const unsigned char *in_arg, size_t nbytes);

#define DECLARE_AEAD_CTRL(name)		\
int af_alg_##name##_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr) \
{									\
	return af_alg_AEAD_ctrl(c, type, arg, ptr);	\
}

#define DEFINE_CIPHER_DO_CIPHER(name)						\
int af_alg_##name##_do_cipher(EVP_CIPHER_CTX *ctx);

#define DEFINE_AEAD_DO_CIPHER(name)						\
int af_alg_##name##_do_cipher(EVP_CIPHER_CTX *ctx);


#define DECLARE_CIPHER(name, param)\
DECLARE_CIPHER_INIT_KEY(name, param)\
DECLARE_CIPHER_CLEANUP_KEY(name)\
DECLARE_CIPHER_DO_CIPHER(name)

#define DECLARE_AEAD(name, param)\
DECLARE_AEAD_INIT_KEY(name, param)\
DECLARE_AEAD_CTRL(name)\
DECLARE_AEAD_CLEANUP_KEY(name)\
DECLARE_AEAD_DO_CIPHER(name)


int af_alg_CIPHER_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa, const unsigned char *key, const unsigned char *iv __U__, int enc __U__);
int af_alg_CIPHER_cleanup_key(EVP_CIPHER_CTX *ctx);
int af_alg_CIPHER_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes);

int af_alg_AEAD_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa, const unsigned char *key, const unsigned char *iv __U__, int enc __U__);
int af_alg_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
int af_alg_AEAD_cleanup_key(EVP_CIPHER_CTX *ctx);
int af_alg_AEAD_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes);


int af_alg_list_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
