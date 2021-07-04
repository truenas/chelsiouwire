struct af_alg_digest_data
{
	int tfmfd;
	int opfd;
	int flags;
};

#define DIGEST_DATA(ctx) ((struct af_alg_digest_data*)(ctx->md_data))
#define AF_ALG_UPDATE_CALLED 0x00000001

#define MIN(a,b) (((a)<(b))?(a):(b))

#define DECLARE_DIGEST_INIT(name)\
int af_alg_##name##_init(EVP_MD_CTX *ctx)					\
{															\
	static struct sockaddr_alg sa = {  						\
		.salg_family = AF_ALG,  							\
		.salg_type = "hash",								\
		.salg_name = #name,  							\
	};														\
	return af_alg_DIGEST_init(ctx, &sa);					\
}

#define DEFINE_DIGEST_INIT(name)\
int af_alg_##name##_init_key (EVP_MD_CTX *ctx);

#define DECLARE_DIGEST_UPDATE(name) 						\
int af_alg_##name##_update(EVP_MD_CTX *ctx, 				\
						   const void *data, size_t length) \
{   														\
	return af_alg_DIGEST_update(ctx, data, length); 		\
}

#define DEFINE_DIGEST_UPDATE(name) \
int af_alg_##name##_update(EVP_MD_CTX *ctx, const void *data, size_t length);


#define DECLARE_DIGEST_FINAL(name, digest_len) \
int af_alg_##name##_final(EVP_MD_CTX *ctx, unsigned char *md)\
{   														 \
	return af_alg_DIGEST_final(ctx, md, digest_len##_DIGEST_LENGTH);   			 \
}

#define DEFINE_DIGEST_FINAL(name) \
int af_alg_##name##_final(EVP_MD_CTX *ctx, unsigned char *md);

#define DECLARE_DIGEST_COPY(name) \
int af_alg_##name##_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from) \
{   															  \
	return af_alg_DIGEST_copy(_to, _from);  					  \
}
#define DEFINE_DIGEST_COPY(name) \
int af_alg_##name##_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from);

#define DECLARE_DIGEST_CLEANUP(name) \
int af_alg_##name##_cleanup(EVP_MD_CTX *ctx)  \
{   										\
	return af_alg_DIGEST_cleanup(ctx);  	\
}

#define DEFINE_DIGEST_CLEANUP(name) \
int af_alg_##name##_cleanup(EVP_MD_CTX *ctx);

extern EVP_PKEY_METHOD af_alg_hmac_pkey_meth;

#define DECLARE_DIGEST(name, digest_len)\
DECLARE_DIGEST_INIT(name)\
DECLARE_DIGEST_UPDATE(name)\
DECLARE_DIGEST_FINAL(name, digest_len)\
DECLARE_DIGEST_COPY(name)\
DECLARE_DIGEST_CLEANUP(name)

#define DEFINE_DIGEST(name)\
DEFINE_DIGEST_INIT(name)\
DEFINE_DIGEST_UPDATE(name)\
DEFINE_DIGEST_FINAL(name)\
DEFINE_DIGEST_COPY(name)\
DEFINE_DIGEST_CLEANUP(name)


#define	DECLARE_MD(digest, md, block)\
const EVP_MD af_alg_##digest##_md = {\
	.type = NID_##digest,\
	.pkey_type = NID_##digest##WithRSAEncryption,\
	.md_size = md##_DIGEST_LENGTH,\
	.flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,\
	.init = af_alg_##digest##_init,\
	.update = af_alg_##digest##_update,\
	.final = af_alg_##digest##_final,\
	.copy = af_alg_##digest##_copy,\
	.cleanup = af_alg_##digest##_cleanup,\
	.sign = NULL, \
        .verify = NULL, \
        .required_pkey_type = {0, 0, 0, 0 }, \
	.block_size = block##_CBLOCK,\
	.ctx_size = sizeof(struct af_alg_digest_data),\
	.md_ctrl = NULL\
};

#define DEFINE_MD(digest)\
extern const EVP_MD af_alg_##digest##_md;

DEFINE_DIGEST(md4)
DEFINE_MD(md4)

DEFINE_DIGEST(md5)
DEFINE_MD(md5)

DEFINE_DIGEST(sha1)
DEFINE_MD(sha1)

DEFINE_DIGEST(sha224)
DEFINE_MD(sha224)

DEFINE_DIGEST(sha256)
DEFINE_MD(sha256)

DEFINE_DIGEST(sha384)
DEFINE_MD(sha384)

DEFINE_DIGEST(sha512)
DEFINE_MD(sha512)

int af_alg_list_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
int af_alg_list_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pk_meth, const int **nids, int nid);
