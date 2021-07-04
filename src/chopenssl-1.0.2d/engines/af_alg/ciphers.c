#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "if_alg.h"

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/modes.h>
#include "e_af_alg.h"
#include "ciphers.h"
#include "aes.h"


typedef unsigned int u32;
typedef unsigned char u8;

#define GETU32(p)       ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
#define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))


/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/* increment upper 96 bits of 128-bit counter by 1 */
static void ctr96_inc(unsigned char *counter)
{
    u32 n = 12;
    u8 c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

int af_alg_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa,
			   const unsigned char *key,
			   const unsigned char *iv __U__, int enc __U__)
{
	int keylen = EVP_CIPHER_CTX_key_length(ctx);
	struct af_alg_data *acd = AFALG_DATA(ctx);

	acd->op = -1;

	if( ctx->encrypt )
		acd->type = ALG_OP_ENCRYPT;
	else
		acd->type = ALG_OP_DECRYPT;

	if((acd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
	{
		TRACE("%s socket\n", __PRETTY_FUNCTION__);
		return 0;
	}

	if( bind(acd->tfmfd, (struct sockaddr *)sa, sizeof(struct sockaddr_alg)) == -1 )
	{
		TRACE("%s bind\n", __PRETTY_FUNCTION__);
		return 0;
	}

	if (setsockopt(acd->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1)
	{
		TRACE("%s setsockopt \n", __PRETTY_FUNCTION__);
		return 0;
	}

	return 1;

}
int af_alg_CIPHER_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa,
			   const unsigned char *key,
			   const unsigned char *iv __U__, int enc __U__)
{
	return af_alg_init_key(ctx, sa , key, iv, enc);
}

int af_alg_AEAD_init_key(EVP_CIPHER_CTX *ctx, const struct sockaddr_alg *sa,
			 const unsigned char *key, const unsigned char *iv __U__, int enc __U__)

{
	struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	struct af_alg_data *acd = AFALG_DATA(ctx);


	if (!iv && !key) {
		TRACE("%s No IV or Key\n", __PRETTY_FUNCTION__);
	        return 1;
	}
	if (key) {
		af_alg_init_key(ctx, sa, key, iv, enc);
		if (iv == NULL && gctx->iv_set)
			iv = gctx->iv;
		if (iv) {
			memcpy(gctx->iv, iv, gctx->ivlen);
			gctx->iv_set = 1;
		}

		if (setsockopt(acd->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
			       EVP_GCM_TLS_TAG_LEN) == -1)
		{
			TRACE("%s setsockopt Authsize\n", __PRETTY_FUNCTION__);
			return 0;
		}
		gctx->key_set = 1;

	} else {
		memcpy(gctx->iv, iv, gctx->ivlen);
		gctx->iv_set = 1;
		gctx->iv_gen = 0;
	}

	return 1;
}

int af_alg_AEAD_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{

	struct af_alg_aead_data *gctx = AEAD_DATA(ctx);

	switch (type) {
	case EVP_CTRL_INIT:
		gctx->key_set = 0;
	        gctx->iv_set = 0;
		gctx->ivlen = ctx->cipher->iv_len;
		gctx->iv = ctx->iv;
		gctx->taglen = -1;
		gctx->iv_gen = 0;
		gctx->tls_aad_len = -1;
		gctx->aadlen = 0;
		gctx->iovlen = 0;
		return 1;
	case EVP_CTRL_GCM_SET_IVLEN:
		if (arg <= 0) {
			TRACE("%s EVP_CTRL_GCM_SET_IVLEN\n", __PRETTY_FUNCTION__);
			return 0;
		}
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
			if (gctx->iv != ctx->iv)
				OPENSSL_free(gctx->iv);
			gctx->iv = OPENSSL_malloc(arg);
			if (!gctx->iv) {
				TRACE("%s EVP_CTRL_GCM_SET_IVLEN iv error\n", __PRETTY_FUNCTION__);
				return	0;
			}
		}
		gctx->ivlen = arg;
		return 1;
	case EVP_CTRL_GCM_SET_TAG:
		if (arg <= 0 || arg > 16 || ctx->encrypt) {
			TRACE("%s EVP_CTRL_GCM_SET_TAG error\n", __PRETTY_FUNCTION__);
			return 0;
		}
		memcpy(ctx->buf, ptr, arg);
		gctx->taglen = arg;
		return 1;
	case EVP_CTRL_GCM_GET_TAG:
		if (arg <= 0 || arg > 16 || !ctx->encrypt || gctx->taglen < 0) {
			TRACE("%s EVP_CTRL_GCM_GET_TAG error\n", __PRETTY_FUNCTION__);
			return 0;
		}
		memcpy(ptr, ctx->buf, arg);
		return 1;
	case EVP_CTRL_GCM_SET_IV_FIXED:
		/* Special case: -1 length restores whole IV */
		if (arg == -1) {
			memcpy(gctx->iv, ptr, gctx->ivlen);
			gctx->iv_gen = 1;
			return 1;
		}
		/*
		 * * Fixed field must be at least 4 bytes and invocation field at least
		 * 8.
		 */
		if ((arg < 4) || (gctx->ivlen - arg) < 8) {
			TRACE("%s EVP_CTRL_GCM_SET_IV_FIXED error\n",  __PRETTY_FUNCTION__);
			return 0;
		}
		if (arg)
			memcpy(gctx->iv, ptr, arg);
		if (ctx->encrypt && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0) {
			TRACE("%s EVP_CTRL_GCM_SET_IV_FIXED error2\n",  __PRETTY_FUNCTION__);
			return 0;
		}
		gctx->iv_gen = 1;
		return 1;
	case EVP_CTRL_GCM_IV_GEN:
		if (gctx->iv_gen == 0 || gctx->key_set == 0) {
			TRACE("%s EVP_CTRL_GCM_IV_GEN error\n", __PRETTY_FUNCTION__);
			return 0;
		}
		if (arg <= 0 || arg > gctx->ivlen)
			arg = gctx->ivlen;
		memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
		/*
		 * Invocation field will be at least 8 bytes in size and so no need
		 * to check wrap around or increment more than last 8 bytes.
		 */
		ctr64_inc(gctx->iv + gctx->ivlen - 8);
		gctx->iv_set = 1;
		return 1;
	case EVP_CTRL_GCM_SET_IV_INV:
		if (gctx->iv_gen == 0 || gctx->key_set == 0 || ctx->encrypt) {
			TRACE("%s EVP_CTRL_GCM_SET_IV_INV error\n", __PRETTY_FUNCTION__);
			return 0;
		}
		memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
		gctx->iv_set = 1;
		return 1;
	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save the AAD for later use */
		if (arg != EVP_AEAD_TLS1_AAD_LEN) {
			TRACE("%s EVP_CTRL_AEAD_TLS1_AAD length error\n", __PRETTY_FUNCTION__);
			return 0;
		}
		memcpy(ctx->buf, ptr, arg);
		gctx->tls_aad_len = arg;
		{
			unsigned int len = ctx->buf[arg - 2] << 8 | ctx->buf[arg - 1];
			/* Correct length for explicit IV */
			len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
			/* If decrypting correct for tag too */
			if (!ctx->encrypt)
				len -= EVP_GCM_TLS_TAG_LEN;
			ctx->buf[arg - 2] = len >> 8;
			ctx->buf[arg - 1] = len & 0xff;
		}
		/* Extra padding: tag appended to record */
		return EVP_GCM_TLS_TAG_LEN;
	case EVP_CTRL_COPY:
#if 0
		{
			EVP_CIPHER_CTX *out = ptr;
			struct af_alg_aead_data *gctx_out = out->cipher_data;
			if (gctx->gcm.key) {
				if (gctx->gcm.key != &gctx->ks)
					return 0;
				gctx_out->gcm.key = &gctx_out->ks;
			}
			if (gctx->iv == c->iv)
				gctx_out->iv = out->iv;
			else {
				gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
				if (!gctx_out->iv)
					return 0;
				memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
			}
			return 1;
		}
#endif

	default:
		return -1;
	}
}

int af_alg_CIPHER_cleanup_key(EVP_CIPHER_CTX *ctx)
{
	struct af_alg_data *acd = AFALG_DATA(ctx);
	if( acd->op != -1 )
		close(acd->op);
	if( acd->tfmfd != -1 )
		close(acd->tfmfd);

	return 1;
}

int af_alg_AEAD_cleanup_key(EVP_CIPHER_CTX *ctx)
{
	struct af_alg_aead_data *gctx = AEAD_DATA(ctx);

	af_alg_CIPHER_cleanup_key(ctx);
	if (gctx->iv != ctx->iv)
		OPENSSL_free(gctx->iv);
	return 1;
}

int recvmsg_common(EVP_CIPHER_CTX *ctx, struct iovec *iov, int iovlen)
{
	struct msghdr rmsg = {.msg_name = NULL};
	struct af_alg_data *acd = AFALG_DATA(ctx);
	int rbytes;

	rmsg.msg_name = NULL;
	rmsg.msg_namelen = 0;
	rmsg.msg_control = NULL;
	rmsg.msg_controllen = 0;
	rmsg.msg_flags = 0;
	rmsg.msg_iov = iov;
	rmsg.msg_iovlen = iovlen;

	if ((rbytes = recvmsg(acd->op, &rmsg, 0)) == -1){
		return -errno;
	}
	return rbytes;
}



static int cipher_sendmsg_common(EVP_CIPHER_CTX *ctx,
			  struct iovec *iov,
			  int iovlen)
{
	int block_size = AES_BLOCK_SIZE;
	struct af_alg_data *acd = AFALG_DATA(ctx);
	struct msghdr msg = {.msg_name = NULL};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	char buf[CMSG_SPACE(sizeof(acd->type)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + block_size)];
	ssize_t len;

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = 0;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + block_size);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = block_size;
	memcpy(ivm->iv, ctx->iv, block_size);

	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;


	if((len = sendmsg(acd->op, &msg, 0)) == -1) {
		TRACE("%s\n", __PRETTY_FUNCTION__);
		return -1;
	}
	return 1;
}

int af_alg_ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	struct af_alg_data *acd = AFALG_DATA(ctx);
	struct af_alg_cipher_data *cdata = CIPHER_DATA(ctx);
	struct iovec iov[2];
	int iovnum = 0;
	int ret;
	size_t blocks = 0;
	int n = ctx->num;
	unsigned int ctr32;

	while (n && nbytes) {
		*(out_arg++) = *(in_arg++) ^ cdata->part_buf[n];
		--nbytes;
		n = (n + 1) % 16;
   	}
	ctr32 = GETU32(ctx->iv + 12);
	
	if( acd->op == -1 ) {
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1) {
			TRACE("%s accept\n", __PRETTY_FUNCTION__);
			return 0;
		}
	}
	/* set operation type encrypt|decrypt */
	/* set IV - or update if it was set before */
	if (nbytes >= 16) {
		size_t len16;
		
		blocks = nbytes / 16;
		iov[0].iov_base = (void *)(in_arg);
		len16 = nbytes & ~(0x0f);
		nbytes %= 16;
		iov[0].iov_len = len16;
		in_arg += len16;
		iovnum++;
	}

	if (nbytes) {
		memset(cdata->part_buf, 0, 16);
		iov[1].iov_base = cdata->part_buf;
		iov[1].iov_len = 16;
		iovnum++;
	}
	ret = cipher_sendmsg_common(ctx, iov, iovnum);
	if (!ret) {
		TRACE("%s sendmsg \n", __PRETTY_FUNCTION__);
		return ret;
	}
	iov[0].iov_base = (void *)(out_arg);
	out_arg += iov[0].iov_len;
	ret = recvmsg_common(ctx, iov, iovnum);
	if (ret < 0) {
		TRACE("%s recvmsg \n", __PRETTY_FUNCTION__);
		return -1;
	}
	
	if (nbytes) {
		blocks++;
		while (nbytes--) {
            		out_arg[n] = in_arg[n] ^ cdata->part_buf[n];
			n++;
		}
	}
	ctr32 += (u32)blocks;
	PUTU32(ctx->iv + 12, ctr32);
	if (ctr32 < (u32)blocks)
		ctr96_inc(ctx->iv);

	ctx->num = n;

	return 1;
}


int af_alg_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	struct af_alg_data *acd = AFALG_DATA(ctx);
	struct iovec iov[1];
	int ret;
	int block_size = AES_BLOCK_SIZE;
	unsigned char save_iv[block_size];

	if( acd->op == -1 ) {
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1) {
			TRACE("%s accept\n", __PRETTY_FUNCTION__);
			return 0;
		}
	}
	/* set operation type encrypt|decrypt */
	/* set IV - or update if it was set before */
	if(!ctx->encrypt)
		memcpy(save_iv, in_arg + nbytes - block_size, block_size);
	iov[0].iov_base = (void *)(in_arg);
	iov[0].iov_len = nbytes;

	ret = cipher_sendmsg_common(ctx, iov, 1);
	if (ret < 0) {
		TRACE("%s sendmsg \n", __PRETTY_FUNCTION__);
		return ret;
	}
	iov[0].iov_base = (void *)out_arg;
	iov[0].iov_len = nbytes;
	ret = recvmsg_common(ctx, iov, 1);
	if (ret < 0) {
		TRACE("%s recvmsg \n", __PRETTY_FUNCTION__);
		return -1;
	}

		/* copy IV for next iteration */
	if(ctx->encrypt)
		memcpy(ctx->iv, out_arg + nbytes - block_size, block_size);
	else
		memcpy(ctx->iv, save_iv, block_size);
	return 1;
}

static int sendmsg_common(EVP_CIPHER_CTX *ctx,
			  struct iovec *iov,
			  int iovlen,
			  unsigned char *iv,
			  int ivlen,
			  int aadlen)
{
	struct msghdr msg = {.msg_name = NULL};
	struct af_alg_iv *ivm;
	struct af_alg_data *acd = AFALG_DATA(ctx);
	struct cmsghdr *cmsg;
	unsigned int *assoclen = NULL;
	ssize_t rbytes = -1;
	char buf[CMSG_SPACE(sizeof(acd->type)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + ivlen) + CMSG_SPACE(sizeof(unsigned int))];

	memset(buf, 0, sizeof(buf));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	if( acd->op == -1 ) {
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1) {
			TRACE("%s accept\n", __PRETTY_FUNCTION__);
			return 0;
		}
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = ivlen;
	memcpy(ivm->iv, iv, ivlen);


	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len  = CMSG_LEN(sizeof(unsigned int));
	assoclen = (void*)CMSG_DATA(cmsg);
	*assoclen = aadlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	if((rbytes = sendmsg(acd->op, &msg, 0)) == -1) {
		TRACE("%s sendmsg\n", __PRETTY_FUNCTION__);		
		return -errno;
	}

	return rbytes;

}

static int aes_gcm_tls_encrypt(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
        struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	struct iovec iov[2];
	int ret = -1;
 
	in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

	iov[0].iov_base = (void *)ctx->buf;
	iov[0].iov_len = gctx->tls_aad_len;
	iov[1].iov_base = (void *)in;
	if(afalg_compare_kernver(4,9,0)) {
		iov[1].iov_len = len;
	}
	else {
		iov[1].iov_len = len + EVP_GCM_TLS_TAG_LEN;
	}
	ret = sendmsg_common(ctx, iov, 2, gctx->iv, gctx->ivlen,
			     gctx->tls_aad_len);
	if (ret < 0 ) {
		TRACE("%s sendmsg\n", __PRETTY_FUNCTION__);
		return -1;
	}
	if(afalg_compare_kernver(4,9,0)) {
		iov[1].iov_len = len + EVP_GCM_TLS_TAG_LEN;
	}
	ret = recvmsg_common(ctx, iov, 2);
	if (ret < 0) {
		TRACE("%s recvmsg\n", __PRETTY_FUNCTION__);
		return -1;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN,
				EVP_GCM_TLS_EXPLICIT_IV_LEN, out -
				EVP_GCM_TLS_EXPLICIT_IV_LEN) <= 0)
		ret = -1;

	ret = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
	return ret;
}

static int aes_gcm_tls_decrypt(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
	struct iovec iov[2];
        struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	int ret = -1;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_INV,
				EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
		ret = -1;

	in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

	iov[0].iov_base = (void *)ctx->buf;
	iov[0].iov_len = gctx->tls_aad_len;
	iov[1].iov_base = (void *)in;
	iov[1].iov_len = len + EVP_GCM_TLS_TAG_LEN;

	ret = sendmsg_common(ctx, iov, 2, gctx->iv, gctx->ivlen, gctx->tls_aad_len);
	if (ret < 0) {
		TRACE("%s sendmsg\n", __PRETTY_FUNCTION__);
		return -1;
	}
	ret = recvmsg_common(ctx, iov, 2);

	if (ret < 0) {
		TRACE("%s recvmsg\n", __PRETTY_FUNCTION__);
		return -1;
	}

	return len;
}


static int aes_gcm_tls_do_cipher(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
	int rv = -1;

	if (out != in
	    || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN)) {
		TRACE("%s destination buffer size\n", __PRETTY_FUNCTION__);
		return -1;
	}

	if (ctx->encrypt) {
		rv = aes_gcm_tls_encrypt(ctx, out, in, len);
	} else {
		rv = aes_gcm_tls_decrypt(ctx, out, in, len);
	}

	return rv;
}
static int aes_gcm_nontls_encrypt(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
        struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	struct iovec iov[3];
	int i = 0;
	//int iovcount = 0;
	int ret = -1;

	if (in == NULL) {
		/* Copy Tag to ctx->buf. Which is done in encrypt operation.
		 * Nothing to do here*/
		gctx->iv_set = 0;
		gctx->taglen = 16;
		ret = 0;
		goto end;
	}
	gctx->iov[gctx->iovlen].iov_base = (void *)in;
	if(afalg_compare_kernver(4,9,0)) {
		gctx->iov[gctx->iovlen].iov_len = len;
		gctx->iovlen++;
	}
	else {
		gctx->iov[gctx->iovlen].iov_len = len;
		gctx->iovlen++;
		gctx->iov[gctx->iovlen].iov_base = (void *)ctx->buf;
		gctx->iov[gctx->iovlen].iov_len = 16;
		gctx->iovlen++;
	}
	ret = sendmsg_common(ctx, gctx->iov,gctx->iovlen, gctx->iv, gctx->ivlen,
			     gctx->aadlen);
	if (ret < 0 ) {
		TRACE("%s sendmsg\n", __PRETTY_FUNCTION__);
		return -1;
	}
	/* Recv output*/
	if (gctx->aadlen) {
		iov[i].iov_base = malloc(gctx->aadlen);
		iov[i].iov_len = gctx->aadlen;
		i++;
	}
	iov[i].iov_base = out;
	iov[i].iov_len = len;
	i++;
	iov[i].iov_base = ctx->buf;
	iov[i].iov_len = 16;
	i++;

	ret = recvmsg_common(ctx, iov, i);
	if (ret < 0) {
		TRACE("%s recvmsg\n", __PRETTY_FUNCTION__);
		ret = -errno;
		goto clear;
	}
	ret = len;
clear:
	if (gctx->aadlen)
		free(iov[0].iov_base);
end:
	gctx->iovlen = 0;
	gctx->aadlen = 0;
	return ret;
}

static int aes_gcm_nontls_decrypt(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
	struct iovec iov[3];
        struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	int ret = -1;
	int i = 0;

	if (in == NULL) {
		/* Return */
		ret = sendmsg_common(ctx, gctx->iov, gctx->iovlen, gctx->iv,
				     gctx->ivlen, gctx->aadlen);
		if (ret < 0) {
			TRACE("%s sendmsg\n", __PRETTY_FUNCTION__);
			return -1;
		}
		if (gctx->aadlen) {
			iov[i].iov_base = malloc(gctx->aadlen);
			iov[i].iov_len = gctx->aadlen;
			i++;
		}
		iov[i].iov_base = out;
		iov[i].iov_len = gctx->len;
		i++;
		ret = recvmsg_common(ctx, iov, i);

		if (ret < 0) {
			TRACE("%s recvmsg\n", __PRETTY_FUNCTION__);
			len = -1;
		}
		if (gctx->aadlen)
			free(iov[0].iov_base);

		gctx->iv_set = 0;
		goto end;
	}
	gctx->iov[gctx->iovlen].iov_base = (void *)in;
	gctx->iov[gctx->iovlen].iov_len = len;
	gctx->iovlen++;
	gctx->iov[gctx->iovlen].iov_base = (void *)ctx->buf;
	gctx->iov[gctx->iovlen].iov_len = 16;
	gctx->iovlen++;
	gctx->len = len;
	return len;

end:
	gctx->iovlen = 0;
	gctx->aadlen = 0;
	return len;
}
/*Function: aes_gcm_nontls_do_cipher
 * It behaves differently based on argument passed
 *   in			out		Behavior
 * Not NULL		NULL		User sent AAD data
 * Not NULL		Not NULL	User sent plain/cipher test
 * NULL			Not NULL	User expecting tag in ctx->buf (final)	
 * */
static int aes_gcm_nontls_do_cipher(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
	struct af_alg_aead_data *gctx = AEAD_DATA(ctx);;
	int rv;

	if (!gctx->iv_set)
		         return -1;
	if (in && !out) {
		/*Input contains AAD. Save in iovec*/
		if (gctx->iovlen > 16) {
			TRACE("Input has more than 16 entries. Which cannot be \
			      sent in IOV\n");
		}
		gctx->iov[gctx->iovlen].iov_base = (void *)in;
		gctx->iov[gctx->iovlen].iov_len = len;
		gctx->aadlen += len;
		gctx->iovlen++;
		return len;
	}

	if (ctx->encrypt) {
		rv = aes_gcm_nontls_encrypt(ctx, out, in, len);
	} else {
		rv = aes_gcm_nontls_decrypt(ctx, out, in, len);
	}

	return rv;

}

static int af_alg_aes_gcm_do_cipher(EVP_CIPHER_CTX *ctx, 
				     unsigned char *out,
				     const unsigned char *in,
				     size_t len)
{
        struct af_alg_aead_data *gctx = AEAD_DATA(ctx);
	int ret = -1;
	if(gctx->tls_aad_len >= 0) {
		ret = aes_gcm_tls_do_cipher(ctx, out, in, len);
	} else {
		ret = aes_gcm_nontls_do_cipher(ctx, out, in, len);
	}

	return ret;

}

int af_alg_list_ciphers(ENGINE *e __U__, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if( !cipher )
	{
		*nids = ciphers_used.data;
		return ciphers_used.len;
	}

	if( NID_store_contains(&ciphers_used, nid) == false ) {
		TRACE("%s NID store\n", __PRETTY_FUNCTION__);
		return 0;
	}

	switch( nid )
	{
#define CASE(name)\
case NID_##name:\
	*cipher = &af_alg_##name;\
	break;
	CASE(aes_128_cbc);
	CASE(aes_192_cbc);
	CASE(aes_256_cbc);
	CASE(aes_128_ctr);
	CASE(aes_192_ctr);
	CASE(aes_256_ctr);
	CASE(aes_128_gcm);
	CASE(aes_192_gcm);
	CASE(aes_256_gcm);
//	CASE(aes_128_ccm);
//	CASE(aes_192_ccm);
//	CASE(aes_256_ccm);
#undef CASE
	default:
		*cipher = NULL;
	}
	return(*cipher != 0);
}

DECLARE_AEAD(aes_gcm, gcm(aes));
/**
 * AES
 */

DECLARE_CIPHER(cbc, cbc(aes))
DECLARE_CIPHER(ctr, ctr(aes))
#define EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CTR   1
#define EVP_CIPHER_block_size_XTS	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CCM   1
DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(256,cbc,CBC);
DECLARE_AES_EVP(128,ctr, CTR);
DECLARE_AES_EVP(192,ctr, CTR);
DECLARE_AES_EVP(256,ctr, CTR);
DECLARE_AES_GCM_EVP(128);
DECLARE_AES_GCM_EVP(192);
DECLARE_AES_GCM_EVP(256);
//DECLARE_AES_EVP(128,ccm, CCM);
//DECLARE_AES_EVP(192,ccm, CCM);
//DECLARE_AES_EVP(256,ccm, CCM);
#undef EVP_CIPHER_block_size_CBC
#undef EVP_CIPHER_block_size_CTR
#undef EVP_CIPHER_block_size_XTS
#undef EVP_CIPHER_block_size_CCM
