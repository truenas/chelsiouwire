#include <string.h>
#include <execinfo.h>
#include <sys/socket.h>
#include "if_alg.h"
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>

#include <openssl/engine.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "e_af_alg.h"
#include "digests.h"

unsigned char SHA1_0B_HASH[] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                                  0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                                  0xaf, 0xd8, 0x07, 0x09};

unsigned char SHA224_0B_HASH[] = {0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
                                  0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
                                  0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
                                  0xc5, 0xb3, 0xe4, 0x2f};

unsigned char SHA256_0B_HASH[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

unsigned char SHA384_0B_HASH[] = {0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
                                  0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
                                  0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                                  0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
                                  0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                                  0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};

unsigned char SHA512_0B_HASH[] = {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                                  0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                                  0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                                  0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                                  0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                                  0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                                  0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                                  0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};

void print_trace (void)
{
	void *array[20];
    size_t size;
    char **strings;
    size_t i;

    size = backtrace (array, 20);
    strings = backtrace_symbols (array, size);
    printf ("Obtained %zd stack frames.\n", size);

    for (i = 0; i < size; i++)
	printf ("%s\n", strings[i]);

    free (strings);
}

unsigned char *string_to_hex(const char *str, long *len)
{
        unsigned char *hexbuf, *q;
        unsigned char ch, cl, *p;
        if(!str) {
                X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_INVALID_NULL_ARGUMENT);
                return NULL;
        }
        if(!(hexbuf = OPENSSL_malloc(strlen(str) >> 1))) goto err;
        for(p = (unsigned char *)str, q = hexbuf; *p;) {
                ch = *p++;
#ifdef CHARSET_EBCDIC
                ch = os_toebcdic[ch];
#endif
                if(ch == ':') continue;
                cl = *p++;
#ifdef CHARSET_EBCDIC
                cl = os_toebcdic[cl];
#endif
                if(!cl) {
                        X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ODD_NUMBER_OF_DIGITS);
                        OPENSSL_free(hexbuf);
                        return NULL;
                }
                if(isupper(ch)) ch = tolower(ch);
                if(isupper(cl)) cl = tolower(cl);

                if((ch >= '0') && (ch <= '9')) ch -= '0';
                else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
                else goto badhex;

                if((cl >= '0') && (cl <= '9')) cl -= '0';
                else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
                else goto badhex;

                *q++ = (ch << 4) | cl;
        }

        if(len) *len = q - hexbuf;

        return hexbuf;

        err:
        if(hexbuf) OPENSSL_free(hexbuf);
        X509V3err(X509V3_F_STRING_TO_HEX,ERR_R_MALLOC_FAILURE);
        return NULL;

        badhex:
        OPENSSL_free(hexbuf);
        X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ILLEGAL_HEX_DIGIT);
        return NULL;

}

int af_alg_DIGEST_init(EVP_MD_CTX *ctx, struct sockaddr_alg *sa)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( (ddata->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1 ) {
		TRACE("%s socket\n", __PRETTY_FUNCTION__);
		return 0;
	}

	if( bind(ddata->tfmfd, (struct sockaddr *)sa, sizeof(struct sockaddr_alg)) != 0 )
	{
		TRACE("%s bind\n", __PRETTY_FUNCTION__);
		return 0;
	}

	if( (ddata->opfd = accept(ddata->tfmfd,NULL,0)) == -1 )
	{
		TRACE("%s accept\n", __PRETTY_FUNCTION__);
		return 0;
	}
	ddata->flags = 0;

	return 1;
}

int af_alg_DIGEST_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r;
	r = send(ddata->opfd, data, length, MSG_MORE);
	if( r < 0 || (size_t)r < length ) {
		TRACE("%s send\n", __PRETTY_FUNCTION__);
		return 0;
	}
	if(r)
		ddata->flags |= AF_ALG_UPDATE_CALLED;

	return 1;
}

void copy_0B_hash(EVP_MD_CTX *ctx, unsigned char *md, int len)
{
	switch(ctx->digest->type) {
		case NID_sha1:
			memcpy(md, &SHA1_0B_HASH, MIN(ctx->digest->md_size, len));
			break;
		case NID_sha224:
			memcpy(md, &SHA224_0B_HASH, MIN(ctx->digest->md_size, len));
			break;
		case NID_sha256:
			memcpy(md, &SHA256_0B_HASH, MIN(ctx->digest->md_size, len));
			break;
		case NID_sha384:
			memcpy(md, &SHA384_0B_HASH, MIN(ctx->digest->md_size, len));
			break;
		case NID_sha512:
			memcpy(md, &SHA512_0B_HASH, MIN(ctx->digest->md_size, len));
			break;
	}	
}

int af_alg_DIGEST_final(EVP_MD_CTX *ctx, unsigned char *md, int len)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);

	/* if the user is trying to compute null hash 
	 * we should rather return the fixed value instead of trying to 
	 * offload it to the hw.
	 */
	if (!(ddata->flags & AF_ALG_UPDATE_CALLED)) {
		copy_0B_hash(ctx, md, len);
		return 1;
	}
 
	if( read(ddata->opfd, md, len) != len ) {
		TRACE("%s read\n", __PRETTY_FUNCTION__);
		return 0;
	}

	return 1;
}

int af_alg_DIGEST_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from)
{
	struct af_alg_digest_data *from = DIGEST_DATA(_from);
	struct af_alg_digest_data *to = DIGEST_DATA(_to);
	if( from == NULL || to == NULL )
		return 1;
	if( (to->opfd = accept(from->opfd, NULL, 0)) == -1 )
	{
		TRACE("%s accept opfd\n", __PRETTY_FUNCTION__);
		return 0;
	}
	if( (to->tfmfd = accept(from->tfmfd, NULL, 0)) == -1 )
	{
		TRACE("%s accept tfmfd\n", __PRETTY_FUNCTION__);
		return 0;
	}
	return 1;
}

int af_alg_DIGEST_cleanup(EVP_MD_CTX *ctx)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if(!ddata) 
		return 0;
	if( ddata->opfd != -1 )
		close(ddata->opfd);
	if( ddata->tfmfd != -1 )
		close(ddata->tfmfd);
	ddata->flags = 0;
	return 0;
}

int af_alg_list_pkey_meths(ENGINE *e __U__, EVP_PKEY_METHOD **pk_meth, const int **nids, int nid)
{
	static int hmac_pkey_nids[] =
	{
		EVP_PKEY_HMAC,
		0
	};
	if(!pk_meth)
	{
		*nids = hmac_pkey_nids;
		return 1;
	}
	if(nid == EVP_PKEY_HMAC)
	{
//		*pk_meth = &af_alg_hmac_pkey_meth;
		*pk_meth = NULL;
		return 1;
	}
	*pk_meth = NULL;
	return 0;
}

int af_alg_list_digests(ENGINE *e __U__, const EVP_MD **digest, const int **nids, int nid)
{
	if( !digest )
	{
		*nids = digests_used.data;
		return digests_used.len;
	}

	if( NID_store_contains(&digests_used, nid) == false ) {
		TRACE("%s unsupported digest\n", __PRETTY_FUNCTION__);
		return 0;
	}

	switch( nid )
	{
#define CASE(name)\
case NID_##name:\
	*digest = &af_alg_##name##_md;\
	break;

	CASE(sha1)
	CASE(sha224)
	CASE(sha256)
	CASE(sha384)
	CASE(sha512)
#undef CASE

	default:
		*digest = NULL;
	}
	return (*digest != NULL);
}

/**
 * SHA
 */
DECLARE_DIGEST(sha1, SHA)
DECLARE_MD(sha1, SHA, SHA)

DECLARE_DIGEST(sha224, SHA224)
DECLARE_MD(sha224, SHA224, SHA)

DECLARE_DIGEST(sha256, SHA256)
DECLARE_MD(sha256, SHA256, SHA256)

DECLARE_DIGEST(sha384, SHA384)
DECLARE_MD(sha384, SHA384, SHA512)

DECLARE_DIGEST(sha512, SHA512)
DECLARE_MD(sha512, SHA512, SHA512)



