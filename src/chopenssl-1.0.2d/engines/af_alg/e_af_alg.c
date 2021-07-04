/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <memory.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <sys/socket.h>
#include "if_alg.h"
#include <unistd.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/utsname.h>
#include "e_af_alg.h"
#include "ciphers.h"
#include "digests.h"

#define DYNAMIC_ENGINE
#define AF_ALG_ENGINE_ID	"af_alg"
#define AF_ALG_ENGINE_NAME	"use AF_ALG for AES crypto"
static struct af_alg_ker kerver;

static int afalg_get_kernver(struct af_alg_ker *ker)
{
	struct utsname kernel;
	char *saveptr = NULL;
	char *res = NULL;

	if (uname(&kernel))
		return -errno;

	/* 3.15.0 */
	res = strtok_r(kernel.release, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	ker->kernel_maj = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	ker->kernel_minor = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	ker->kernel_patchlevel = strtoul(res, NULL, 10);

	return 1;
}

/* return 1 if kernel is greater or equal to given values, otherwise 0 */
int afalg_compare_kernver(unsigned int maj, unsigned int minor,
			  unsigned int patchlevel)
{
	if (maj < kerver.kernel_maj)
		return 1;
	if (maj == kerver.kernel_maj) {
		if (minor < kerver.kernel_minor)
			return 1;
		if (minor == kerver.kernel_minor) {
			if (patchlevel <= kerver.kernel_patchlevel)
				return 1;
		}
	}
	return 0;
}

bool NID_store_contains(struct NID_store *store, int nid)
{
	size_t i=0;
	for( i=0;i<store->len;i++ )
	{
		if( store->data[i] == nid )
			return true;
	}
	return false;
}

bool NID_store_add(struct NID_store *store, int nid)
{
	int *r = malloc((store->len+1) * sizeof(int));
	memcpy(r, store->data, store->len * sizeof(int));
	free(store->data);
	store->data = r;
	store->data[store->len] = nid;
	store->len += 1;
	return true;
}

static int CIPHER_to_nid(const EVP_CIPHER *c)
{
	return EVP_CIPHER_nid(c);
}

static int MD_to_nid(const EVP_MD *d)
{
	return EVP_MD_type(d);
}

static bool NID_store_from_string(struct NID_store *store,
				  struct NID_store *available,
				  const char *names, const void *(*by_name)(const char *),
				  int (*to_nid)(const void *))
{
	char *str, *r;
	char *c = NULL;
	r = str = strdup(names);
	while( (c = strtok_r(r, " ", &r)) != NULL )
	{
		const void *ec = by_name(c);
		if( ec == NULL )
		{
			/* the cipher/digest is unknown */
			TRACE("%s unknown %s\n", __PRETTY_FUNCTION__, c);
			return false;
		}
		int nid = to_nid(ec);
		if( NID_store_contains(available, nid) == false ) {
			/* we do not support the cipher */
			TRACE("%s not supported %s\n", __PRETTY_FUNCTION__, c);
			return false;
		}

		if( NID_store_add(store, nid) == false) {
			TRACE("%s NID_store_add failed\n", __PRETTY_FUNCTION__);
			return false;
		}
	}
	return true;
}

int digest_nids[] = {
	NID_sha1,
	NID_sha224,
	NID_sha256,
	NID_sha384,
	NID_sha512,
};

struct NID_store digests_available =
{
	.len = sizeof(digest_nids)/sizeof(digest_nids[0]),
	.data = digest_nids,
};

struct NID_store digests_used =
{
	.len = 0,
};

int cipher_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_gcm,
	NID_aes_192_gcm,
	NID_aes_256_gcm,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_xts,
	NID_aes_256_xts,
	NID_aes_128_ccm,
	NID_aes_192_ccm,
	NID_aes_256_ccm,
};

struct NID_store ciphers_available =
{
	.len = sizeof(cipher_nids)/sizeof(cipher_nids[0]),
	.data = cipher_nids,
};

struct NID_store ciphers_used =
{
	.len = 0,
};

int af_alg_init(ENGINE * engine __U__)
{
	int sock;
	if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	close(sock);
	return afalg_get_kernver(&kerver);
}

int af_alg_finish(ENGINE * engine __U__)
{
	return 1;
}
/* The definitions for control commands specific to this engine */
#define AF_ALG_CMD_CIPHERS	ENGINE_CMD_BASE
#define AF_ALG_CMD_DIGESTS	(ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN af_alg_cmd_defns[] = {
	{AF_ALG_CMD_CIPHERS,"CIPHERS","which ciphers to run",ENGINE_CMD_FLAG_STRING},
	{AF_ALG_CMD_DIGESTS,"DIGESTS","which digests to run",ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

static void OpenSSL_add_alg_ciphers()
{
	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_cipher(EVP_aes_128_gcm());
	EVP_add_cipher(EVP_aes_192_gcm());
	EVP_add_cipher(EVP_aes_256_gcm());
}

static void OpenSSL_add_alg_digests()
{
	EVP_add_digest(EVP_sha());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	EVP_add_digest(EVP_sha384());
	EVP_add_digest(EVP_sha512());
}

static int af_alg_ctrl(ENGINE *e, int cmd, long i __U__, void *p,
		       void (*f)() __U__)
{
	OpenSSL_add_alg_ciphers();
	OpenSSL_add_alg_digests();
	switch( cmd )
	{
	case AF_ALG_CMD_CIPHERS:
		if( p == NULL ) {
			TRACE("%s AF_ALG_CMD_CIPHERS error\n", __PRETTY_FUNCTION__);
			return 1;
		}
		if (!NID_store_from_string(&ciphers_used, &ciphers_available, p, (void *)EVP_get_cipherbyname, (void *)CIPHER_to_nid)) {
			TRACE("%s Cipher store_from_string Error p:%s \n",
				 __PRETTY_FUNCTION__, (unsigned char*)p);
		}
		ENGINE_unregister_ciphers(e);
		ENGINE_register_ciphers(e);
		return 1;
	case AF_ALG_CMD_DIGESTS:
		if( p == NULL ) {
			TRACE("%s AF_ALG_CMD_DIGESTS error\n", __PRETTY_FUNCTION__);
			return 1;
		}
		if (!NID_store_from_string(&digests_used, &digests_available, p, (void *)EVP_get_digestbyname, (void *)MD_to_nid)) {
			TRACE("%s Digests store_from_string Error\n",
				 __PRETTY_FUNCTION__);
		}
		ENGINE_unregister_digests(e);
		ENGINE_register_digests(e);
		return 1;

	default:
		break;
	}
	return 0;
}

static int af_alg_bind_helper(ENGINE * e)
{
	if( !ENGINE_set_id(e, AF_ALG_ENGINE_ID) ||
		!ENGINE_set_init_function(e, af_alg_init) ||
		!ENGINE_set_finish_function(e, af_alg_finish) ||
		!ENGINE_set_name(e, AF_ALG_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, af_alg_list_ciphers) ||
		!ENGINE_set_digests (e, af_alg_list_digests) ||
		!ENGINE_set_ctrl_function(e, af_alg_ctrl) ||
		!ENGINE_set_cmd_defns(e, af_alg_cmd_defns))
		return 0;
	return 1;
}

ENGINE *ENGINE_af_alg(void)
{
	ENGINE *eng = ENGINE_new();
	if( !eng ) {
		TRACE("%s error\n", __PRETTY_FUNCTION__);
		return NULL;
	}

	if( !af_alg_bind_helper(eng) )
	{
		TRACE("%s bind error\n", __PRETTY_FUNCTION__);
		ENGINE_free(eng);
		return NULL;
	}
	return eng;
}

static int af_alg_bind_fn(ENGINE *e, const char *id)
{
	if( id && (strcmp(id, AF_ALG_ENGINE_ID) != 0) ) {
		TRACE("%s error\n", __PRETTY_FUNCTION__);
		return 0;
	}

	if( !af_alg_bind_helper(e) ) {
		TRACE("%s bind error\n", __PRETTY_FUNCTION__);
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(af_alg_bind_fn)

