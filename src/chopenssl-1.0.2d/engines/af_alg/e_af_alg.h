#ifndef HAVE_E_AF_ALG_H
#define HAVE_E_AF_ALG_H
#include <stdint.h>
#include <stdbool.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Socket options */
#define ALG_SET_KEY			1
#define ALG_SET_IV			2
#define ALG_SET_OP			3

/* Operations */
#define ALG_OP_DECRYPT			0
#define ALG_OP_ENCRYPT			1


#define HAVE___ATTRIBUTE__ 1

#if HAVE___ATTRIBUTE__
#  define __UNUSED__ __attribute__((unused))
#  define __U__      __attribute__((unused))
#else
#  define __UNUSED__
#  define __U__
#endif	/* HAVE___ATTRIBUTE__ */

struct af_alg_ker {
	unsigned long kernel_maj, kernel_minor, kernel_patchlevel;
};


struct NID_store
{
	size_t len;
	int *data;
};
bool NID_store_contains(struct NID_store *store, int nid);

extern struct NID_store ciphers_available;
extern struct NID_store ciphers_used;
extern int afalg_compare_kernver(unsigned int maj, unsigned int minor,
					unsigned int patchlevel);
extern struct NID_store digests_available;
extern struct NID_store digests_used;
#define DEBUG
#ifdef DEBUG
#define TRACE(...) fprintf(stderr,__VA_ARGS__)
#else
#define TRACE(...)
#endif
#endif
