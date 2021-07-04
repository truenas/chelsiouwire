#include <crypto/sha.h>
#include <linux/scatterlist.h>

static const u32 chcr_sha1_init[SHA1_DIGEST_SIZE / 4] = {
	SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4,
};

static const u32 cxgb4_sha224_init[SHA256_DIGEST_SIZE / 4] = {
	SHA224_H0, SHA224_H1, SHA224_H2, SHA224_H3,
	SHA224_H4, SHA224_H5, SHA224_H6, SHA224_H7,
};

static const u32 cxgb4_sha256_init[SHA256_DIGEST_SIZE / 4] = {
	SHA256_H0, SHA256_H1, SHA256_H2, SHA256_H3,
	SHA256_H4, SHA256_H5, SHA256_H6, SHA256_H7,
};

static const u64 sha384_init[SHA512_DIGEST_SIZE / 4] = {
	SHA384_H0, SHA384_H1, SHA384_H2, SHA384_H3,
	SHA384_H4, SHA384_H5, SHA384_H6, SHA384_H7,
};

static const u64 sha512_init[SHA512_DIGEST_SIZE / 4] = {
	SHA512_H0, SHA512_H1, SHA512_H2, SHA512_H3,
	SHA512_H4, SHA512_H5, SHA512_H6, SHA512_H7,
};

/*
 * The AES s-transform matrix (s-box).
 */
static const u8 aes_sbox[256] = {
	99,  124, 119, 123, 242, 107, 111, 197, 48,  1,   103, 43,  254, 215, 171, 118,
	202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175, 156, 164, 114, 192,
	183, 253, 147, 38,  54,  63,  247, 204, 52,  165, 229, 241, 113, 216, 49, 21,
	4,   199, 35,  195, 24,  150, 5,   154, 7,   18,  128, 226, 235, 39,  178, 117,
	9,   131, 44,  26,  27,  110, 90,  160, 82,  59,  214, 179, 41,  227, 47, 132,
	83,  209, 0,   237, 32,  252, 177, 91,  106, 203, 190, 57,  74,  76,  88, 207,
	208, 239, 170, 251, 67,  77,  51,  133, 69,  249, 2,   127, 80,  60,  159, 168,
	81,  163, 64,  143, 146, 157, 56,  245, 188, 182, 218, 33,  16,  255, 243, 210,
	205, 12,  19,  236, 95,  151, 68,  23,  196, 167, 126, 61,  100, 93,  25, 115,
	96,  129, 79,  220, 34,  42,  144, 136, 70,  238, 184, 20,  222, 94,  11, 219,
	224, 50,  58,  10,  73,  6,   36,  92,  194, 211, 172, 98,  145, 149, 228, 121,
	231, 200, 55,  109, 141, 213, 78,  169, 108, 86,  244, 234, 101, 122, 174, 8,
	186, 120, 37,  46,  28,  166, 180, 198, 232, 221, 116, 31,  75,  189, 139, 138,
	112, 62,  181, 102, 72,  3,   246, 14,  97,  53,  87,  185, 134, 193, 29, 158,
	225, 248, 152, 17,  105, 217, 142, 148, 155, 30,  135, 233, 206, 85,  40, 223,
	140, 161, 137, 13,  191, 230, 66,  104, 65,  153, 45,  15,  176, 84,  187, 22
};

/* AES has a 32 bit word round constants for each round in the key schedule.
 * round_constant[i] is really Rcon[i+1] in FIPS187.
 */
static u32 round_constant[11] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000, 0x6C000000
};

/* Apply the s-box to each of the four occtets in w. */
static inline u32 aes_ks_subword(const u32 w)
{
	u8 bytes[4];

	*(u32 *)(&bytes[0]) = w;
	bytes[0] = aes_sbox[bytes[0]];
	bytes[1] = aes_sbox[bytes[1]];
	bytes[2] = aes_sbox[bytes[2]];
	bytes[3] = aes_sbox[bytes[3]];

	return *(u32 *)(&bytes[0]);
}

/* dec_key - OUTPUT - Reverse round key
 * key - INPUT - key
 * keylength - INPUT - length of the key in number of bits
 */
static inline void get_aes_decrypt_key(unsigned char *dec_key,
				       const unsigned char *key,
				       unsigned int keylength)
{
	u32 temp;
	u32 w_ring[8]; /* nk is max 8, use element 0..(nk - 1) as a ringbuffer*/
	u8  w_last_ix;
	int i, j, k = 0, flag = 0, start = 1, t1 = 0;
	u8  nr, nk;

	switch (keylength) {
	case 128:
		nk = 4;
		nr = 10;
		start = 4;
		break;
	case 192:
		nk = 6;
		nr = 12;
		start = 2;
		break;
	case 256:
		nk = 8;
		nr = 14;
		start = 0;
		break;
	default:
		return;
	};

	j = keylength >> 3;

	/* Need to do host byte order correction here since key is byte oriented
	 * and the kx algorithm is word (u32) oriented.
	 */
	for (i = 0; i < nk; i += 1)
		w_ring[i] = be32_to_cpu(*(u32 *)&key[4 * i]);

	i = (int)nk;
	w_last_ix = i - 1;
	while (i < (4 * (nr + 2))) {
		temp = w_ring[w_last_ix];
		if (!(i % nk)) {
			/* RotWord(temp) */
			temp = (temp << 8) | (temp >> 24);
			temp = aes_ks_subword(temp);
			temp ^= round_constant[i / nk - 1];
		} else if ((nk > 6) && ((i % nk) == 4)) {
			temp = aes_ks_subword(temp);
		}
		/* This is the same as (i-Nk) mod Nk */
		w_last_ix = (w_last_ix + 1) % nk;
		temp ^= w_ring[w_last_ix];
		w_ring[w_last_ix] = temp;
		/* We need the round keys for round Nr+1 and Nr+2 (round key
		 * Nr+2 is the round key beyond the last one used when
		 * encrypting).  Rounds are numbered starting from 0, Nr=10
		 * implies 11 rounds are used in encryption/decryption.
		 */
		if (i >= (4 * (nr - 1))) {
			/* Need to do host byte order correction here, the key
			 * is byte oriented. */
			if (t1 >= start) {
				if (j >= 0)
					j -= 4;
				if ((j < 0) && !flag) {
					k = (keylength >> 3) - 4;
					flag = 1;
				}
				if (k && flag)
					k += 4;
				if (j < 0)
					j = 0;
				*(u32 *)((u8 *)dec_key + j + k) = htonl(temp);
			} else {
				t1++;
			}
		}
		++i;
	}
}
