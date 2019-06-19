/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2019 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2019 Fox Crypto B.V. <openvpn@fox-it.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file Data Channel Cryptography wolfSSL-specific backend interface
 */

#ifndef CRYPTO_WOLFSSL_H_
#define CRYPTO_WOLFSSL_H_

#define WOLFSSL_DES_ECB

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/ssl.h>

// Digests
#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/wolfcrypt/md5.h>

// Encryption ciphers
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/poly1305.h>

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>

#define NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>

#include <stdbool.h>

# define SHA224_DIGEST_LENGTH    WC_SHA224_DIGEST_SIZE
# define SHA256_DIGEST_LENGTH    WC_SHA256_DIGEST_SIZE
# define SHA384_DIGEST_LENGTH    WC_SHA384_DIGEST_SIZE
# define SHA512_DIGEST_LENGTH    WC_SHA512_DIGEST_SIZE

#define NOT_IMPLEMENTED -0x666

/** Generic cipher key type %context. */
typedef enum {
	/* DO NOT CHANGE ORDER OF ELEMENTS */
	OV_WC_AES_128_CBC_TYPE = 0,
	OV_WC_AES_192_CBC_TYPE,
	OV_WC_AES_256_CBC_TYPE,
	OV_WC_AES_128_CTR_TYPE,
	OV_WC_AES_192_CTR_TYPE,
	OV_WC_AES_256_CTR_TYPE,
	OV_WC_AES_128_ECB_TYPE,
	OV_WC_AES_192_ECB_TYPE,
	OV_WC_AES_256_ECB_TYPE,
	OV_WC_AES_128_OFB_TYPE,
	OV_WC_AES_192_OFB_TYPE,
	OV_WC_AES_256_OFB_TYPE,
	OV_WC_AES_128_CFB_TYPE,
	OV_WC_AES_192_CFB_TYPE,
	OV_WC_AES_256_CFB_TYPE,
	OV_WC_AES_128_GCM_TYPE,
	OV_WC_AES_192_GCM_TYPE,
	OV_WC_AES_256_GCM_TYPE,
	OV_WC_DES_CBC_TYPE,
	OV_WC_DES_ECB_TYPE,
	OV_WC_DES_EDE3_CBC_TYPE,
	OV_WC_DES_EDE3_ECB_TYPE,
	OV_WC_CHACHA20_POLY1305_TYPE,
	/* LEAVE NULL CIPHER AS LAST ELEMENT */
	OV_WC_NULL_CIPHER_TYPE,
} cipher_kt_t;

/* Make sure the order is the same as in cipher_kt_t */
const cipher_kt_t cipher_static[] = {
	OV_WC_AES_128_CBC_TYPE,
	OV_WC_AES_192_CBC_TYPE,
	OV_WC_AES_256_CBC_TYPE,
	OV_WC_AES_128_CTR_TYPE,
	OV_WC_AES_192_CTR_TYPE,
	OV_WC_AES_256_CTR_TYPE,
	OV_WC_AES_128_ECB_TYPE,
	OV_WC_AES_192_ECB_TYPE,
	OV_WC_AES_256_ECB_TYPE,
	OV_WC_AES_128_OFB_TYPE,
	OV_WC_AES_192_OFB_TYPE,
	OV_WC_AES_256_OFB_TYPE,
	OV_WC_AES_128_CFB_TYPE,
	OV_WC_AES_192_CFB_TYPE,
	OV_WC_AES_256_CFB_TYPE,
	OV_WC_AES_128_GCM_TYPE,
	OV_WC_AES_192_GCM_TYPE,
	OV_WC_AES_256_GCM_TYPE,
	OV_WC_DES_CBC_TYPE,
	OV_WC_DES_ECB_TYPE,
	OV_WC_DES_EDE3_CBC_TYPE,
	OV_WC_DES_EDE3_ECB_TYPE,
	OV_WC_CHACHA20_POLY1305_TYPE,
	OV_WC_NULL_CIPHER_TYPE,
};

const struct cipher{
		cipher_kt_t type;
        const char *name;
} cipher_tbl[] = {
	/* Make sure the order is the same as in cipher_kt_t */
    {OV_WC_AES_128_CBC_TYPE, "AES-128-CBC"},
    {OV_WC_AES_192_CBC_TYPE, "AES-192-CBC"},
    {OV_WC_AES_256_CBC_TYPE, "AES-256-CBC"},
	{OV_WC_AES_128_CTR_TYPE, "AES-128-CTR"},
	{OV_WC_AES_192_CTR_TYPE, "AES-192-CTR"},
	{OV_WC_AES_256_CTR_TYPE, "AES-256-CTR"},
	{OV_WC_AES_128_ECB_TYPE, "AES-128-ECB"},
	{OV_WC_AES_192_ECB_TYPE, "AES-192-ECB"},
	{OV_WC_AES_256_ECB_TYPE, "AES-256-ECB"},
	{OV_WC_AES_128_OFB_TYPE,"AES-128-OFB"},
	{OV_WC_AES_192_OFB_TYPE,"AES-192-OFB"},
	{OV_WC_AES_256_OFB_TYPE,"AES-256-OFB"},
	{OV_WC_AES_128_CFB_TYPE,"AES-128-CFB"},
	{OV_WC_AES_192_CFB_TYPE,"AES-192-CFB"},
	{OV_WC_AES_256_CFB_TYPE,"AES-256-CFB"},
	{OV_WC_AES_128_GCM_TYPE,"AES-128-GCM"},
	{OV_WC_AES_192_GCM_TYPE,"AES-192-GCM"},
	{OV_WC_AES_256_GCM_TYPE,"AES-256-GCM"},
    {OV_WC_DES_CBC_TYPE, "DES-CBC"},
    {OV_WC_DES_ECB_TYPE, "DES-ECB"},
    {OV_WC_DES_EDE3_CBC_TYPE, "DES-EDE3-CBC"},
    {OV_WC_DES_EDE3_ECB_TYPE, "DES-EDE3-ECB"},
    {OV_WC_CHACHA20_POLY1305_TYPE, "CHACHA20-POLY1305"},
    { 0, NULL}
};

/** Generic cipher %context. */
typedef struct {
	union {
	#ifndef NO_AES
	    Aes  aes;
	#endif
	#ifndef NO_DES3
	    Des  des;
	    Des3 des3;
	#endif
	#ifdef HAVE_CHACHA
	    struct {
	    	ChaCha chacha;
	        uint8_t tag_poly1305Key[CHACHA20_POLY1305_AEAD_KEYSIZE];
	        uint8_t init_poly1305Key[CHACHA20_POLY1305_AEAD_KEYSIZE];
	    } chacha20_poly1305;
	#endif
	} cipher;
	cipher_kt_t cipher_type;
	enum {
		OV_WC_ENCRYPT,
		OV_WC_DECRYPT,
	} enc;
	union {
		uint8_t aes[AES_BLOCK_SIZE];
		uint8_t des[DES_BLOCK_SIZE];
	#ifdef HAVE_CHACHA
		uint8_t chacha[CHACHA_CHUNK_BYTES];
	#endif
	} buf;
	int buf_used;
} cipher_ctx_t;

/** Generic message digest key type %context. */
typedef enum {
	OV_WC_MD4,
	OV_WC_MD5,
	OV_WC_SHA,
	OV_WC_SHA224,
	OV_WC_SHA384,
	OV_WC_SHA512,
	OV_WC_SHA3,
	OV_WC_RIPEMD,
} md_kt_t;

/** Generic message digest %context. */
typedef struct {
	union {
	#ifndef NO_MD4
		Md4    md4;
	#endif
	#ifndef NO_MD5
		Md5    md5;
	#endif
	wc_Sha    sha;
	#ifdef WOLFSSL_SHA224
		wc_Sha224 sha224;
	#endif
	wc_Sha256 sha256;
	#ifdef WOLFSSL_SHA384
		wc_Sha384 sha384;
	#endif
	#ifdef WOLFSSL_SHA512
		wc_Sha512 sha512;
	#endif
	#ifdef WOLFSSL_RIPEMD
		RipeMd ripemd;
	#endif
	#ifdef WOLFSSL_SHA3
		wc_Sha3 sha3;
	#endif
	} hash;
	md_kt_t hash_type;
} md_ctx_t;

/** Generic HMAC %context. */
typedef Hmac hmac_ctx_t;

/** Maximum length of an IV */
#define OPENVPN_MAX_IV_LENGTH   16

typedef enum {
	OPENVPN_MODE_CBC,
	OPENVPN_MODE_CFB,
	OPENVPN_MODE_OFB, // this needs to be implemented using CBC with a stream of 0's
	OPENVPN_MODE_GCM,
} cipher_modes;

#define DES_KEY_LENGTH 8
#define MD4_DIGEST_LENGTH       16

/** Cipher should encrypt */
#define OPENVPN_OP_ENCRYPT      1

/** Cipher should decrypt */
#define OPENVPN_OP_DECRYPT      0


/* Set if variable length cipher */
#define EVP_CIPH_VARIABLE_LENGTH 0x8

extern bool cipher_kt_var_key_size(const cipher_kt_t *cipher);

#define CIPHER_LIST_SIZE 1000

#endif /* CRYPTO_WOLFSSL_H_ */
