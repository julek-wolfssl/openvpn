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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_WOLFSSL)

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto.h"
#include "crypto_backend.h"

void crypto_init_lib(void) {
	int ret;
    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
    }
}

void crypto_uninit_lib(void) {
	int ret;
    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }
}

void crypto_clear_error(void) {}

void crypto_init_lib_engine(const char *engine_name) {
    msg(M_INFO, "Note: wolfSSL does not have an engine");
}

void show_available_ciphers(void) {
    int nid;
    size_t i;

    /* If we ever exceed this, we must be more selective */
    const cipher_kt_t *cipher_list[CIPHER_LIST_SIZE];
    size_t num_ciphers = 0;

    for (nid = 0; nid < CIPHER_LIST_SIZE; ++nid) {
        const cipher_kt_t *cipher = wolfSSL_EVP_get_cipherbynid(nid);
        if (cipher) {
            cipher_list[num_ciphers++] = cipher;
        }
        if (num_ciphers == CIPHER_LIST_SIZE) {
            msg(M_INFO, "WARNING: Too many ciphers, not showing all");
            break;
        }
    }

    for (i = 0; i < num_ciphers; i++) {
		print_cipher(cipher_list[i]);
    }

    printf("\n");
}

void show_available_digests(void) {
    int nid;

    for (nid = 0; nid < 10000; ++nid) {
        const WOLFSSL_EVP_MD *digest = wolfSSL_EVP_get_digestbynid(nid);
        if (digest) {
            printf("%s %d bit digest size\n",
            		wolfSSL_OBJ_nid2sn(nid), wolfSSL_EVP_MD_size(digest) * 8);
        }
    }
    printf("\n");
}

void show_available_engines(void) {
    msg(M_INFO, "Note: wolfSSL does not have an engine");
}

bool crypto_pem_encode(const char *name, struct buffer *dst,
                       const struct buffer *src, struct gc_arena *gc) {
    bool ret = false;
    WOLFSSL_BIO *bio = wolfSSL_BIO_new(BIO_s_mem());
    if (!bio || !wolfSSL_PEM_write_bio(bio, name, "", BPTR(src), BLEN(src)))
    {
        ret = false;
        goto cleanup;
    }

    WOLFSSL_BUF_MEM *bptr;
    wolfSSL_BIO_get_mem_ptr(bio, &bptr);

    *dst = alloc_buf_gc(bptr->length + 1, gc);
    ASSERT(buf_write(dst, bptr->data, bptr->length));
    buf_null_terminate(dst);

    ret = true;
cleanup:
    if (!wolfSSL_BIO_free(bio))
    {
        ret = false;
    }

    return ret;
}

bool crypto_pem_decode(const char *name, struct buffer *dst,
                       const struct buffer *src) {
    bool ret = false;

    WOLFSSL_BIO *bio = wolfSSL_BIO_new_mem_buf((char *)BPTR(src), BLEN(src));
    if (!bio)
    {
        msg(M_FATAL, "Cannot open memory BIO for PEM decode");
    }

    char *name_read = NULL;
    char *header_read = NULL;
    uint8_t *data_read = NULL;
    long data_read_len = 0;
    if (!wolfSSL_PEM_read_bio(bio, &name_read, &header_read, &data_read,
                      	  	  &data_read_len))
    {
        msg(D_CRYPT_ERRORS, "%s: PEM decode failed", __func__);
        goto cleanup;
    }

    if (strcmp(name, name_read))
    {
        msg(D_CRYPT_ERRORS,
		    "%s: unexpected PEM name (got '%s', expected '%s')",
            __func__, name_read, name);
        goto cleanup;
    }

    uint8_t *dst_data = buf_write_alloc(dst, data_read_len);
    if (!dst_data)
    {
        msg(D_CRYPT_ERRORS, "%s: dst too small (%i, needs %li)", __func__,
            BCAP(dst), data_read_len);
        goto cleanup;
    }
    memcpy(dst_data, data_read, data_read_len);

    ret = true;
cleanup:
	wolfSSL_OPENSSL_free(name_read);
	wolfSSL_OPENSSL_free(header_read);
	wolfSSL_OPENSSL_free(data_read);
    if (!wolfSSL_BIO_free(bio))
    {
        ret = false;
    }

    return ret;
}

int rand_bytes(uint8_t *output, int len) {
    if (unlikely(WOLFSSL_SUCCESS != wolfSSL_RAND_bytes(output, len))) {
    	msg(D_CRYPT_ERRORS, "wolfSSL_RAND_bytes() failed");
        return 0;
    }
    return 1;
}

int key_des_num_cblocks(const cipher_kt_t *kt) {
    int ret = 0;
    if (kt && !strncmp(kt, "DES-", 4))
    {
		ret = wolfSSL_EVP_Cipher_key_length(kt) / sizeof(WOLFSSL_DES_cblock);

    }
    msg(D_CRYPTO_DEBUG, "CRYPTO INFO: n_DES_cblocks=%d", ret);
    return ret;
}

static const unsigned char odd_parity[256] = {
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110,
    110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127,
    127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143,
    143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158,
    158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174,
    174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191,
    191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206,
    206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223,
    223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239,
    239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254,
    254
};

static int DES_check_key_parity(WOLFSSL_const_DES_cblock *key)
{
    unsigned int i;

    for (i = 0; i < sizeof(WOLFSSL_DES_cblock); i++) {
        if ((*key)[i] != odd_parity[(*key)[i]])
            return 0;
    }
    return 1;
}


bool key_des_check(uint8_t *key, int key_len, int ndc) {
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);

    for (i = 0; i < ndc; ++i)
    {
    	WOLFSSL_DES_cblock *dc = (WOLFSSL_DES_cblock *) buf_read_alloc(&b, sizeof(WOLFSSL_DES_cblock));
        if (!dc)
        {
        	msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
            goto err;
        }
        if (wolfSSL_DES_is_weak_key(dc))
        {
        	msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
            goto err;
        }
        if (!DES_check_key_parity(dc))
        {
        	msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
            goto err;
        }
    }
    return true;

err:
	wolfSSL_ERR_clear_error();
    return false;
}

void key_des_fixup(uint8_t *key, int key_len, int ndc) {
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);
    for (i = 0; i < ndc; ++i)
    {
    	WOLFSSL_DES_cblock *dc = (WOLFSSL_DES_cblock *) buf_read_alloc(&b, sizeof(WOLFSSL_DES_cblock));
        if (!dc)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
            wolfSSL_ERR_clear_error();
            return;
        }
        wolfSSL_DES_set_odd_parity(dc);
    }
}

void cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                            unsigned char src[DES_KEY_LENGTH],
                            unsigned char dst[DES_KEY_LENGTH]) {
	WOLFSSL_DES_key_schedule sched;

	wolfSSL_DES_set_key_unchecked((WOLFSSL_DES_cblock *)key, &sched);
	wolfSSL_DES_ecb_encrypt((WOLFSSL_DES_cblock *)src, (WOLFSSL_DES_cblock *)dst,
							&sched, DES_ENCRYPT);
}

const cipher_kt_t *cipher_kt_get(const char *ciphername) {
	return wolfSSL_EVP_get_cipherbyname(ciphername);
}

const char *cipher_kt_name(const cipher_kt_t *cipher_kt) {
	return cipher_kt;
}

int cipher_kt_key_size(const cipher_kt_t *cipher_kt) {
	return wolfSSL_EVP_Cipher_key_length(cipher_kt);
}

int cipher_kt_iv_size(const cipher_kt_t *cipher_kt) {
	return wolfSSL_EVP_CIPHER_iv_length(cipher_kt);
}

int cipher_kt_block_size(const cipher_kt_t *cipher_kt) {
	return wolfSSL_EVP_CIPHER_block_size(cipher_kt);
}

int cipher_kt_tag_size(const cipher_kt_t *cipher_kt) {
    if (cipher_kt_mode_aead(cipher_kt)) {
        return OPENVPN_AEAD_TAG_LENGTH;
    } else {
        return 0;
    }
}

bool cipher_kt_insecure(const cipher_kt_t *cipher) {
    return !(cipher_kt_block_size(cipher) >= 128 / 8);
}

int cipher_kt_mode(const cipher_kt_t *cipher_kt) {
    ASSERT(NULL != cipher_kt);
    return WOLFSSL_EVP_CIPHER_mode(cipher_kt);
}

bool cipher_kt_mode_cbc(const cipher_kt_t *cipher) {
    return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC;
}

bool cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher) {
    return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB
    		          || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB);
}

bool cipher_kt_mode_aead(const cipher_kt_t *cipher) {
#ifdef HAVE_AEAD_CIPHER_MODES
    msg(M_FATAL, "wolfSSL does not support AEAD ciphers in OpenSSL compatibility layer");
#endif

    return false;
}

cipher_ctx_t *cipher_ctx_new(void) {
	WOLFSSL_EVP_CIPHER_CTX *ctx = wolfSSL_EVP_CIPHER_CTX_new();
    check_malloc_return(ctx);
    return ctx;
}

void cipher_ctx_free(cipher_ctx_t *ctx) {
	wolfSSL_EVP_CIPHER_CTX_free(ctx);
}

void cipher_ctx_init(cipher_ctx_t *ctx, const uint8_t *key, int key_len,
                     const cipher_kt_t *kt, int enc) {
    ASSERT(NULL != kt && NULL != ctx);

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    if (!wolfSSL_EVP_CipherInit(ctx, kt, NULL, NULL, enc))
    {
        msg(M_FATAL, "EVP cipher init #1");
    }
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
    if (!wolfSSL_EVP_CIPHER_CTX_set_key_length(ctx, key_len))
    {
        msg(M_FATAL, "EVP set key size");
    }
#endif
    if (!wolfSSL_EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, enc))
    {
        msg(M_FATAL, "EVP cipher init #2");
    }

    /* make sure we used a big enough key */
    ASSERT(wolfSSL_EVP_CIPHER_CTX_key_length(ctx) <= key_len);
}

void cipher_ctx_cleanup(cipher_ctx_t *ctx) {
	wolfSSL_EVP_CIPHER_CTX_cleanup(ctx);
}

int cipher_ctx_iv_length(const cipher_ctx_t *ctx) {
    return wolfSSL_EVP_CIPHER_CTX_iv_length(ctx);
}

int cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len) {
#ifdef HAVE_AEAD_CIPHER_MODES
	msg(M_FATAL, "wolfSSL does not support AEAD ciphers in OpenSSL compatibility layer");
#else
    ASSERT(0);
#endif
    return 0;
}

int cipher_ctx_block_size(const cipher_ctx_t *ctx) {
    return wolfSSL_EVP_CIPHER_CTX_block_size(ctx);
}

int cipher_ctx_mode(const cipher_ctx_t *ctx) {
    return wolfSSL_EVP_CIPHER_CTX_mode(ctx);
}

const cipher_kt_t *cipher_ctx_get_cipher_kt(const cipher_ctx_t *ctx) {
    const struct cipher *ent;


    static const struct cipher{
            unsigned char type;
            const char *name;
    } cipher_tbl[] = {
        {AES_128_CBC_TYPE, "AES-128-CBC"},
        {AES_192_CBC_TYPE, "AES-192-CBC"},
        {AES_256_CBC_TYPE, "AES-256-CBC"},
    	{AES_128_CTR_TYPE, "AES-128-CTR"},
    	{AES_192_CTR_TYPE, "AES-192-CTR"},
    	{AES_256_CTR_TYPE, "AES-256-CTR"},
    	{AES_128_ECB_TYPE, "AES-128-ECB"},
    	{AES_192_ECB_TYPE, "AES-192-ECB"},
    	{AES_256_ECB_TYPE, "AES-256-ECB"},
        {DES_CBC_TYPE, "DES-CBC"},
        {DES_ECB_TYPE, "DES-ECB"},
        {DES_EDE3_CBC_TYPE, "DES-EDE3-CBC"},
        {DES_EDE3_ECB_TYPE, "DES-EDE3-ECB"},
        {ARC4_TYPE, "ARC4"},
    #ifdef HAVE_IDEA
        {IDEA_CBC_TYPE, "IDEA-CBC"},
    #endif
        { 0, NULL}
    };

	if (ctx == NULL)
		return NULL;

    for (ent = cipher_tbl; ent->name != NULL; ent++) {
        if (ctx->cipherType == ent->type) {
            return (WOLFSSL_EVP_CIPHER *)ent->name;
        }
    }
	return NULL;
}

int cipher_ctx_reset(cipher_ctx_t *ctx, const uint8_t *iv_buf) {
    return wolfSSL_EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv_buf, -1);
}

int cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len) {
#ifdef HAVE_AEAD_CIPHER_MODES
	msg(M_FATAL, "wolfSSL does not support AEAD ciphers in OpenSSL compatibility layer");
#else
    ASSERT(0);
#endif
    return 0;
}

int cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                      uint8_t *src, int src_len) {
    if (!wolfSSL_EVP_CipherUpdate(ctx, dst, dst_len, src, src_len)) {
        msg(M_FATAL, "%s: wolfSSL_EVP_CipherUpdate() failed", __func__);
    }
    return 1;
}

int cipher_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len) {
    return wolfSSL_EVP_CipherFinal(ctx, dst, dst_len);
}

int cipher_ctx_final_check_tag(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                               uint8_t *tag, size_t tag_len) {
#ifdef HAVE_AEAD_CIPHER_MODES
	msg(M_FATAL, "wolfSSL does not support AEAD ciphers in OpenSSL compatibility layer");
#else
    ASSERT(0);
#endif
    return 0;
}

const md_kt_t *md_kt_get(const char *digest) {
    const WOLFSSL_EVP_MD *md = NULL;
    ASSERT(digest);
    md = wolfSSL_EVP_get_digestbyname(digest);
    if (!md) {
        msg(M_FATAL, "Message hash algorithm '%s' not found", digest);
    }
    if (wolfSSL_EVP_MD_size(md) > MAX_HMAC_KEY_LENGTH) {
        msg(M_FATAL, "Message hash algorithm '%s' uses a default hash "
        		 	 "size (%d bytes) which is larger than " PACKAGE_NAME "'s current "
					 "maximum hash size (%d bytes)",
					 digest, EVP_MD_size(md), MAX_HMAC_KEY_LENGTH);
    }
    return md;
}

const char *md_kt_name(const md_kt_t *kt) {
    if (NULL == kt) {
        return "[null-digest]";
    }
    return kt;
}

int md_kt_size(const md_kt_t *kt) {
    return wolfSSL_EVP_MD_size(kt);
}

int md_full(const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst) {
    unsigned int in_md_len = 0;
    return wolfSSL_EVP_Digest(src, src_len, dst, &in_md_len, kt, NULL);
}

md_ctx_t *md_ctx_new(void) {
	WOLFSSL_EVP_MD_CTX *ctx = wolfSSL_EVP_MD_CTX_new();
    check_malloc_return(ctx);
    return ctx;
}

void md_ctx_free(md_ctx_t *ctx) {
	wolfSSL_EVP_MD_CTX_free(ctx);
}

void md_ctx_init(md_ctx_t *ctx, const md_kt_t *kt) {
    ASSERT(NULL != ctx && NULL != kt);

    wolfSSL_EVP_MD_CTX_init(ctx);
    wolfSSL_EVP_DigestInit(ctx, kt);
}

void md_ctx_cleanup(md_ctx_t *ctx) {
	wolfSSL_EVP_MD_CTX_cleanup(ctx);
}

int md_ctx_size(const md_ctx_t *ctx) {
    return wolfSSL_EVP_MD_CTX_size(ctx);
}

void md_ctx_update(md_ctx_t *ctx, const uint8_t *src, int src_len) {
	wolfSSL_EVP_DigestUpdate(ctx, src, src_len);
}

void md_ctx_final(md_ctx_t *ctx, uint8_t *dst) {
    unsigned int in_md_len = 0;
    wolfSSL_EVP_DigestFinal(ctx, dst, &in_md_len);
}

hmac_ctx_t *hmac_ctx_new(void) {
    int ret;
	WOLFSSL_HMAC_CTX *ctx = (WOLFSSL_HMAC_CTX*) malloc(sizeof(WOLFSSL_HMAC_CTX));
    check_malloc_return(ctx);
    if ((ret = wolfSSL_HMAC_CTX_Init(ctx)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_CTX_Init failed. Errno: %d", ret);
    }
    return ctx;
}

void hmac_ctx_free(hmac_ctx_t *ctx) {
	wolfSSL_HMAC_cleanup(ctx);
}

static const WOLFSSL_EVP_MD* wolfSSL_get_MD_from_ctx(const WOLFSSL_HMAC_CTX* ctx)
{
    WOLFSSL_ENTER("EVP_DigestFinal");
    switch (ctx->type) {
#ifndef NO_MD4
        case WC_HASH_TYPE_MD4:
        	return wolfSSL_EVP_md4();
#endif
#ifndef NO_MD5
        case WC_HASH_TYPE_MD5:
        	return wolfSSL_EVP_md5();
#endif
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
        	return wolfSSL_EVP_md4();
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
        	return wolfSSL_EVP_sha1();
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
        	return wolfSSL_EVP_sha256();
#endif /* !NO_SHA256 */
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
        	return wolfSSL_EVP_sha384();
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
        	return wolfSSL_EVP_sha512();
#endif /* WOLFSSL_SHA512 */
        default:
            return NULL;
    }
}

void hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, int key_length,
                   const md_kt_t *kt) {
	int ret;
	WOLFSSL_EVP_MD* md;
    ASSERT(NULL != kt && NULL != ctx);

    if ((ret = wolfSSL_HMAC_cleanup(ctx)) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_cleanup failed. Errno: %d", ret);
    }
    if ((ret = wolfSSL_HMAC_CTX_Init(ctx)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_CTX_Init failed. Errno: %d", ret);
    }
    if ((ret = wolfSSL_HMAC_Init_ex(ctx, key, key_length, kt, NULL)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_Init_ex failed. Errno: %d", ret);
    }

    /* make sure we used a big enough key */
    md = wolfSSL_get_MD_from_ctx(ctx);
    ASSERT(NULL != md);
    ASSERT(wolfSSL_EVP_MD_size(md) <= key_length);
}

void hmac_ctx_cleanup(hmac_ctx_t *ctx) {
	int ret;
    if ((ret = wolfSSL_HMAC_cleanup(ctx)) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_cleanup failed. Errno: %d", ret);
    }
    if ((ret = wolfSSL_HMAC_CTX_Init(ctx)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_HMAC_CTX_Init failed. Errno: %d", ret);
    }
}

int hmac_ctx_size(const hmac_ctx_t *ctx) {
	WOLFSSL_EVP_MD* md;
    md = wolfSSL_get_MD_from_ctx(ctx);
    ASSERT(NULL != md);
    return wolfSSL_EVP_MD_size(md);
}

void hmac_ctx_reset(hmac_ctx_t *ctx) {
	wolfSSL_HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);
}

void hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len) {
	wolfSSL_HMAC_Update(ctx, src, src_len);
}

void hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst) {
    unsigned int in_hmac_len = 0;
    wolfSSL_HMAC_Final(ctx, dst, &in_hmac_len);
}

#endif /* ENABLE_CRYPTO_WOLFSSL */
