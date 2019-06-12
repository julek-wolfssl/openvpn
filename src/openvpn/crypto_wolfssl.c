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
    msg(M_WARN, "Note: wolfSSL does not have an engine");
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
            msg(M_WARN, "WARNING: Too many ciphers, not showing all");
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
    msg(M_WARN, "Note: wolfSSL does not have an engine");
}

bool crypto_pem_encode(const char *name, struct buffer *dst,
                       const struct buffer *src, struct gc_arena *gc);

bool crypto_pem_decode(const char *name, struct buffer *dst,
                       const struct buffer *src);

int rand_bytes(uint8_t *output, int len) {
    if (unlikely(WOLFSSL_SUCCESS != wolfSSL_RAND_bytes(output, len))) {
    	msg(M_WARN, "wolfSSL_RAND_bytes() failed");
        return 0;
    }
    return 1;
}

int key_des_num_cblocks(const cipher_kt_t *kt);

bool key_des_check(uint8_t *key, int key_len, int ndc);

void key_des_fixup(uint8_t *key, int key_len, int ndc);

void cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                            unsigned char src[DES_KEY_LENGTH],
                            unsigned char dst[DES_KEY_LENGTH]);

const cipher_kt_t *cipher_kt_get(const char *ciphername) {
	return wolfSSL_EVP_get_cipherbyname(ciphername);
}

const char *cipher_kt_name(const cipher_kt_t *cipher_kt) {
	return wolfSSL_CIPHER_get_name(cipher_kt);
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

int cipher_kt_tag_size(const cipher_kt_t *cipher_kt);

bool cipher_kt_insecure(const cipher_kt_t *cipher);

int cipher_kt_mode(const cipher_kt_t *cipher_kt);

bool cipher_kt_mode_cbc(const cipher_kt_t *cipher);

bool cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher);

bool cipher_kt_mode_aead(const cipher_kt_t *cipher);

cipher_ctx_t *cipher_ctx_new(void);

void cipher_ctx_free(cipher_ctx_t *ctx);

void cipher_ctx_init(cipher_ctx_t *ctx, const uint8_t *key, int key_len,
                     const cipher_kt_t *kt, int enc);

void cipher_ctx_cleanup(cipher_ctx_t *ctx);

int cipher_ctx_iv_length(const cipher_ctx_t *ctx);

int cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len);

int cipher_ctx_block_size(const cipher_ctx_t *ctx);

int cipher_ctx_mode(const cipher_ctx_t *ctx);

const cipher_kt_t *cipher_ctx_get_cipher_kt(const cipher_ctx_t *ctx);

int cipher_ctx_reset(cipher_ctx_t *ctx, const uint8_t *iv_buf);

int cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len);

int cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                      uint8_t *src, int src_len);

int cipher_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len);

int cipher_ctx_final_check_tag(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                               uint8_t *tag, size_t tag_len);

const md_kt_t *md_kt_get(const char *digest);

const char *md_kt_name(const md_kt_t *kt);

int md_kt_size(const md_kt_t *kt);

int md_full(const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst);

md_ctx_t *md_ctx_new(void);

void md_ctx_free(md_ctx_t *ctx);

void md_ctx_init(md_ctx_t *ctx, const md_kt_t *kt);

void md_ctx_cleanup(md_ctx_t *ctx);

int md_ctx_size(const md_ctx_t *ctx);

void md_ctx_update(md_ctx_t *ctx, const uint8_t *src, int src_len);

void md_ctx_final(md_ctx_t *ctx, uint8_t *dst);

hmac_ctx_t *hmac_ctx_new(void);

void hmac_ctx_free(hmac_ctx_t *ctx);

void hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, int key_length,
                   const md_kt_t *kt);

void hmac_ctx_cleanup(hmac_ctx_t *ctx);

int hmac_ctx_size(const hmac_ctx_t *ctx);

void hmac_ctx_reset(hmac_ctx_t *ctx);

void hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len);

void hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst);

const char *translate_cipher_name_from_openvpn(const char *cipher_name);

const char *translate_cipher_name_to_openvpn(const char *cipher_name);

#endif /* ENABLE_CRYPTO_WOLFSSL */
