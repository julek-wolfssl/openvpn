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

#define OPENSSL_ALL
#define OPENSSL_EXTRAs

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/objects.h>
#include <wolfssl/openssl/des.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/ssl.h>
#include <stdbool.h>

/** Generic cipher key type %context. */
typedef EVP_CIPHER cipher_kt_t;

/** Generic message digest key type %context. */
typedef EVP_MD md_kt_t;

/** Generic cipher %context. */
typedef EVP_CIPHER_CTX cipher_ctx_t;

/** Generic message digest %context. */
typedef EVP_MD_CTX md_ctx_t;

/** Generic HMAC %context. */
typedef HMAC_CTX hmac_ctx_t;

/** Maximum length of an IV */
#define OPENVPN_MAX_IV_LENGTH   16

/** Cipher is in CBC mode */
#define OPENVPN_MODE_CBC        EVP_CIPH_CBC_MODE

/** Cipher is in OFB mode */
#define OPENVPN_MODE_OFB        EVP_CIPH_OFB_MODE

/** Cipher is in CFB mode */
#define OPENVPN_MODE_CFB        EVP_CIPH_CFB_MODE

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
