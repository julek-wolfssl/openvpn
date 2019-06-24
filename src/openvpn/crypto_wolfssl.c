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
        msg(D_CRYPT_ERRORS, "wolfCrypt_Init failed");
        printf("wolfCrypt_Init failed %d\n", ret);
    }
}

void crypto_uninit_lib(void) {
    int ret;
    if ((ret = wolfCrypt_Cleanup()) != 0) {
        msg(D_CRYPT_ERRORS, "wolfCrypt_Cleanup failed");
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }
}

void crypto_clear_error(void) {}

void crypto_init_lib_engine(const char *engine_name) {
    msg(M_INFO, "Note: wolfSSL does not have an engine");
}

void show_available_ciphers(void) {
    static char ciphers[4096];
    char* x;

    int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

    for (x = ciphers; *x != '\0'; x++) {
        if (*x == ':')
            *x = '\n';
    }

    if (ret == WOLFSSL_SUCCESS)
        printf("%s\n", ciphers);
}

void show_available_digests(void) {
    #ifdef WOLFSSL_MD2
        printf("MD2 128 bit digest size\n")
    #endif
    #ifndef NO_MD4
        printf("MD4 128 bit digest size\n");
    #endif
    #ifndef NO_MD5
        printf("MD5 128 bit digest size\n");
    #endif
    #ifndef NO_SHA
        printf("SHA1 160 bit digest size\n");
    #endif
    #ifndef NO_SHA256
        printf("SHA256 256 bit digest size\n");
    #endif
    #ifdef WOLFSSL_SHA384
        printf("SHA384 384 bit digest size\n");
    #endif
    #ifdef WOLFSSL_SHA512
        printf("SHA512 512 bit digest size\n");
    #endif
}

void show_available_engines(void) {
    msg(M_INFO, "Note: wolfSSL does not have an engine");
}


#define PEM_BEGIN              "-----BEGIN "
#define PEM_BEGIN_LEN          11
#define PEM_LINE_END           "-----\n"
#define PEM_LINE_END_LEN       6
#define PEM_END                "-----END "
#define PEM_END_LEN            9

uint32_t der_to_pem_len(uint32_t der_len) {
    uint32_t pem_len;
    pem_len = (der_len + 2) / 3 * 4;
    pem_len += (pem_len + 63) / 64;
    return pem_len;
}

bool crypto_pem_encode(const char *name, struct buffer *dst,
                       const struct buffer *src, struct gc_arena *gc) {
    uint8_t* pem_buf;
    uint32_t pem_len = der_to_pem_len(BLEN(src));
    uint8_t* out_buf;
    uint8_t* out_buf_ptr;
    bool ret = false;
    int err;
    int name_len = strlen(name);
    int out_len = PEM_BEGIN_LEN + PEM_LINE_END_LEN + name_len + pem_len +
                      PEM_END_LEN + PEM_LINE_END_LEN + name_len;

    if (!(pem_buf = (uint8_t*) malloc(pem_len))) {
        return false;
    }

    if (!(out_buf = (uint8_t*) malloc(out_len))) {
        goto out_buf_err;
    }

    if ((err = Base64_Encode(BPTR(src), BLEN(src), pem_buf, &pem_len)) != 0) {
        msg(M_INFO, "Base64_Encode failed with Errno: %d", err);
        goto Base64_Encode_err;
    }

    out_buf_ptr = out_buf;
    memcpy(out_buf_ptr, PEM_BEGIN, PEM_BEGIN_LEN);
    out_buf_ptr += PEM_BEGIN_LEN;
    memcpy(out_buf_ptr, name, name_len);
    out_buf_ptr += name_len;
    memcpy(out_buf_ptr, PEM_LINE_END, PEM_LINE_END_LEN);
    out_buf_ptr += PEM_LINE_END_LEN;
    memcpy(out_buf_ptr, pem_buf, pem_len);
    out_buf_ptr += pem_len;
    memcpy(out_buf_ptr, PEM_END, PEM_END_LEN);
    out_buf_ptr += PEM_END_LEN;
    memcpy(out_buf_ptr, name, name_len);
    out_buf_ptr += name_len;
    memcpy(out_buf_ptr, PEM_LINE_END, PEM_LINE_END_LEN);

    *dst = alloc_buf_gc(out_len + 1, gc);
    ASSERT(buf_write(dst, out_buf, out_len));
    buf_null_terminate(dst);

    ret = true;

Base64_Encode_err:
    free(out_buf);
out_buf_err:
    free(pem_buf);

    return ret;
}

uint32_t pem_to_der_len(uint32_t pem_len) {
    static int PEM_LINE_SZ = 64;
    int plainSz = pem_len - ((pem_len + (PEM_LINE_SZ - 1)) / PEM_LINE_SZ );
    return (plainSz * 3 + 3) / 4;
}

bool crypto_pem_decode(const char *name, struct buffer *dst,
                       const struct buffer *src) {
    int name_len = strlen(name);
    int err;
    uint8_t* src_buf;
    bool ret = false;
    unsigned int der_len = BLEN(src) - PEM_BEGIN_LEN - PEM_LINE_END_LEN -
                           PEM_END_LEN - PEM_LINE_END_LEN -
                           name_len - name_len - 1;
    unsigned int pem_len = pem_to_der_len(der_len);

    ASSERT(BLEN(src) > PEM_BEGIN_LEN + PEM_LINE_END_LEN + PEM_END_LEN + PEM_LINE_END_LEN);

    if (!(src_buf = (uint8_t*) malloc(BLEN(src)))) {
        msg(M_FATAL, "Cannot allocate memory for PEM decode");
        return false;
    }
    memcpy(src_buf, BPTR(src), BLEN(src));

    src_buf[PEM_BEGIN_LEN + name_len] = '\0';

    if (strcmp((char*)(src_buf + PEM_BEGIN_LEN), name)) {
        msg(D_CRYPT_ERRORS,
            "%s: unexpected PEM name (got '%s', expected '%s')",
            __func__, src_buf + PEM_BEGIN_LEN, name);
        goto cleanup;
    }

    if ((err = Base64_Decode(BPTR(src) + PEM_BEGIN_LEN + PEM_LINE_END_LEN + name_len,
                             der_len, src_buf, &pem_len)) != 0) {
        msg(M_INFO, "Base64_Decode failed with Errno: %d", err);
        goto cleanup;
    }

    uint8_t *dst_data = buf_write_alloc(dst, pem_len);
    if (!dst_data)
    {
        msg(D_CRYPT_ERRORS, "%s: dst too small (%i, needs %i)", __func__,
            BCAP(dst), pem_len);
        goto cleanup;
    }

    memcpy(dst_data, src_buf, pem_len);

    ret = true;

cleanup:
    free(src_buf);
    return ret;
}

int rand_bytes(uint8_t *output, int len) {
    WC_RNG rng;
    int ret;

    if ((ret = wc_InitRng(&rng)) != 0){
        msg(D_CRYPT_ERRORS, "wc_InitRng failed Errno: %d", ret);
        return 0;
    }

    if ((ret = wc_RNG_GenerateBlock(&rng, output, len)) != 0){
        msg(D_CRYPT_ERRORS, "wc_RNG_GenerateBlock failed Errno: %d", ret);
        return 0;
    }

    if ((ret = wc_FreeRng(&rng)) != 0){
        msg(D_CRYPT_ERRORS, "wc_FreeRng failed Errno: %d", ret);
        return 0;
    }

    return 1;
}

int key_des_num_cblocks(const cipher_kt_t *kt) {
    int ret = 0;

    if (kt) {
        switch (*kt) {
        case OV_WC_DES_CBC_TYPE:
        case OV_WC_DES_ECB_TYPE:
            ret = DES_KEY_SIZE/DES_BLOCK_SIZE;
            break;
        case OV_WC_DES_EDE3_CBC_TYPE:
        case OV_WC_DES_EDE3_ECB_TYPE:
            ret = DES3_KEY_SIZE/DES_BLOCK_SIZE;
            break;
        default:
            ret = 0;
        }
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

static int DES_check_key_parity(const uint8_t *key)
{
    unsigned int i;

    for (i = 0; i < DES_BLOCK_SIZE; i++) {
        if (key[i] != odd_parity[key[i]])
            return 0;
    }
    return 1;
}


/* return true in fail case (1) */
static int DES_check(word32 mask, word32 mask2, uint8_t* key)
{
    word32 value[2];

    value[0] = mask;
    value[1] = mask2;
    return (memcmp(value, key, sizeof(value)) == 0)? 1: 0;
}

static inline uint32_t ByteReverseWord32(uint32_t value)
{
    /* 6 instructions with rotate instruction, 8 without */
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return value << 16U | value >> 16U;
}


/* check is not weak. Weak key list from Nist "Recommendation for the Triple
 * Data Encryption Algorithm (TDEA) Block Cipher"
 *
 * returns 1 if is weak 0 if not
 */
static int wolfSSL_DES_is_weak_key(uint8_t* key) {
    word32 mask, mask2;

    mask = 0x01010101; mask2 = 0x01010101;
    if (DES_check(mask, mask2, key)) {
        return 1;
    }

    mask = 0xFEFEFEFE; mask2 = 0xFEFEFEFE;
    if (DES_check(mask, mask2, key)) {
        return 1;
    }

    mask = 0xE0E0E0E0; mask2 = 0xF1F1F1F1;
    if (DES_check(mask, mask2, key)) {
        return 1;
    }

    mask = 0x1F1F1F1F; mask2 = 0x0E0E0E0E;
    if (DES_check(mask, mask2, key)) {
        return 1;
    }

    /* semi-weak *key check (list from same Nist paper) */
    mask  = 0x011F011F; mask2 = 0x010E010E;
    if (DES_check(mask, mask2, key) ||
       DES_check(ByteReverseWord32(mask), ByteReverseWord32(mask2), key)) {
        return 1;
    }

    mask  = 0x01E001E0; mask2 = 0x01F101F1;
    if (DES_check(mask, mask2, key) ||
       DES_check(ByteReverseWord32(mask), ByteReverseWord32(mask2), key)) {
        return 1;
    }

    mask  = 0x01FE01FE; mask2 = 0x01FE01FE;
    if (DES_check(mask, mask2, key) ||
       DES_check(ByteReverseWord32(mask), ByteReverseWord32(mask2), key)) {
        return 1;
    }

    mask  = 0x1FE01FE0; mask2 = 0x0EF10EF1;
    if (DES_check(mask, mask2, key) ||
       DES_check(ByteReverseWord32(mask), ByteReverseWord32(mask2), key)) {
        return 1;
    }

    mask  = 0x1FFE1FFE; mask2 = 0x0EFE0EFE;
    if (DES_check(mask, mask2, key) ||
       DES_check(ByteReverseWord32(mask), ByteReverseWord32(mask2), key)) {
        return 1;
    }

    return 0;
}


bool key_des_check(uint8_t *key, int key_len, int ndc) {
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);

    for (i = 0; i < ndc; ++i)
    {
        uint8_t *dc = (uint8_t *) buf_read_alloc(&b, DES_KEY_SIZE);
        if (!dc)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
            return false;
        }
        if (wolfSSL_DES_is_weak_key(dc))
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
            return false;
        }
        if (!DES_check_key_parity(dc))
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
            return false;
        }
    }
    return true;

}

/* Sets the parity of the DES key for use */
void wolfSSL_DES_set_odd_parity(uint8_t* myDes)
{
    uint32_t i;

    for (i = 0; i < DES_BLOCK_SIZE; i++) {
        uint8_t c = myDes[i];
        if ((
            ((c >> 1) & 0x01) ^
            ((c >> 2) & 0x01) ^
            ((c >> 3) & 0x01) ^
            ((c >> 4) & 0x01) ^
            ((c >> 5) & 0x01) ^
            ((c >> 6) & 0x01) ^
            ((c >> 7) & 0x01)) != 1) {
            msg(D_CRYPTO_DEBUG, "Setting odd parity bit");
            myDes[i] = *((unsigned char*)myDes + i) | 0x01;
        }
    }
}

void key_des_fixup(uint8_t *key, int key_len, int ndc) {
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);
    for (i = 0; i < ndc; ++i)
    {
        uint8_t *dc = (uint8_t *) buf_read_alloc(&b, DES_BLOCK_SIZE);
        if (!dc)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
            return;
        }
        wolfSSL_DES_set_odd_parity(dc);
    }
}

void cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                            unsigned char src[DES_KEY_LENGTH],
                            unsigned char dst[DES_KEY_LENGTH]) {
    Des myDes;

    if (src == NULL || dst == NULL || key == NULL) {
        msg(D_CRYPT_ERRORS, "Bad argument passed to cipher_des_encrypt_ecb");
    }

    wc_Des_SetKey(&myDes, key, NULL, DES_ENCRYPTION);
    wc_Des_EcbEncrypt(&myDes, dst, src, DES_KEY_LENGTH);
}

const cipher_kt_t *cipher_kt_get(const char *ciphername) {
    const struct cipher* cipher;

    for (cipher = cipher_tbl; cipher->name != NULL; cipher++) {
        if(strncmp(ciphername, cipher->name, strlen(cipher->name)+1) == 0) {
            return &cipher_static[cipher->type];
        }
    }
    return NULL;
}

const char *cipher_kt_name(const cipher_kt_t *cipher_kt) {
    if (!cipher_kt) {
        return "[null-digest]";
    } else {
        return cipher_tbl[*cipher_kt].name;
    }
}

int cipher_kt_key_size(const cipher_kt_t *cipher_kt) {
    if (cipher_kt == NULL) {
        return 0;
    }
    switch (*cipher_kt) {
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_128_CTR_TYPE:
    case OV_WC_AES_128_ECB_TYPE:
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_128_GCM_TYPE:
        return AES_128_KEY_SIZE;
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_192_CTR_TYPE:
    case OV_WC_AES_192_ECB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
        return AES_192_KEY_SIZE;
    case OV_WC_AES_256_CBC_TYPE:
    case OV_WC_AES_256_CTR_TYPE:
    case OV_WC_AES_256_ECB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
        return AES_256_KEY_SIZE;
    case OV_WC_DES_CBC_TYPE:
    case OV_WC_DES_ECB_TYPE:
        return DES_KEY_SIZE;
    case OV_WC_DES_EDE3_CBC_TYPE:
    case OV_WC_DES_EDE3_ECB_TYPE:
        return DES3_KEY_SIZE;
    case OV_WC_CHACHA20_POLY1305_TYPE:
        return CHACHA20_POLY1305_AEAD_KEYSIZE;
    case OV_WC_NULL_CIPHER_TYPE:
        return 0;
    }
    return 0;
}

int cipher_kt_iv_size(const cipher_kt_t *cipher_kt) {
    if (cipher_kt == NULL) {
        return 0;
    }
    switch (*cipher_kt) {
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_256_CBC_TYPE:
    case OV_WC_AES_128_CTR_TYPE:
    case OV_WC_AES_192_CTR_TYPE:
    case OV_WC_AES_256_CTR_TYPE:
    case OV_WC_AES_128_ECB_TYPE:
    case OV_WC_AES_192_ECB_TYPE:
    case OV_WC_AES_256_ECB_TYPE:
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
    case OV_WC_AES_128_GCM_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
        return AES_BLOCK_SIZE;
    case OV_WC_DES_CBC_TYPE:
    case OV_WC_DES_ECB_TYPE:
    case OV_WC_DES_EDE3_CBC_TYPE:
    case OV_WC_DES_EDE3_ECB_TYPE:
        return DES_BLOCK_SIZE;
    case OV_WC_CHACHA20_POLY1305_TYPE:
        return CHACHA_IV_BYTES;
    case OV_WC_NULL_CIPHER_TYPE:
        return 0;
    }
    return 0;
}

int cipher_kt_block_size(const cipher_kt_t *cipher_kt) {
    if (cipher_kt == NULL) {
        return 0;
    }
    switch (*cipher_kt) {
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_256_CBC_TYPE:
    case OV_WC_AES_128_CTR_TYPE:
    case OV_WC_AES_192_CTR_TYPE:
    case OV_WC_AES_256_CTR_TYPE:
    case OV_WC_AES_128_ECB_TYPE:
    case OV_WC_AES_192_ECB_TYPE:
    case OV_WC_AES_256_ECB_TYPE:
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
    case OV_WC_AES_128_GCM_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
        return AES_BLOCK_SIZE;
    case OV_WC_DES_CBC_TYPE:
    case OV_WC_DES_ECB_TYPE:
    case OV_WC_DES_EDE3_CBC_TYPE:
    case OV_WC_DES_EDE3_ECB_TYPE:
        return DES_BLOCK_SIZE;
    case OV_WC_CHACHA20_POLY1305_TYPE:
        return CHACHA_CHUNK_BYTES;
    case OV_WC_NULL_CIPHER_TYPE:
        return 0;
    }
    return 0;
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
    if (cipher_kt == NULL) {
        return 0;
    }
    switch (*cipher_kt) {
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_256_CBC_TYPE:
    case OV_WC_DES_CBC_TYPE:
    case OV_WC_DES_EDE3_CBC_TYPE:
        return OPENVPN_MODE_CBC;
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
        return OPENVPN_MODE_OFB;
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
        return OPENVPN_MODE_CFB;
    case OV_WC_AES_128_GCM_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
    case OV_WC_CHACHA20_POLY1305_TYPE:
        return OPENVPN_MODE_GCM;
    case OV_WC_NULL_CIPHER_TYPE:
        break;
    }
    return 0;
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
    if (cipher) {
        switch (*cipher) {
        case OV_WC_AES_128_GCM_TYPE:
        case OV_WC_AES_192_GCM_TYPE:
        case OV_WC_AES_256_GCM_TYPE:
        case OV_WC_CHACHA20_POLY1305_TYPE:
            return true;
        }
    }
#endif
    return false;
}

static void wc_cipher_init(cipher_ctx_t* ctx) {
    ctx->cipher_type = OV_WC_NULL_CIPHER_TYPE;
    ctx->enc = OV_WC_ENCRYPT;
}

cipher_ctx_t *cipher_ctx_new(void) {
    cipher_ctx_t *ctx = (cipher_ctx_t*) malloc(sizeof *ctx);
    check_malloc_return(ctx);
    wc_cipher_init(ctx);
    return ctx;
}

void cipher_ctx_free(cipher_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

static void check_key_length(const cipher_kt_t kt, int key_len) {
    int correct_key_len;

    if (!kt) {
        return;
    }

    correct_key_len = cipher_kt_key_size(&kt);

    if (key_len != correct_key_len) {
        msg(M_FATAL,
            "Wrong key length for chosen cipher.\n"
            "Cipher chosen: %s\n"
            "Key length expected: %d\n"
            "Key length provided: %d\n",
        cipher_kt_name(&kt), correct_key_len, key_len);
    }
}

static int wolfssl_ctx_init(cipher_ctx_t *ctx, const uint8_t *key, int key_len, const uint8_t* iv,
                            const cipher_kt_t *kt, int enc) {
    int ret;

    switch (*kt) {
    /* SETUP AES */
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_128_CTR_TYPE:
    case OV_WC_AES_128_ECB_TYPE:
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_128_GCM_TYPE:
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_192_CTR_TYPE:
    case OV_WC_AES_192_ECB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
    case OV_WC_AES_256_CBC_TYPE:
    case OV_WC_AES_256_CTR_TYPE:
    case OV_WC_AES_256_ECB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
        if (key) {
            if ((ret = wc_AesSetKey(
                    &ctx->cipher.aes, key, key_len, iv,
                    enc == OPENVPN_OP_ENCRYPT ? AES_ENCRYPTION : AES_DECRYPTION
                )) != 0) {
                msg(M_FATAL, "wc_AesSetKey failed with Errno: %d", ret);
                return 0;
            }
        }
        if (iv && !key) {
            if ((ret = wc_AesSetIV(&ctx->cipher.aes, iv))) {
                msg(M_FATAL, "wc_AesSetIV failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_DES_CBC_TYPE:
    case OV_WC_DES_ECB_TYPE:
        if (key) {
            if ((ret = wc_Des_SetKey(
                    &ctx->cipher.des, key, iv,
                    enc == OPENVPN_OP_ENCRYPT ? DES_ENCRYPTION : DES_DECRYPTION
                )) != 0) {
                msg(M_FATAL, "wc_Des_SetKey failed with Errno: %d", ret);
                return 0;
            }
        }
        if (iv && !key) {
            wc_Des_SetIV(&ctx->cipher.des, iv);
        }
        break;
    case OV_WC_DES_EDE3_CBC_TYPE:
    case OV_WC_DES_EDE3_ECB_TYPE:
        if (key) {
            if ((ret = wc_Des3_SetKey(
                    &ctx->cipher.des3, key, iv,
                    enc == OPENVPN_OP_ENCRYPT ? DES_ENCRYPTION : DES_DECRYPTION
                )) != 0) {
                msg(M_FATAL, "wc_Des3_SetKey failed with Errno: %d", ret);
                return 0;
            }
        }
        if (iv && !key) {
            if ((ret = wc_Des3_SetIV(&ctx->cipher.des3, iv)) != 0) {
                msg(M_FATAL, "wc_Des3_SetIV failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_CHACHA20_POLY1305_TYPE:
        if (key) {
            memcpy(ctx->cipher.chacha20_poly1305.init_poly1305Key, key,
                   CHACHA20_POLY1305_AEAD_KEYSIZE);
        }
        if (iv) {
            if ((ret = wc_Chacha_SetKey(&ctx->cipher.chacha20_poly1305.chacha,
                                        ctx->cipher.chacha20_poly1305.init_poly1305Key,
                                        CHACHA20_POLY1305_AEAD_KEYSIZE)) != 0) {
                msg(M_FATAL, "wc_Chacha_SetKey failed with Errno: %d", ret);
                return 0;
            }
            if ((ret = wc_Chacha_SetIV(&ctx->cipher.chacha20_poly1305.chacha,
                                       iv, 0)) != 0) {
                msg(M_FATAL, "wc_Chacha_SetIV failed with Errno: %d", ret);
                return 0;
            }
            if ((ret = wc_Chacha_Process(&ctx->cipher.chacha20_poly1305.chacha,
                                         ctx->cipher.chacha20_poly1305.tag_poly1305Key,
                                         ctx->cipher.chacha20_poly1305.init_poly1305Key,
                                         CHACHA20_POLY1305_AEAD_KEYSIZE)) != 0) {
                msg(M_FATAL, "wc_Chacha_Process failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_NULL_CIPHER_TYPE:
        return 0;
    }

    ctx->cipher_type = *kt;
    ctx->enc = enc == OPENVPN_OP_ENCRYPT ? OV_WC_ENCRYPT : OV_WC_DECRYPT;
    ctx->buf_used = 0;
    return 1;
}

void cipher_ctx_init(cipher_ctx_t *ctx, const uint8_t *key, int key_len,
                     const cipher_kt_t *kt, int enc) {
    int ret;
    ASSERT(NULL != kt && NULL != ctx && NULL != key);

    check_key_length(*kt, key_len);
    if ((ret = wolfssl_ctx_init(ctx, key, key_len, NULL, kt, enc)) != 1) {
        msg(M_FATAL, "wolfssl_ctx_init failed with Errno: %d", ret);
    }
}

void cipher_ctx_cleanup(cipher_ctx_t *ctx) {
    if (ctx) {
        ctx->cipher_type = OV_WC_NULL_CIPHER_TYPE;
        ctx->enc = -1;
        memset(&ctx->cipher, 0, sizeof(ctx->cipher));
    }
}

int cipher_ctx_iv_length(const cipher_ctx_t *ctx) {
    return cipher_kt_iv_size(&ctx->cipher_type);
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
    return cipher_kt_key_size(&ctx->cipher_type);
}

int cipher_ctx_mode(const cipher_ctx_t *ctx) {
    return cipher_kt_mode(&ctx->cipher_type);
}

const cipher_kt_t *cipher_ctx_get_cipher_kt(const cipher_ctx_t *ctx) {
    if (ctx) {
        return &ctx->cipher_type;
    }
    return NULL;
}

int cipher_ctx_reset(cipher_ctx_t *ctx, const uint8_t *iv_buf) {
    int ret;
    if ((ret = wolfssl_ctx_init(ctx, NULL, 0, iv_buf, &ctx->cipher_type, -1)) != 1) {
        msg(M_FATAL, "wolfssl_ctx_init failed with Errno: %d", ret);
        return 0;
    }
    return 1;
}

int cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len) {
#ifdef HAVE_AEAD_CIPHER_MODES
    msg(M_FATAL, "wolfSSL does not support AEAD ciphers in OpenSSL compatibility layer");
#else
    ASSERT(0);
#endif
    return 0;
}

static int wolfssl_ctx_update_blocks(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                                         uint8_t *src, int src_len) {
    int ret;
    ASSERT((src_len % cipher_kt_block_size(&ctx->cipher_type)) == 0);

    switch (ctx->cipher_type) {
    case OV_WC_AES_128_CBC_TYPE:
    case OV_WC_AES_192_CBC_TYPE:
    case OV_WC_AES_256_CBC_TYPE:
        if (ctx->enc == OV_WC_ENCRYPT) {
            if ((ret = wc_AesCbcEncrypt(&ctx->cipher.aes, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_AesCbcEncrypt failed with Errno: %d", ret);
                return 0;
            }
        } else {
            if ((ret = wc_AesCbcDecrypt(&ctx->cipher.aes, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_AesCbcDecrypt failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_AES_128_CTR_TYPE:
    case OV_WC_AES_192_CTR_TYPE:
    case OV_WC_AES_256_CTR_TYPE:
        /* encryption and decryption are the same for CTR */
        if ((ret = wc_AesCtrEncrypt(&ctx->cipher.aes, dst, src, src_len)) != 0) {
            msg(M_FATAL, "wc_AesCtrEncrypt failed with Errno: %d", ret);
            return 0;
        }
        break;
    case OV_WC_AES_128_ECB_TYPE:
    case OV_WC_AES_192_ECB_TYPE:
    case OV_WC_AES_256_ECB_TYPE:
        msg(M_FATAL, "ECB not yet implemented");
        break;
    case OV_WC_AES_128_OFB_TYPE:
    case OV_WC_AES_192_OFB_TYPE:
    case OV_WC_AES_256_OFB_TYPE:
        msg(M_FATAL, "OFB is needs to be tested");
        /* encryption and decryption are the same for OFB */
        uint8_t zero_in[AES_BLOCK_SIZE] = {0};
        uint8_t out_buf[AES_BLOCK_SIZE];
        int i, j;
        for (i = 0; i < src_len; i += AES_BLOCK_SIZE) {
            if ((ret = wc_AesCfbEncrypt(&ctx->cipher.aes, out_buf, zero_in, AES_BLOCK_SIZE)) != 0) {
                msg(M_FATAL, "wc_AesCfbEncrypt failed with Errno: %d", ret);
                return 0;
            }
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                dst[i + j] = out_buf[j] ^ src[i + j];
            }
        }
        break;
    case OV_WC_AES_128_CFB_TYPE:
    case OV_WC_AES_192_CFB_TYPE:
    case OV_WC_AES_256_CFB_TYPE:
        if (ctx->enc == OV_WC_ENCRYPT) {
            if ((ret = wc_AesCfbEncrypt(&ctx->cipher.aes, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_AesCfbEncrypt failed with Errno: %d", ret);
                return 0;
            }
        } else {
            if ((ret = wc_AesCfbDecrypt(&ctx->cipher.aes, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_AesCfbDecrypt failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_AES_128_GCM_TYPE:
    case OV_WC_AES_192_GCM_TYPE:
    case OV_WC_AES_256_GCM_TYPE:
        msg(M_FATAL, "AEAD NOT IMPLEMENTED YET");
        break;
    case OV_WC_DES_CBC_TYPE:
        if (ctx->enc == OV_WC_ENCRYPT) {
            if ((ret = wc_Des_CbcEncrypt(&ctx->cipher.des, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_Des3_CbcEncrypt failed with Errno: %d", ret);
                return 0;
            }
        } else {
            if ((ret = wc_Des_CbcDecrypt(&ctx->cipher.des, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_Des3_CbcDecrypt failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_DES_EDE3_CBC_TYPE:
        if (ctx->enc == OV_WC_ENCRYPT) {
            if ((ret = wc_Des3_CbcEncrypt(&ctx->cipher.des3, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_Des3_CbcEncrypt failed with Errno: %d", ret);
                return 0;
            }
        } else {
            if ((ret = wc_Des3_CbcDecrypt(&ctx->cipher.des3, dst, src, src_len)) != 0) {
                msg(M_FATAL, "wc_Des3_CbcDecrypt failed with Errno: %d", ret);
                return 0;
            }
        }
        break;
    case OV_WC_DES_ECB_TYPE:
    case OV_WC_DES_EDE3_ECB_TYPE:
        msg(M_FATAL, "ECB not yet implemented");
        break;
    case OV_WC_CHACHA20_POLY1305_TYPE:
        msg(M_FATAL, "AEAD NOT IMPLEMENTED YET");
        break;
    case OV_WC_NULL_CIPHER_TYPE:
        return 0;
    }
    *dst_len += src_len;
    return 1;
}

static int wolfssl_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                              uint8_t *src, int src_len) {
    int ret;
    int block_size = cipher_kt_block_size(&ctx->cipher_type);
    int block_leftover;

    if (!ctx || !src || (src_len < 0) || !dst_len|| !dst) return 0;

    *dst_len = 0;
    if (!src_len) {
        /* nothing to do */
        return 1;
    }

    if (ctx->buf_used) {
        if ((ctx->buf_used + src_len) < block_size) {
            memcpy((&ctx->buf) + ctx->buf_used, src, src_len);
            ctx->buf_used += src_len;
            return 1;
        } else {
            memcpy((&ctx->buf) + ctx->buf_used, src, block_size - ctx->buf_used);
            src += block_size - ctx->buf_used;
            src_len -= block_size - ctx->buf_used;
            if ((ret = wolfssl_ctx_update_blocks(ctx, dst, dst_len,
                                                 (uint8_t*)&(ctx->buf), block_size) != 1)) {
                msg(M_FATAL, "%s: wolfssl_ctx_update_blocks() failed", __func__);
                return 0;
            }
            ctx->buf_used = 0;
            dst += block_size;
            *dst_len += block_size;
        }
    }

    ASSERT(ctx->buf_used == 0);

    if (src_len < block_size) {
        memcpy(&ctx->buf, src, src_len);
        ctx->buf_used = src_len;
        return 1;
    }

    block_leftover = src_len % block_size;
    if ((ret = wolfssl_ctx_update_blocks(ctx, dst, dst_len,
                                         src, src_len - block_leftover) != 1)) {
        msg(M_FATAL, "%s: wolfssl_ctx_update_blocks() failed", __func__);
        return 0;
    }

    if (block_leftover) {
        memcpy(&ctx->buf, src + (src_len - block_leftover), block_leftover);
        ctx->buf_used = block_leftover;
    } else if (ctx->enc == OV_WC_DECRYPT) {
        /* copy last decrypted block to check padding in final call */
        memcpy(&ctx->buf, dst + (src_len - block_size), block_size);
    }

    return 1;
}

int cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                      uint8_t *src, int src_len) {
    if (!wolfssl_ctx_update(ctx, dst, dst_len, src, src_len)) {
        msg(M_FATAL, "%s: wolfssl_ctx_update() failed", __func__);
    }
    return 1;
}

static void pad_block(cipher_ctx_t *ctx) {
    int i, block_size;
    block_size = cipher_kt_block_size(&ctx->cipher_type);
    for (i = ctx->buf_used; i < block_size; i++) {
        ((uint8_t*)&(ctx->buf))[i] = (uint8_t)(block_size - ctx->buf_used);
    }
}

static int check_pad(cipher_ctx_t *ctx, uint8_t *buff, int block_size)
{
    int i;
    int n;
    n = buff[block_size-1];
    if (n > block_size) return -1;
    for (i = 0; i < n; i++) {
        if (buff[block_size-i-1] != n)
            return -1;
    }
    return block_size - n;
}

static int wolfssl_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len) {
    int block_size;
    int pad_left;

    if (!ctx || !dst_len|| !dst) {
        return 0;
    }

    block_size = cipher_kt_block_size(&ctx->cipher_type);
    *dst_len = 0;

    if (ctx->enc == OV_WC_ENCRYPT) {
        pad_block(ctx);
        if (wolfssl_ctx_update_blocks(ctx, dst, dst_len, (uint8_t*)&ctx->buf,
                                      block_size) != 1) {
            return 0;
        }
    } else {
        if (ctx->buf_used != 0) {
            *dst_len = 0;
            msg(M_FATAL, "%s: not enough padding for decrypt", __func__);
            return 0;
        }
        if ((pad_left = check_pad(ctx, (uint8_t*)&ctx->buf, block_size)) >= 0) {
            *dst_len = -pad_left;
        }
        else {
            msg(M_FATAL, "%s: padding is incorrect", __func__);
            return 0;
        }
    }

    return 1;
}

int cipher_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len) {
    return wolfssl_ctx_final(ctx, dst, dst_len);
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
    const struct digest* digest_;

    for (digest_ = digest_tbl; digest_->name != NULL; digest_++) {
        if(strncmp(digest, digest_->name, strlen(digest_->name)+1) == 0) {
            return &digest_static[digest_->type];
        }
    }
    return NULL;
}

const char *md_kt_name(const md_kt_t *kt) {
    if (!kt) {
        return "[null-digest]";
    } else {
        return digest_tbl[*kt].name;
    }
}

int md_kt_size(const md_kt_t *kt) {
    if (!kt || *kt >= OV_WC_NULL_DIGEST) {
        return 0;
    }
    return wc_HashGetDigestSize(OV_to_WC_hash_type[*kt]);
}

int md_full(const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst) {
    int ret;

    if (!kt || !src || !dst) {
        return 0;
    }

    if ((ret = wc_Hash(OV_to_WC_hash_type[*kt], src, src_len, dst, -1)) != 0) {
        msg(M_FATAL, "md_full failed with Errno: %d", ret);
        return 0;
    }
    return 1;
}

md_ctx_t *md_ctx_new(void) {
    md_ctx_t *ctx = (md_ctx_t*) malloc(sizeof(md_ctx_t));
    check_malloc_return(ctx);
    return ctx;
}

void md_ctx_free(md_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void md_ctx_init(md_ctx_t *ctx, const md_kt_t *kt) {
    ASSERT(NULL != ctx && NULL != kt);

    wc_HashInit(&ctx->hash, OV_to_WC_hash_type[*kt]);
    ctx->hash_type = *kt;
}

void md_ctx_cleanup(md_ctx_t *ctx) {
    if (ctx) {
        wc_HashFree(&ctx->hash, OV_to_WC_hash_type[ctx->hash_type]);
    }
}

int md_ctx_size(const md_ctx_t *ctx) {
    return md_kt_size(&ctx->hash_type);
}

void md_ctx_update(md_ctx_t *ctx, const uint8_t *src, int src_len) {
    int ret;

    if ((ret = wc_HashUpdate(&ctx->hash, OV_to_WC_hash_type[ctx->hash_type],
                             src, src_len)) != 0) {
        msg(M_FATAL, "wc_HashUpdate failed with Errno: %d", ret);
    }
}

void md_ctx_final(md_ctx_t *ctx, uint8_t *dst) {
    int ret;

    if ((ret = wc_HashFinal(&ctx->hash, OV_to_WC_hash_type[ctx->hash_type], dst)) != 0) {
        msg(M_FATAL, "wc_HashFinal failed with Errno: %d", ret);
    }
}

hmac_ctx_t *hmac_ctx_new(void) {
    hmac_ctx_t *ctx = (hmac_ctx_t*) malloc(sizeof(hmac_ctx_t));
    check_malloc_return(ctx);
    return ctx;
}

void hmac_ctx_free(hmac_ctx_t *ctx) {
    if (ctx) {
        wc_HmacFree(&ctx->hmac);
    }
}

void hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, int key_length,
                   const md_kt_t *kt) {
    int ret;
    ASSERT(NULL != kt && NULL != ctx);

    hmac_ctx_free(ctx);
    if ((ret = wc_HmacSetKey(&ctx->hmac, OV_to_WC_hash_type[*kt], key, key_length)) != 0) {
        msg(M_FATAL, "wc_HmacSetKey failed. Errno: %d", ret);
    }

    memcpy(&ctx->key, key, key_length);
    ctx->key_len = key_length;

    /* make sure we used a big enough key */
    ASSERT(md_kt_size(kt) <= key_length);
}

void hmac_ctx_cleanup(hmac_ctx_t *ctx) {
    hmac_ctx_free(ctx);
}

int hmac_ctx_size(const hmac_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }
    md_kt_t md;
    for (md = 0; md < OV_WC_NULL_DIGEST; md++) {
        if (ctx->hmac.macType == OV_to_WC_hash_type[md]) {
            return md_kt_size(&md);
        }
    }
    return 0;
}

void hmac_ctx_reset(hmac_ctx_t *ctx) {
    if (ctx) {
        hmac_ctx_init(ctx, (uint8_t*)&ctx->key, ctx->key_len, (md_kt_t*)&ctx->hmac.macType);
    }
}

void hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len) {
    int ret;
    if (ctx && src) {
        if ((ret = wc_HmacUpdate(&ctx->hmac, src, src_len)) != 0) {
            msg(M_FATAL, "wc_HmacUpdate failed. Errno: %d", ret);
        }
    }
}

void hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst) {
    int ret;
    if (ctx && dst) {
        if ((ret = wc_HmacFinal(&ctx->hmac, dst)) != 0) {
            msg(M_FATAL, "wc_HmacFinal failed. Errno: %d", ret);
        }
    }
}

//extern bool cipher_kt_var_key_size(const cipher_kt_t *cipher) {
//    return false;
//}

const cipher_name_pair cipher_name_translation_table[] = {
    { "AES-128-GCM", "AES-128-GCM" },
    { "AES-192-GCM", "AES-192-GCM" },
    { "AES-256-GCM", "AES-256-GCM" },
    { "CHACHA20-POLY1305", "CHACHA20-POLY1305" },
};
const size_t cipher_name_translation_table_count =
    sizeof(cipher_name_translation_table) / sizeof(*cipher_name_translation_table);


#endif /* ENABLE_CRYPTO_WOLFSSL */
