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
 * @file Control Channel Verification Module wolfSSL backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_WOLFSSL)

#include "ssl_backend.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"

int verify_callback(int preverify_ok, WOLFSSL_X509_STORE_CTX *store) {
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    struct key_state_ssl* ks_ssl = store->userCtx;

    if (store->error) {
        msg(M_INFO, "In verification callback, error = %d, %s\n", store->error,
                                     wolfSSL_ERR_error_string(store->error, buffer));
        return 0;
    } else {
        if (verify_cert(ks_ssl->session,
                        store->current_cert,
                        store->error_depth) != SUCCESS ){
            return 0;
        }
        return 1;
    }
}

char *x509_get_subject(openvpn_x509_cert_t *cert, struct gc_arena *gc) {
    char *subject = NULL;
    int subject_len;
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(cert);
    if (!name) {
        return NULL;
    }
    subject_len = wolfSSL_X509_NAME_get_sz(name);

    subject = gc_malloc(subject_len + 1, FALSE, gc);
    check_malloc_return(subject);

    subject[subject_len] = '\0';

    return wolfSSL_X509_NAME_oneline(name, subject, subject_len);
}

struct buffer x509_get_sha1_fingerprint(openvpn_x509_cert_t *cert,
                                        struct gc_arena *gc) {
    unsigned int hashSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA);
    struct buffer hash = alloc_buf_gc(hashSz, gc);
    check_malloc_return(BPTR(&hash));
    if (wolfSSL_X509_digest(cert, wolfSSL_EVP_sha1(), BPTR(&hash), &hashSz) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_digest for sha1 failed.");
    }
    return hash;
}

struct buffer x509_get_sha256_fingerprint(X509 *cert, struct gc_arena *gc) {
    unsigned int hashSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
    struct buffer hash = alloc_buf_gc(hashSz, gc);
    check_malloc_return(BPTR(&hash));
    if (wolfSSL_X509_digest(cert, wolfSSL_EVP_sha256(), BPTR(&hash), &hashSz) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_digest for sha256 failed.");
    }
    return hash;
}

result_t backend_x509_get_username(char *common_name, int cn_len,
                                   char *x509_username_field, openvpn_x509_cert_t *peer_cert) {
#ifdef ENABLE_X509ALTUSERNAME
    if (strncmp("ext:",x509_username_field,4) == 0) {
        ASSERT(0);
    } else
#endif
    {
        char *subject;
        char *c;
        char *start_pos;
        int field_len = strlen(x509_username_field);
        int value_len;
        WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(peer_cert);
        if (!name) {
            return FAILURE;
        }
        subject = wolfSSL_X509_NAME_oneline(name, NULL, 0);

        for (c = subject; *c != '\0'; c++) {
            if (*c == '/' && strncmp(++c, x509_username_field, field_len) == 0) {
                c += field_len; // increment to value of field
                start_pos = c + 1;
                while (*(++c) != '/' && *c != '\0'); // inc to next slash
                value_len = MIN(c-start_pos, cn_len);
                memcpy(common_name, start_pos, value_len);
                break;
            }
        }

        free(subject);
    }
    return SUCCESS;
}

#ifdef ENABLE_X509ALTUSERNAME
bool x509_username_field_ext_supported(const char *extname) {
    if (!strcmp(extname, "subjectAltName") || !strcmp(extname, "issuerAltName")) {
        return true;
    } else {
        return false;
    }
}
#endif


char *backend_x509_get_serial(openvpn_x509_cert_t *cert, struct gc_arena *gc) {
    uint8_t buf[EXTERNAL_SERIAL_SIZE];
    int buf_len = EXTERNAL_SERIAL_SIZE, ret, i, j, radix_size;
    mp_int big_num;
    struct buffer dec_string;

    if ((ret = wolfSSL_X509_get_serial_number(cert, buf, &buf_len)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_get_serial_number failed with Errno: %d", ret);
    }

    if (mp_init(&big_num) != MP_OKAY) {
        msg(M_FATAL, "mp_init failed");
    }

    /* reverse byte order (make big endian) */
    for (i=0, j=buf_len-1; i < j; i++, j--) {
      int temp = buf[i];
      buf[i] = buf[j];
      buf[j] = temp;
    }

    if ((ret = mp_read_unsigned_bin(&big_num, buf, buf_len)) != MP_OKAY) {
        msg(M_FATAL, "mp_read_unsigned_bin failed with Errno: %d", ret);
    }

    if ((ret = mp_radix_size(&big_num, MP_RADIX_DEC, &radix_size)) != MP_OKAY) {
        msg(M_FATAL, "mp_radix_size failed with Errno: %d", ret);
    }

    dec_string = alloc_buf_gc(radix_size, gc);
    check_malloc_return(BPTR(&dec_string));

    if ((ret = mp_todecimal(&big_num, (char*) BPTR(&dec_string))) != MP_OKAY) {
        msg(M_FATAL, "mp_todecimal failed with Errno: %d", ret);
    }

    return (char*) BPTR(&dec_string);
}

char *backend_x509_get_serial_hex(openvpn_x509_cert_t *cert,
                                  struct gc_arena *gc) {
    uint8_t buf[EXTERNAL_SERIAL_SIZE];
    int buf_len = EXTERNAL_SERIAL_SIZE, ret, i, j;
    struct buffer hex_string;
    char* s;

    if ((ret = wolfSSL_X509_get_serial_number(cert, buf, &buf_len)) != WOLFSSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_get_serial_number failed with Errno: %d", ret);
    }

    hex_string = alloc_buf_gc((buf_len * 2) + 1, gc);
    check_malloc_return(BPTR(&hex_string));
    s = (char*) BPTR(&hex_string);

    for (i = buf_len-1, j=0; i>=0; i--, j++) {
        if (sprintf(&s[j*2], "%02X", buf[i]) < 0) {
            msg(M_FATAL, "sprintf in %s failed", __func__);
        }
    }

    /* sprintf should have added the null terminator */
    ASSERT(s[buf_len * 2] == '\0');
    return s;
}

void x509_setenv(struct env_set *es, int cert_depth, openvpn_x509_cert_t *cert) {
    char *subject;
    char *c;
    char *name_start_pos;
    int name_len;
    char *value_start_pos;
    int value_len;
    char* name_buf = NULL;
    char* value_buf = NULL;
    char *full_name_buf = NULL;
    int full_name_len;
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(cert);
    if (!name) {
        return;
    }
    subject = wolfSSL_X509_NAME_oneline(name, NULL, 0);

    for (c = subject; *c != '\0';) {
        ASSERT(*c == '/'); // c should point to slash on each loop

        name_start_pos = c + 1;
        while (*(++c) != '=' && *c != '\0'); // inc to equals sign
        name_len = c - name_start_pos;

        value_start_pos = c + 1;
        while (*(++c) != '/' && *c != '\0'); // inc to next slash
        value_len = c - value_start_pos;

        /*
         * length of buffer is: length of name + null teminator +
         *                      6 chars from naming convention +
         *                      5 chars for depth number (should be enough)
         */
        full_name_len = name_len + 1 + 6 + 5;

        name_buf = realloc(name_buf, name_len + 1);
        check_malloc_return(name_buf);
        full_name_buf = realloc(full_name_buf, full_name_len);
        check_malloc_return(full_name_buf);
        value_buf = realloc(value_buf, value_len + 1);
        check_malloc_return(value_buf);

        memcpy(name_buf, name_start_pos, name_len);
        memcpy(value_buf, value_start_pos, value_len);
        name_buf[name_len] = '\0';
        value_buf[value_len] = '\0';

        snprintf(full_name_buf, full_name_len, "X509_%d_%s", cert_depth, name_buf);

        setenv_str_incr(es, full_name_buf, value_buf);
    }

    if (name_buf) {
        free(name_buf);
    }
    if (full_name_buf) {
        free(full_name_buf);
    }
    if (value_buf) {
        free(value_buf);
    }
    free(subject);
}

void x509_track_add(const struct x509_track **ll_head, const char *name,
                    int msglevel, struct gc_arena *gc) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

void x509_setenv_track(const struct x509_track *xt, struct env_set *es,
                       const int depth, openvpn_x509_cert_t *x509) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

result_t x509_verify_ns_cert_type(openvpn_x509_cert_t *cert, const int usage) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

result_t x509_verify_cert_ku(openvpn_x509_cert_t *x509, const unsigned *const expected_ku,
                             int expected_len) {
    unsigned int ku = wolfSSL_X509_get_keyUsage(x509);

    if (ku == 0)
    {
        msg(D_TLS_ERRORS, "Certificate does not have key usage extension");
        return FAILURE;
    }

    if (expected_ku[0] == OPENVPN_KU_REQUIRED)
    {
        /* Extension required, value checked by TLS library */
        return SUCCESS;
    }

    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

result_t x509_verify_cert_eku(openvpn_x509_cert_t *x509, const char *const expected_oid) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

result_t x509_write_pem(FILE *peercert_file, openvpn_x509_cert_t *peercert) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

bool tls_verify_crl_missing(const struct tls_options *opt) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

#endif /* ENABLE_CRYPTO_WOLFSSL */
