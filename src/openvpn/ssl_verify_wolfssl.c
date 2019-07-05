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


#if defined(ENABLE_CRYPTO_WOLFSSL)

#include "ssl_verify_wolfssl.h"

int verify_callback(int preverify_ok, WOLFSSL_X509_STORE_CTX *store) {
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    msg(M_INFO, "In verification callback, error = %d, %s\n", store->error,
                                 wolfSSL_ERR_error_string(store->error, buffer));
    if (store->error) {
        return 0;
    } else {
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
    if (wolfSSL_X509_digest(cert, wolfSSL_EVP_sha1(), BPTR(&hash), &hashSz) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_digest for sha1 failed.");
    }
    return hash;
}

struct buffer x509_get_sha256_fingerprint(X509 *cert, struct gc_arena *gc) {
    unsigned int hashSz = wc_HashGetDigestSize(WC_HASH_TYPE_SHA256);
    struct buffer hash = alloc_buf_gc(hashSz, gc);
    if (wolfSSL_X509_digest(cert, wolfSSL_EVP_sha256(), BPTR(&hash), &hashSz) != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_X509_digest for sha256 failed.");
    }
    return hash;
}

#endif /* ENABLE_CRYPTO_WOLFSSL */
