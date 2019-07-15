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
 * @file Control Channel wolfSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_WOLFSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "ssl_verify_wolfssl.h"
#include "base64.h"

/*
 *
 * Functions used in ssl.c which must be implemented by the backend SSL library
 *
 */

void tls_init_lib(void) {
	int ret;
	if ((ret = wolfSSL_Init()) != SSL_SUCCESS) {
		msg(M_FATAL, "wolfSSL_Init failed with Errno: %d", ret);
	}
}

void tls_free_lib(void) {
	int ret;
	if ((ret = wolfSSL_Cleanup()) != SSL_SUCCESS) {
		msg(M_FATAL, "wolfSSL_Cleanup failed with Errno: %d", ret);
	}
}

void tls_clear_error(void) {
	wolfSSL_ERR_clear_error();
}

int tls_version_max(void) {
#ifdef WOLFSSL_TLS13
    return TLS_VER_1_3;
#endif
    return TLS_VER_1_2;
}

void tls_ctx_server_new(struct tls_root_ctx *ctx) {
    ASSERT(NULL != ctx);

#ifdef WOLFSSL_TLS13
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#else
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif
    check_malloc_return(ctx->ctx);
}

void tls_ctx_client_new(struct tls_root_ctx *ctx) {
    ASSERT(NULL != ctx);

#ifdef WOLFSSL_TLS13
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif
    check_malloc_return(ctx->ctx);
}

void tls_ctx_free(struct tls_root_ctx *ctx) {
    ASSERT(NULL != ctx);
    if (NULL != ctx->ctx) {
    	wolfSSL_CTX_free(ctx->ctx);
    }
    ctx->ctx = NULL;
}

bool tls_ctx_initialised(struct tls_root_ctx *ctx) {
    ASSERT(NULL != ctx);
    return NULL != ctx->ctx;
}

bool tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags) {
    int ret = SSL_SUCCESS;
    int verify_flags = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    ASSERT(NULL != ctx);

    switch ((ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) & SSLF_TLS_VERSION_MIN_MASK) {
    case TLS_VER_1_3:
        ret = wolfSSL_CTX_SetMinVersion(ctx->ctx, WOLFSSL_TLSV1_3);
        break;
    case TLS_VER_1_2:
        ret = wolfSSL_CTX_SetMinVersion(ctx->ctx, WOLFSSL_TLSV1_2);
        break;
    case TLS_VER_1_1:
        ret = wolfSSL_CTX_SetMinVersion(ctx->ctx, WOLFSSL_TLSV1_1);
        break;
    case TLS_VER_1_0:
        ret = wolfSSL_CTX_SetMinVersion(ctx->ctx, WOLFSSL_TLSV1);
        break;
    case TLS_VER_UNSPEC:
        break;
    default:
        msg(M_FATAL, "Unidentified minimum TLS version");
    }

    if (ret != SSL_SUCCESS) {
        msg(M_FATAL, "wolfSSL_CTX_SetMinVersion failed");
    }

    if (((ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK) != TLS_VER_UNSPEC &&
        ((ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK) != TLS_VER_BAD) {
        msg(M_WARN, "wolfSSL backend does not support setting a maximum TLS version");
    }

    wolfSSL_CTX_set_session_cache_mode(ctx->ctx, WOLFSSL_SESS_CACHE_OFF);
    wolfSSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

    /* Require peer certificate verification */
#if P2MP_SERVER
    if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED) {
        verify_flags = 0;
    } else if (ssl_flags & SSLF_CLIENT_CERT_OPTIONAL) {
        verify_flags = WOLFSSL_VERIFY_PEER;
    }
#endif

    wolfSSL_CTX_set_verify(ctx->ctx, verify_flags, verify_callback);

    return true;
}

void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers) {
    if (ciphers == NULL) {
        return;
    }

    if (wolfSSL_CTX_set_cipher_list(ctx->ctx, ciphers) != SSL_SUCCESS) {
        msg(M_FATAL, "Failed to set ciphers: %s", ciphers);
    }
}

void tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers) {
    if (ciphers == NULL) {
        return;
    }

    if (wolfSSL_CTX_set_cipher_list(ctx->ctx, ciphers) != SSL_SUCCESS) {
        msg(M_FATAL, "Failed to set ciphers: %s", ciphers);
    }
}

void tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile) {
    /*
     * TODO Figure out how to service this in wolfSSL
     */
    msg(M_WARN, "NOT IMPLEMENTED %s", __func__);
}

void tls_ctx_check_cert_time(const struct tls_root_ctx *ctx) {
    /*
     * This is verified during loading of certificate.
     */
}

void tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
                            const char *dh_file_inline) {
    int dh_len, ret;

    ASSERT(ctx != NULL);

    if (!strcmp(dh_file, INLINE_FILE_TAG) && dh_file_inline) {
        /* Parameters in memory */
        if ((dh_len = strlen(dh_file_inline)) == 0) {
            msg(M_FATAL, "Empty DH parameters passed.");
            return;
        }

        if ((ret = wolfSSL_CTX_SetTmpDH_buffer(ctx->ctx,
                                               (uint8_t*) dh_file_inline,
                                               dh_len,
                                               WOLFSSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            msg(M_FATAL, "wolfSSL_CTX_SetTmpDH_buffer failed with Errno: %d", ret);
            return;
        }
    } else {
        /* Parameters in file */
        if ((ret = wolfSSL_CTX_SetTmpDH_file(ctx->ctx,
                                             dh_file,
                                             WOLFSSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            msg(M_FATAL, "wolfSSL_CTX_SetTmpDH_file failed with Errno: %d", ret);
            return;
        }
    }
}

void tls_ctx_load_ecdh_params(struct tls_root_ctx *ctx, const char *curve_name) {
    int nid;
    WOLFSSL_EC_KEY* ecdh;

    if (curve_name == NULL) {
        return;
    }

    msg(D_TLS_DEBUG, "Using user specified ECDH curve (%s)", curve_name);

    if ((nid = wc_ecc_get_curve_id_from_name(curve_name)) < 0) {
        msg(M_FATAL, "Unknown curve name: %s", curve_name);
    }

    if (!(ecdh = wolfSSL_EC_KEY_new_by_curve_name(nid))) {
        msg(M_FATAL, "wolfSSL_EC_KEY_new_by_curve_name failed");
    }

    if (wolfSSL_SSL_CTX_set_tmp_ecdh(ctx->ctx, ecdh) != WOLFSSL_SUCCESS) {
        wolfSSL_EC_KEY_free(ecdh);
        msg(M_FATAL, "wolfSSL_SSL_CTX_set_tmp_ecdh failed");
    }

    wolfSSL_EC_KEY_free(ecdh);
}

int tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
                        const char *pkcs12_file_inline, bool load_ca_file) {
    msg(M_FATAL, "NEEDS CHECKING OF INPUT FORMAT %s", __func__);

#if 0
    int ret;
    ASSERT(ctx != NULL);

    if (!strcmp(pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline) {
        /* PKCS12 in memory */
    } else {
        /* PKCS12 in file */
    }

    if ((ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap,
                        NULL, NULL)) != 0) {

    }
#endif
    return 1;
}

#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
    ASSERT(NULL != ctx);

    /* Load Certificate and Private Key */
    if (!SSL_CTX_use_CryptoAPI_certificate(ctx->ctx, cryptoapi_cert))
    {
        crypto_msg(M_FATAL, "Cannot load certificate \"%s\" from Microsoft Certificate Store", cryptoapi_cert);
    }
}
#endif /* ENABLE_CRYPTOAPI */

void tls_ctx_load_cert_file(struct tls_root_ctx *ctx, const char *cert_file,
                            const char *cert_file_inline) {
    int ret;
    int cert_len;
    ASSERT(ctx != NULL);

    if (!strcmp(cert_file, INLINE_FILE_TAG) && cert_file_inline) {
        /* Certificate in memory */
        if ((cert_len = strlen(cert_file_inline)) == 0) {
            msg(M_FATAL, "Empty certificate passed.");
            return;
        }

        if ((ret = wolfSSL_CTX_load_verify_buffer(ctx->ctx,
                                                  (uint8_t*) cert_file_inline,
                                                  cert_len,
                                                  SSL_FILETYPE_PEM)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_load_verify_buffer failed with Errno: %d", ret);
            return;
        }
        if ((ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx->ctx,
                                                            (uint8_t*) cert_file_inline,
                                                            cert_len)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_buffer failed with Errno: %d", ret);
            return;
        }
    } else {
        /* Certificate in file */
        if ((ret = wolfSSL_CTX_load_verify_locations(ctx->ctx, cert_file, NULL)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_load_verify_locations failed with Errno: %d", ret);
            return;
        }
        if ((ret = wolfSSL_CTX_use_certificate_chain_file(ctx->ctx, cert_file)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_chain_file failed with Errno: %d", ret);
            return;
        }
    }
}

int tls_ctx_load_priv_file(struct tls_root_ctx *ctx, const char *priv_key_file,
                           const char *priv_key_file_inline) {

    int ret;
    int key_len;
    ASSERT(ctx != NULL);

    if (!strcmp(priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline) {
        /* Key in memory */
        if ((key_len = strlen(priv_key_file_inline)) == 0) {
            msg(M_FATAL, "Empty certificate passed.");
            return 1;
        }
        if ((ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx->ctx,
                                                     (uint8_t*) priv_key_file_inline,
                                                     key_len,
                                                     WOLFSSL_FILETYPE_PEM)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_PrivateKey_buffer failed with Errno: %d", ret);
            return 1;
        }
    } else {
        /* Key in file */
        if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx->ctx,
                                                   priv_key_file,
                                                   WOLFSSL_FILETYPE_PEM)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_PrivateKey_file failed with Errno: %d", ret);
            return 1;
        }
    }
    return 0;
}

#ifdef ENABLE_MANAGEMENT
int tls_ctx_use_management_external_key(struct tls_root_ctx *ctx) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
    return 1;
}
#endif /* ENABLE_MANAGEMENT */

void tls_ctx_load_ca(struct tls_root_ctx *ctx, const char *ca_file,
                     const char *ca_file_inline, const char *ca_path, bool tls_server) {
    int ca_len, ret;

    ASSERT(ctx != NULL);

    if (!strcmp(ca_file, INLINE_FILE_TAG) && ca_file_inline) {
        /* Certificate in memory */
        if ((ca_len = strlen(ca_file_inline)) == 0) {
            msg(M_FATAL, "Empty certificate passed.");
            return;
        }

        if ((ret = wolfSSL_CTX_load_verify_buffer(ctx->ctx,
                                                  (uint8_t*) ca_file_inline,
                                                  ca_len,
                                                  SSL_FILETYPE_PEM)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_load_verify_buffer failed with Errno: %d", ret);
            return;
        }
        if ((ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx->ctx,
                                                            (uint8_t*) ca_file_inline,
                                                            ca_len)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_buffer failed with Errno: %d", ret);
            return;
        }
    } else {
        /* Certificate in file */
        if ((ret = wolfSSL_CTX_load_verify_locations(ctx->ctx, ca_file, NULL)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_load_verify_locations failed with Errno: %d", ret);
            return;
        }
        if ((ret = wolfSSL_CTX_use_certificate_chain_file(ctx->ctx, ca_file)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_chain_file failed with Errno: %d", ret);
            return;
        }
    }

    if (ca_path) {
        if ((ret = wolfSSL_CTX_load_verify_locations(ctx->ctx, NULL, ca_path)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_load_verify_locations failed with Errno: %d", ret);
            return;
        }
    }
}

void tls_ctx_load_extra_certs(struct tls_root_ctx *ctx, const char *extra_certs_file,
                              const char *extra_certs_file_inline) {
    int extra_cert_len, ret;

    ASSERT(ctx != NULL);

    if (!strcmp(extra_certs_file, INLINE_FILE_TAG) && extra_certs_file_inline) {
        /* Certificate in memory */
        if ((extra_cert_len = strlen(extra_certs_file_inline)) == 0) {
            msg(M_FATAL, "Empty certificate passed.");
            return;
        }

        if ((ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx->ctx,
                                                            (uint8_t*) extra_certs_file_inline,
                                                            extra_cert_len)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_buffer failed with Errno: %d", ret);
            return;
        }
    } else {
        /* Certificate in file */
        if ((ret = wolfSSL_CTX_use_certificate_chain_file(ctx->ctx, extra_certs_file)) != SSL_SUCCESS ) {
            msg(M_FATAL, "wolfSSL_CTX_use_certificate_chain_file failed with Errno: %d", ret);
            return;
        }
    }
}

/* **************************************
 *
 * Key-state specific functions
 *
 * **************************************/

/*
 * SSL is handled by library (wolfSSL in this case) but data is dumped
 * to buffers instead of being sent directly through TCP sockets. OpenVPN
 * itself handles sending and receiving data.
 */

static int ssl_buff_read(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    struct ring_buffer_t* ssl_buf = (struct ring_buffer_t*)ctx;
    uint32_t len = sz < ssl_buf->len ? sz : ssl_buf->len;

    if (len == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    if (ssl_buf->offset + len <= RING_BUF_LEN) {
        /* The data to be read does not wrap around the edge of the buffer */
        memcpy(buf, ssl_buf->buf + ssl_buf->offset, len);
    } else {
        /* The data wraps around the end to the beginning of the buffer */
        msg(M_INFO, "READ ring buffer is wrapping around.");
        uint32_t partial_len = RING_BUF_LEN - ssl_buf->offset;
        memcpy(buf, ssl_buf->buf + ssl_buf->offset, partial_len);
        memcpy(buf + partial_len, ssl_buf->buf, len - partial_len);
    }
    ssl_buf->offset += len;
    ssl_buf->offset %= RING_BUF_LEN;
    ssl_buf->len -= len;

    msg(M_INFO, "Buffer read from.\n"
                "Bytes read: %d\n"
                "Buffer space: %d/%d\n"
                "sz was: %d", len, ssl_buf->len, RING_BUF_LEN, sz);

    return len;
}
static int ssl_buff_write(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    struct ring_buffer_t* ssl_buf = (struct ring_buffer_t*)ctx;
    uint32_t len = sz;

    if (len == 0) {
        return 0;
    }

    if (len > RING_BUF_LEN) {
        msg(M_FATAL, "Ring buffer is too small to hold all data.");
    }

    if (ssl_buf->len + len > RING_BUF_LEN) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }

    if (ssl_buf->offset + ssl_buf->len + len < RING_BUF_LEN) {
        /* The data to be sent will not wrap around the edge of the buffer */
        memcpy(ssl_buf->buf + ssl_buf->offset + ssl_buf->len, buf, len);
    } else {
        /* The data will wrap around the end to the beginning of the buffer */
        msg(M_INFO, "WRITE ring buffer is wrapping around.");
        uint32_t partial_len = RING_BUF_LEN - (ssl_buf->offset + ssl_buf->len);
        memcpy(ssl_buf->buf + ssl_buf->offset + ssl_buf->len, buf, partial_len);
        memcpy(ssl_buf->buf, buf + partial_len, len - partial_len);
    }
    ssl_buf->len += len;

    msg(M_INFO, "Buffer written to.\n"
                "Bytes written: %d\n"
                "Buffer space: %d/%d", len, ssl_buf->len, RING_BUF_LEN);

    return len;
}

void key_state_ssl_init(struct key_state_ssl *ks_ssl,
                        const struct tls_root_ctx *ssl_ctx, bool is_server,
                        struct tls_session *session) {
    ASSERT(ssl_ctx != NULL);

    if((ks_ssl->ssl = wolfSSL_new(ssl_ctx->ctx)) == NULL) {
        msg(M_FATAL, "wolfSSL_new failed");
    }

    if ((ks_ssl->send_buf =
            (struct ring_buffer_t*) calloc(sizeof(struct ring_buffer_t), 1)) == NULL) {
        wolfSSL_free(ks_ssl->ssl);
        msg(M_FATAL, "Failed to allocate memory for send buffer.");
    }

    if ((ks_ssl->recv_buf =
            (struct ring_buffer_t*) calloc(sizeof(struct ring_buffer_t), 1)) == NULL) {
        free(ks_ssl->send_buf);
        wolfSSL_free(ks_ssl->ssl);
        msg(M_FATAL, "Failed to allocate memory for receive buffer.");
    }

    /* Register functions handling queuing of data in buffers */
    wolfSSL_SSLSetIORecv(ks_ssl->ssl, &ssl_buff_read);
    wolfSSL_SSLSetIOSend(ks_ssl->ssl, &ssl_buff_write);

    /* Register pointers to appropriate buffers */
    wolfSSL_SetIOWriteCtx(ks_ssl->ssl, ks_ssl->send_buf);
    wolfSSL_SetIOReadCtx(ks_ssl->ssl, ks_ssl->recv_buf);

    ks_ssl->session = session;
}

void key_state_ssl_free(struct key_state_ssl *ks_ssl) {
    wolfSSL_free(ks_ssl->ssl);
    if (ks_ssl->recv_buf) {
        free(ks_ssl->recv_buf);
    }
    if (ks_ssl->send_buf) {
        free(ks_ssl->send_buf);
    }
    ks_ssl->ssl = NULL;
    ks_ssl->recv_buf = NULL;
    ks_ssl->send_buf = NULL;
    ks_ssl->session = NULL;
}

void backend_tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx,
                                const char *crl_file, const char *crl_inline) {
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

void key_state_export_keying_material(struct key_state_ssl *ks_ssl,
                                 struct tls_session *session) {
    msg(M_WARN, "NOT IMPLEMENTED %s", __func__);
}


int key_state_write_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf) {
    int ret = 1;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(ks_ssl != NULL);

    switch (key_state_write_plaintext_const(ks_ssl, BPTR(buf), BLEN(buf))) {
    case 1:
        ret = 1;
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
        break;
    case 0:
        ret = 0;
        break;
    case -1:
        ret = -1;
        break;
    default:
        msg(M_WARN, "Invalid error code from key_state_write_plaintext_const");
        break;
    }

    perf_pop();
    return ret;
}


int key_state_write_plaintext_const(struct key_state_ssl *ks_ssl,
                                    const uint8_t *data, int len) {
    int err = 0;
    int ret = 1;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(ks_ssl != NULL);

    if (len > 0) {
//        msg(M_INFO, "Enter key_state_write_plaintext_const");
        if ((err = wolfSSL_write(ks_ssl->ssl, data, len)) != len) {
            err = wolfSSL_get_error(ks_ssl->ssl, err);
            switch (err) {
            case WOLFSSL_ERROR_WANT_WRITE:
            case WOLFSSL_ERROR_WANT_READ:
                ret = 0;
                goto cleanup;
            default:
                msg(M_WARN, "wolfSSL_write failed with Error: %s", wc_GetErrorString(err));
                ret =  -1;
                goto cleanup;
            }
        }
    }

cleanup:
    perf_pop();
    return ret;
}

int key_state_read_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf,
                              int maxlen) {
    int ret = 1;
    perf_push(PERF_BIO_READ_CIPHERTEXT);

    if (BLEN(buf) != 0) {
        ret = 0;
        goto cleanup;
    }

    ASSERT(ks_ssl != NULL);
//    msg(M_INFO, "Enter key_state_read_ciphertext");

    buf->len = ssl_buff_read(ks_ssl->ssl, (char*)BPTR(buf), maxlen, ks_ssl->send_buf);

    ret = buf->len > 0 ? 1 : 0;

cleanup:
    perf_pop();
    return ret;
}


int key_state_write_ciphertext(struct key_state_ssl *ks_ssl,
                               struct buffer *buf) {
    int err, ret = 1;
    perf_push(PERF_BIO_WRITE_CIPHERTEXT);

    ASSERT(ks_ssl != NULL);

    if (BLEN(buf) > 0) {
//        msg(M_INFO, "Enter key_state_write_ciphertext");
        if ((err = (ssl_buff_write(ks_ssl->ssl, (char*) BPTR(buf),
                                   BLEN(buf), ks_ssl->recv_buf))) != BLEN(buf)) {
            ret = 0;
            goto cleanup;
        }
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
    }

cleanup:
    perf_pop();
    return ret;
}

int key_state_read_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf,
                             int maxlen) {
    int err, ret = 1;
    perf_push(PERF_BIO_READ_PLAINTEXT);

    ASSERT(ks_ssl != NULL);

    if (BLEN(buf) != 0) {
        ret = 0;
        goto cleanup;
    }
//    msg(M_INFO, "Enter key_state_read_plaintext");

    if ((err = wolfSSL_read(ks_ssl->ssl, BPTR(buf), maxlen)) < 0) {
        err = wolfSSL_get_error(ks_ssl->ssl, err);
        switch (err) {
        case WOLFSSL_ERROR_WANT_WRITE:
        case WOLFSSL_ERROR_WANT_READ:
            ret = 0;
            goto cleanup;
        default:
            msg(M_WARN, "wolfSSL_read failed with Error: %s", wc_GetErrorString(err));
            ret =  -1;
            goto cleanup;
        }
    }
    buf->len = err;

cleanup:
    perf_pop();
    return ret;
}

void print_details(struct key_state_ssl *ks_ssl, const char *prefix) {
    msg(M_WARN, "NOT IMPLEMENTED %s", __func__);
}

void show_available_tls_ciphers_list(const char *cipher_list,
                                     const char *tls_cert_profile,
                                     bool tls13) {
    msg(M_WARN, "NOT IMPLEMENTED %s", __func__);
}

void show_available_curves(void) {
    msg(M_WARN, "NOT IMPLEMENTED %s", __func__);
}

void get_highest_preference_tls_cipher(char *buf, int size) {
    WOLFSSL *ssl;
    WOLFSSL_CTX* ctx;
    const char* cipher_name;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL){
        wolfSSL_CTX_free(ctx);
        msg(M_FATAL, "wolfSSL_CTX_new failed");
    }

    if((ssl = wolfSSL_new(ctx)) == NULL) {
        msg(M_FATAL, "wolfSSL_new failed");
    }

    cipher_name = wolfSSL_get_cipher_name(ssl);
    if (cipher_name) {
        strncpynt(buf, cipher_name, size);
    } else {
        msg(M_WARN, "wolfSSL_get_cipher_name failed");
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

const char * get_ssl_library_version(void) {
    return wolfSSL_lib_version();
}


#endif /* ENABLE_CRYPTO_WOLFSSL */
