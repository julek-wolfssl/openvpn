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

void tls_ctx_server_new(struct tls_root_ctx *ctx) {
    ASSERT(NULL != ctx);

#ifdef WOLFSSL_TLS13
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
#else
    ctx->ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif

    if (ctx->ctx == NULL)
    {
        msg(M_FATAL, "wolfSSL_CTX_new wolfSSLv23_server_method failed");
    }
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
    int ret;
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
    msg(M_FATAL, "NOT IMPLEMENTED %s", __func__);
}

void tls_ctx_check_cert_time(const struct tls_root_ctx *ctx) {
    /*
     * This is verified during loading of certificate.
     */
}

void tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
                            const char *dh_file_inline) {
    msg(M_FATAL, "NEEDS TESTING %s", __func__);
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
    if (curve_name != NULL) {
        /* Use user supplied curve if given */
        msg(D_TLS_DEBUG, "Using user specified ECDH curve (%s)", curve_name);
        nid = OBJ_sn2nid(curve_name);
    }
}



#endif /* ENABLE_CRYPTO_WOLFSSL */
