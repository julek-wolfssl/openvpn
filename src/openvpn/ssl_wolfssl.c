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
#include "base64.h"

void tls_init_lib(void) {
	int ret;
	if ((ret = wolfSSL_library_init()) != SSL_SUCCESS) {
		msg(M_FATAL, "wolfSSL_library_init failed with Errno: %d", ret);
	}

    mydata_index = wolfSSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
    ASSERT(mydata_index >= 0);
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

    ctx->ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());

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
    ASSERT(NULL != ctx);

    /* process SSL options */
    long sslopt = SSL_OP_SINGLE_DH_USE |
				  SSL_OP_NO_TICKET |
				  SSL_OP_CIPHER_SERVER_PREFERENCE |
				  SSL_OP_NO_COMPRESSION |
				  SSL_OP_ALL;

    wolfSSL_CTX_set_options(ctx->ctx, sslopt);
    wolfSSL_CTX_set_options(ctx->ctx, ssl_flags);


    wolfSSL_CTX_set_session_cache_mode(ctx->ctx, WOLFSSL_SESS_CACHE_OFF);
    wolfSSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

    /* Require peer certificate verification */
    int verify_flags = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
#if P2MP_SERVER
    if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
    {
        verify_flags = 0;
    }
    else if (ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
    {
        verify_flags = WOLFSSL_VERIFY_PEER;
    }
#endif

    wolfSSL_CTX_set_verify(ctx->ctx, verify_flags, verify_callback);

    wolfSSL_CTX_set_info_callback(ctx->ctx, info_callback);

    return true;
}

void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers);

void tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers);

void tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile);



#endif /* ENABLE_CRYPTO_WOLFSSL */
