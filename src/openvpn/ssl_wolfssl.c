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

static long get_version_options(unsigned int ssl_flags) {
	long mask = 0;
	/* Set the minimum TLS version */
	switch ((ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) & SSLF_TLS_VERSION_MIN_MASK) {
	case TLS_VER_1_3:
		mask |= SSL_OP_NO_TLSv1_2;
		/* no break */
	case TLS_VER_1_2:
		mask |= SSL_OP_NO_TLSv1_1;
		/* no break */
	case TLS_VER_1_1:
		mask |= SSL_OP_NO_TLSv1;
		/* no break */
	case TLS_VER_1_0:
		mask |= SSL_OP_NO_SSLv3;
		/* no break */
	default:
	}
	/* Set the maximum TLS version */
	switch ((ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK) {
	case TLS_VER_1_0:
		mask |= SSL_OP_NO_TLSv1_1;
		/* no break */
	case TLS_VER_1_1:
		mask |= SSL_OP_NO_TLSv1_2;
		/* no break */
	case TLS_VER_1_2:
		mask |= SSL_OP_NO_TLSv1_3;
		/* no break */
	case TLS_VER_1_3:
	default:
	}
	return mask;
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


    wolfSSL_CTX_set_options(ctx->ctx, get_version_options(ssl_flags));


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

void convert_tls_list_to_openssl(char *openssl_ciphers, size_t len,const char *ciphers) {
    /* Parse supplied cipher list and pass on to OpenSSL */
    size_t begin_of_cipher, end_of_cipher;

    const char *current_cipher;
    size_t current_cipher_len;

    const tls_cipher_name_pair *cipher_pair;

    size_t openssl_ciphers_len = 0;
    openssl_ciphers[0] = '\0';

    /* Translate IANA cipher suite names to OpenSSL names */
    begin_of_cipher = end_of_cipher = 0;
    for (; begin_of_cipher < strlen(ciphers); begin_of_cipher = end_of_cipher) {
        end_of_cipher += strcspn(&ciphers[begin_of_cipher], ":");
        cipher_pair = tls_get_cipher_name_pair(&ciphers[begin_of_cipher], end_of_cipher - begin_of_cipher);

        if (NULL == cipher_pair) {
            /* No translation found, use original */
            current_cipher = &ciphers[begin_of_cipher];
            current_cipher_len = end_of_cipher - begin_of_cipher;

            /* Issue warning on missing translation */
            /* %.*s format specifier expects length of type int, so guarantee */
            /* that length is small enough and cast to int. */
            msg(D_LOW, "No valid translation found for TLS cipher '%.*s'",
                constrain_int(current_cipher_len, 0, 256), current_cipher);
        } else {
            /* Use OpenSSL name */
            current_cipher = cipher_pair->openssl_name;
            current_cipher_len = strlen(current_cipher);

            if (end_of_cipher - begin_of_cipher == current_cipher_len
                && 0 != memcmp(&ciphers[begin_of_cipher], cipher_pair->iana_name,
                               end_of_cipher - begin_of_cipher)) {
                /* Non-IANA name used, show warning */
                msg(M_WARN, "Deprecated TLS cipher name '%s', please use IANA name '%s'", cipher_pair->openssl_name, cipher_pair->iana_name);
            }
        }

        /* Make sure new cipher name fits in cipher string */
        if ((SIZE_MAX - openssl_ciphers_len) < current_cipher_len
            || (len - 1) < (openssl_ciphers_len + current_cipher_len)) {
            msg(M_FATAL,
                "Failed to set restricted TLS cipher list, too long (>%d).",
                (int)(len - 1));
        }

        /* Concatenate cipher name to OpenSSL cipher string */
        memcpy(&openssl_ciphers[openssl_ciphers_len], current_cipher, current_cipher_len);
        openssl_ciphers_len += current_cipher_len;
        openssl_ciphers[openssl_ciphers_len] = ':';
        openssl_ciphers_len++;

        end_of_cipher++;
    }

    if (openssl_ciphers_len > 0) {
        openssl_ciphers[openssl_ciphers_len-1] = '\0';
    }
}

void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers) {
    if (ciphers == NULL)
    {
        /* Use sane default TLS cipher list */
        if (wolfSSL_CTX_set_cipher_list(ctx->ctx,
										/* Use openssl's default list as a basis */
										 "DEFAULT"
										/* Disable export ciphers and openssl's 'low' and 'medium' ciphers */
										":!EXP:!LOW:!MEDIUM"
										/* Disable static (EC)DH keys (no forward secrecy) */
										":!kDH:!kECDH"
										/* Disable DSA private keys */
										":!DSS"
										/* Disable unsupported TLS modes */
										":!PSK:!SRP:!kRSA") != WOLFSSL_SUCCESS)
        {
            msg(M_FATAL, "Failed to set default TLS cipher list.");
        }
        return;
    }

    // TODO CHECK IF WOLFSSL ACCEPTS THE OUTPUT OF convert_tls_list_to_openssl
    char openssl_ciphers[4096];
    convert_tls_list_to_openssl(openssl_ciphers, sizeof(openssl_ciphers), ciphers);

    ASSERT(NULL != ctx);

    /* Set OpenSSL cipher list */
    if (!wolfSSL_CTX_set_cipher_list(ctx->ctx, openssl_ciphers))
    {
        msg(M_FATAL, "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
    }
}

static void convert_tls13_list_to_openssl(char *openssl_ciphers, size_t len,
                              const char *ciphers){
    if (strlen(ciphers) >= (len - 1)) {
        msg(M_FATAL,
            "Failed to set restricted TLS 1.3 cipher list, too long (>%d).",
            (int) (len - 1));
    }

    strncpy(openssl_ciphers, ciphers, len);

    for (size_t i = 0; i < strlen(openssl_ciphers); i++) {
        if (openssl_ciphers[i] == '-') {
            openssl_ciphers[i] = '_';
        }
    }
}


void tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers) {
    if (ciphers == NULL) {
        /* default cipher list is sane */
        return;
    }

	// TODO CHECK IF tls_ctx_restrict_ciphers_tls13 MAKES SENSE IN WOLFSSL
    msg(M_FATAL, "tls_ctx_restrict_ciphers_tls13 may not have proper function in wolfSSL");
}

void tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile) {
    msg(M_WARN, "wolfSSL does not support --tls-cert-profile");
}



#endif /* ENABLE_CRYPTO_WOLFSSL */
