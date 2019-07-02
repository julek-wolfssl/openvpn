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

#ifndef SSL_WOLFSSL_H_
#define SSL_WOLFSSL_H_

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/ssl.h>

#define TLS1_1_VERSION                  0x0302
#define TLS1_2_VERSION                  0x0303
#define TLS1_3_VERSION                  0x0304

#define MAX_DH_SIZE ((8192/8)+1)

/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 */
struct tls_root_ctx {
	WOLFSSL_CTX *ctx;
    time_t crl_last_mtime;
    off_t crl_last_size;
};

struct key_state_ssl {
    WOLFSSL *ssl;
    struct tls_session *session;
};

#endif /* SSL_WOLFSSL_H_ */
