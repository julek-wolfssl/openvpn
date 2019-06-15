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

# define TLS1_1_VERSION                  0x0302
# define TLS1_2_VERSION                  0x0303
# define TLS1_3_VERSION                  0x0304

/**
 * Verify that the remote OpenVPN peer's certificate allows setting up a
 * VPN tunnel.
 * @ingroup control_tls
 *
 * This callback function is called every time a new TLS session is being
 * setup to determine whether the remote OpenVPN peer's certificate is
 * allowed to connect. It is called for once for every certificate in the chain.
 * The callback functionality is configured in the \c init_ssl() function, which
 * calls the OpenSSL library's \c SSL_CTX_set_verify() function with \c
 * verify_callback() as its callback argument.
 *
 * It checks preverify_ok, and registers the certificate hash. If these steps
 * succeed, it calls the \c verify_cert() function, which performs
 * OpenVPN-specific verification.
 *
 * @param preverify_ok - Whether the remote OpenVPN peer's certificate
 *                       past verification.  A value of 1 means it
 *                       verified successfully, 0 means it failed.
 * @param ctx          - The complete context used by the OpenSSL library
 *                       to verify the certificate chain.
 *
 * @return The return value indicates whether the supplied certificate is
 *     allowed to set up a VPN tunnel.  The following values can be
 *     returned:
 *      - \c 0: failure, this certificate is not allowed to connect.
 *      - \c 1: success, this certificate is allowed to connect.
 */
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 */
struct tls_root_ctx {
	WOLFSSL_CTX *ctx;
};

#endif /* SSL_WOLFSSL_H_ */
