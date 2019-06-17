/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "crypto.h"

#include "mock_msg.h"

static const char testtext[] = "Dummy text to test PEM encoding";

static void
show_available_ciphers_digests_test(void **state) {
	show_available_ciphers();
	show_available_digests();
	show_available_engines();
}

static void
crypto_pem_encode_decode_loopback(void **state) {
    struct gc_arena gc = gc_new();
    struct buffer src_buf;
    buf_set_read(&src_buf, (void *)testtext, sizeof(testtext));

    uint8_t dec[sizeof(testtext)];
    struct buffer dec_buf;
    buf_set_write(&dec_buf, dec, sizeof(dec));

    struct buffer pem_buf;

    assert_true(crypto_pem_encode("TESTKEYNAME", &pem_buf, &src_buf, &gc));
    assert_true(BLEN(&src_buf) < BLEN(&pem_buf));

    /* Wrong key name */
    assert_false(crypto_pem_decode("WRONGNAME", &dec_buf, &pem_buf));

    assert_true(crypto_pem_decode("TESTKEYNAME", &dec_buf, &pem_buf));
    assert_int_equal(BLEN(&src_buf), BLEN(&dec_buf));
    assert_memory_equal(BPTR(&src_buf), BPTR(&dec_buf), BLEN(&src_buf));

    printf("%s\n", BPTR(&pem_buf));

    gc_free(&gc);
}

static void
rand_bytes_test(void **state) {
	uint8_t input[10] = {0};
	uint8_t output[10] = {0};
	assert_true(rand_bytes(output, 10));
	assert_memory_not_equal(input, output, 10);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_decode_loopback),
        cmocka_unit_test(show_available_ciphers_digests_test),
        cmocka_unit_test(rand_bytes_test),
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("crypto tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}
