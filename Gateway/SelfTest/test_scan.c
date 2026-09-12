#include <stdio.h>
#include "gateway_tests.h"
#define printf gateway_test_printf
/* Adapted test harness; original assertion logic retained. */
/*
 * Test harness for F*-verified find_header_end
 *
 * Calls the KreMLin-extracted C function with known HTTP requests
 * and verifies correct behavior.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "HTTP_Extract_Scan.h"

static int tests_passed = 0;
static int tests_total = 0;

#define TEST(name, buf, buflen, expected) do { \
    tests_total++; \
    uint32_t result = find_header_end((uint8_t *)(buf), (buflen)); \
    if (result == (expected)) { \
        printf("  PASS: %s (result=%u)\n", (name), (unsigned)(result)); \
        tests_passed++; \
    } else { \
        printf("  FAIL: %s (expected=%u, got=%u)\n", (name), (unsigned)((expected)), (unsigned)(result)); \
    } \
} while(0)

static int run_original_suite_scan(void)
{
    printf("=== find_header_end test suite ===\n\n");

    /* Test 1: Standard HTTP GET with headers */
    {
        const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBody";
        /*  0: G E T   / _ H T T P / 1 . 1 \r \n  (16 bytes)
         * 16: H o s t : _ e x a m p l e . c o m  (17 bytes)
         * 33: \r \n \r \n                          (4 bytes)
         * 37: B o d y
         * Pattern \r\n\r\n starts at offset 33
         */
        TEST("standard GET request", req, (uint32_t)strlen(req), 33);
    }

    /* Test 2: No header end (incomplete headers) */
    {
        const char *incomplete = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        uint32_t len = (uint32_t)strlen(incomplete);
        TEST("incomplete headers", incomplete, len, len);
    }

    /* Test 3: Empty buffer */
    {
        TEST("empty buffer", "", 0, 0);
    }

    /* Test 4: Too short (< 4 bytes) */
    {
        TEST("1 byte", "X", 1, 1);
        TEST("2 bytes", "XY", 2, 2);
        TEST("3 bytes", "XYZ", 3, 3);
    }

    /* Test 5: Exactly \r\n\r\n (pattern at offset 0) */
    {
        TEST("pattern at offset 0", "\r\n\r\n", 4, 0);
    }

    /* Test 6: Pattern at offset 1 */
    {
        TEST("pattern at offset 1", "X\r\n\r\n", 5, 1);
    }

    /* Test 7: Pattern at the last possible position */
    {
        const char *at_end = "abcdef\r\n\r\n";
        uint32_t len = (uint32_t)strlen(at_end);
        /* len=10, pattern at offset 6, which is len-4=6. Valid. */
        TEST("pattern at last position", at_end, len, 6);
    }

    /* Test 8: Multiple \r\n but no double (single CRLFs) */
    {
        const char *single_crlf = "Header1: val\r\nHeader2: val\r\n";
        uint32_t len = (uint32_t)strlen(single_crlf);
        TEST("single CRLFs only", single_crlf, len, len);
    }

    /* Test 9: First of multiple \r\n\r\n occurrences */
    {
        const char *multi = "H: v\r\n\r\nBody\r\n\r\nMore";
        /* First \r\n\r\n at offset 4 */
        TEST("first of multiple occurrences", multi, (uint32_t)strlen(multi), 4);
    }

    /* Test 10: Binary data with 0x0D 0x0A pattern */
    {
        uint8_t bin[] = { 0x00, 0xFF, 0x0D, 0x0A, 0x0D, 0x0A, 0x42 };
        TEST("binary data", bin, 7, 2);
    }

    /* Test 11: Realistic HTTP POST */
    {
        const char *post =
            "POST /api/login HTTP/1.1\r\n"
            "Host: 192.168.1.10\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 42\r\n"
            "\r\n"
            "{\"username\":\"admin\",\"password\":\"admin456\"}";
        /* Count header bytes:
         * "POST /api/login HTTP/1.1\r\n" = 26
         * "Host: 192.168.1.10\r\n"       = 20
         * "Content-Type: application/json\r\n" = 32
         * "Content-Length: 42\r\n"        = 20
         * Total header lines = 98 bytes
         * Then "\r\n" = 2 more bytes -> pattern at 98
         */
        uint32_t len = (uint32_t)strlen(post);
        uint32_t result = find_header_end((uint8_t *)post, len);
        /* Verify it found something and the found position has \r\n\r\n */
        if (result < len &&
            post[result] == '\r' && post[result+1] == '\n' &&
            post[result+2] == '\r' && post[result+3] == '\n') {
            printf("  PASS: realistic POST (header_end=%u, body starts at %u)\n", (unsigned)(result), (unsigned)(result + 4));
            tests_passed++;
        } else {
            printf("  FAIL: realistic POST (result=%u, len=%u)\n", (unsigned)(result), (unsigned)(len));
        }
        tests_total++;
    }

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}

void gateway_test_scan(GatewayTestStats *s)
{
    tests_passed = tests_total = 0;
    (void)run_original_suite_scan();
    s->passed += (uint32_t)tests_passed;
    s->total += (uint32_t)tests_total;
}
