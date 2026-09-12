#include <stdio.h>
#include "gateway_tests.h"
#define printf gateway_test_printf
/* Adapted test harness; original assertion logic retained. */
/*
 * Test harness for F*-verified parse_content_length
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "HTTP_Extract_Header.h"

static int pass = 0, total = 0;

/* Must match HTTP.Extract.Types max_inline_body */
#define MAX_INLINE_BODY 1361

#define TEST(name, input, header_end, expected) do { \
    total++; \
    uint32_t r = parse_content_length((uint8_t *)(input), (header_end)); \
    if (r == (expected)) { \
        printf("  PASS: %s (val=%u)\n", (name), (unsigned)(r)); \
        pass++; \
    } else { \
        printf("  FAIL: %s (expected %u, got %u)\n", (name), (unsigned)((uint32_t)(expected)), (unsigned)(r)); \
    } \
} while(0)

static int run_original_suite_header(void)
{
    printf("=== parse_content_length test suite ===\n\n");

    /* --- Basic Content-Length parsing --- */
    TEST("Content-Length: 42",
         "GET / HTTP/1.1\r\nContent-Length: 42\r\n\r\n", 36, 42);

    TEST("Content-Length: 0",
         "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 35, 0);

    TEST("Content-Length: 100",
         "GET / HTTP/1.1\r\nContent-Length: 100\r\n\r\n", 37, 100);

    TEST("Content-Length: 1361 (max)",
         "GET / HTTP/1.1\r\nContent-Length: 1361\r\n\r\n", 38, 1361);

    /* --- Lowercase variant --- */
    TEST("content-length: 42",
         "GET / HTTP/1.1\r\ncontent-length: 42\r\n\r\n", 36, 42);

    TEST("content-length: 200",
         "POST /api/login HTTP/1.1\r\ncontent-length: 200\r\n\r\n", 47, 200);

    /* --- Over limit --- */
    TEST("Content-Length: 1362 (over max)",
         "GET / HTTP/1.1\r\nContent-Length: 1362\r\n\r\n", 38, MAX_INLINE_BODY + 1);

    TEST("Content-Length: 9999 (way over)",
         "GET / HTTP/1.1\r\nContent-Length: 9999\r\n\r\n", 38, MAX_INLINE_BODY + 1);

    /* --- No Content-Length header --- */
    TEST("no CL header",
         "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 33, 0);

    TEST("empty headers",
         "GET / HTTP/1.1\r\n\r\n", 16, 0);

    /* --- Spaces around value --- */
    TEST("CL with extra spaces",
         "GET / HTTP/1.1\r\nContent-Length:   50\r\n\r\n", 38, 50);

    TEST("CL no space after colon",
         "GET / HTTP/1.1\r\nContent-Length:50\r\n\r\n", 35, 50);

    /* --- Multiple headers (first match) --- */
    TEST("CL among other headers",
         "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 77\r\nAccept: */*\r\n\r\n",
         56, 77);

    /* --- Edge cases --- */
    TEST("CL at very start (after request line CRLF)",
         "GET /\r\nContent-Length: 10\r\n\r\n", 25, 10);

    TEST("partial header name (Content-Lengt)",
         "GET / HTTP/1.1\r\nContent-Lengt: 42\r\n\r\n", 36, 0);

    /* Single digit */
    TEST("Content-Length: 5",
         "GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n", 35, 5);

    /* --- Sub-function tests --- */
    printf("\n--- parse_digits tests ---\n");
    {
        uint8_t buf[] = "123";
        total++;
        uint32_t r = parse_digits(buf, 3, 0, 0);
        if (r == 123) { printf("  PASS: parse_digits 123\n"); pass++; }
        else printf("  FAIL: parse_digits 123 (got %u)\n", (unsigned)(r));
    }
    {
        uint8_t buf[] = "0";
        total++;
        uint32_t r = parse_digits(buf, 1, 0, 0);
        if (r == 0) { printf("  PASS: parse_digits 0\n"); pass++; }
        else printf("  FAIL: parse_digits 0 (got %u)\n", (unsigned)(r));
    }
    {
        uint8_t buf[] = "1362";
        total++;
        uint32_t r = parse_digits(buf, 4, 0, 0);
        if (r == MAX_INLINE_BODY + 1) { printf("  PASS: parse_digits 1362 clamped\n"); pass++; }
        else printf("  FAIL: parse_digits 1362 clamped (got %u)\n", (unsigned)(r));
    }
    {
        uint8_t buf[] = "42xyz";
        total++;
        uint32_t r = parse_digits(buf, 5, 0, 0);
        if (r == 42) { printf("  PASS: parse_digits stops at non-digit\n"); pass++; }
        else printf("  FAIL: parse_digits stops at non-digit (got %u)\n", (unsigned)(r));
    }

    printf("\n--- skip_spaces tests ---\n");
    {
        uint8_t buf[] = "   hello";
        total++;
        uint32_t r = skip_spaces(buf, 8, 0);
        if (r == 3) { printf("  PASS: skip 3 spaces\n"); pass++; }
        else printf("  FAIL: skip 3 spaces (got %u)\n", (unsigned)(r));
    }
    {
        uint8_t buf[] = "hello";
        total++;
        uint32_t r = skip_spaces(buf, 5, 0);
        if (r == 0) { printf("  PASS: skip no spaces\n"); pass++; }
        else printf("  FAIL: skip no spaces (got %u)\n", (unsigned)(r));
    }

    printf("\n=== Results: %d/%d passed ===\n", pass, total);
    return (pass == total) ? 0 : 1;
}

void gateway_test_header(GatewayTestStats *s)
{
    pass = total = 0;
    (void)run_original_suite_header();
    s->passed += (uint32_t)pass;
    s->total += (uint32_t)total;
}
