#include <stdio.h>
#include "gateway_tests.h"
#define printf gateway_test_printf
/* Adapted test harness; original assertion logic retained. */
/*
 * Test harness for F*-verified extract_path_hash
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "HTTP_Extract_Path.h"

static int pass = 0, total = 0;

/* Sentinel constants (must match HTTP.Extract.Types) */
#define PATH_LOGIN    0x11111111u
#define PATH_LOGOUT   0x22222222u
#define PATH_STATUS   0x33333333u
#define PATH_POLICY   0x44444444u

#define TEST(name, input, ilen, method_end, exp_hash, exp_is_root) do { \
    total++; \
    path_result r = extract_path_hash((uint8_t *)(input), (method_end), (ilen)); \
    if (r.pr_hash == (exp_hash) && r.pr_is_root == (exp_is_root)) { \
        printf("  PASS: %s (hash=0x%08x root=%d)\n", (name), (unsigned)(r.pr_hash), r.pr_is_root); \
        pass++; \
    } else { \
        printf("  FAIL: %s (expected hash=0x%08x root=%d, got hash=0x%08x root=%d)\n", (name), (unsigned)((uint32_t)(exp_hash)), (int)(exp_is_root), (unsigned)(r.pr_hash), r.pr_is_root); \
    } \
} while(0)

static int run_original_suite_path(void)
{
    printf("=== extract_path_hash test suite ===\n\n");

    /* --- Known endpoints --- */
    /* "GET /api/login HTTP/1.1\r\n" -> method_end=4, header_end=24 */
    TEST("GET /api/login",
         "GET /api/login HTTP/1.1\r\n", 25, 4, PATH_LOGIN, 0);

    TEST("POST /api/login",
         "POST /api/login HTTP/1.1\r\n", 26, 5, PATH_LOGIN, 0);

    TEST("GET /api/logout",
         "GET /api/logout HTTP/1.1\r\n", 26, 4, PATH_LOGOUT, 0);

    TEST("GET /api/status",
         "GET /api/status HTTP/1.1\r\n", 26, 4, PATH_STATUS, 0);

    TEST("GET /api/policy",
         "GET /api/policy HTTP/1.1\r\n", 26, 4, PATH_POLICY, 0);

    TEST("PUT /api/policy",
         "PUT /api/policy HTTP/1.1\r\n", 26, 4, PATH_POLICY, 0);

    /* --- Root path --- */
    TEST("GET / (root)",
         "GET / HTTP/1.1\r\n", 17, 4, 0, 1);

    /* --- Path with query string --- */
    TEST("/api/login?foo=bar",
         "GET /api/login?foo=bar HTTP/1.1\r\n", 33, 4, PATH_LOGIN, 0);

    TEST("/api/status?v=1",
         "GET /api/status?v=1 HTTP/1.1\r\n", 30, 4, PATH_STATUS, 0);

    /* --- Unknown endpoints --- */
    TEST("unknown /api/foo",
         "GET /api/foo HTTP/1.1\r\n", 23, 4, 0, 0);

    TEST("unknown /favicon.ico",
         "GET /favicon.ico HTTP/1.1\r\n", 27, 4, 0, 0);

    TEST("unknown /api/loginx (too long)",
         "GET /api/loginx HTTP/1.1\r\n", 26, 4, 0, 0);

    TEST("unknown /api/logi (too short)",
         "GET /api/logi HTTP/1.1\r\n", 24, 4, 0, 0);

    /* --- Path traversal rejection --- */
    TEST("path traversal /../etc/passwd",
         "GET /../etc/passwd HTTP/1.1\r\n", 29, 4, 0, 0);

    TEST("path traversal /api/..hidden",
         "GET /api/..hidden HTTP/1.1\r\n", 28, 4, 0, 0);

    TEST("path traversal /api/../login",
         "GET /api/../login HTTP/1.1\r\n", 28, 4, 0, 0);

    /* --- Null byte rejection --- */
    {
        /* "/api/\0login" — embed null byte in path */
        uint8_t null_path[] = "GET /api/\x00login HTTP/1.1\r\n";
        TEST("null byte in path", null_path, sizeof(null_path) - 1, 4, 0, 0);
    }

    /* --- Edge cases --- */
    TEST("empty path (method_end == header_end)",
         "GET ", 4, 4, 0, 0);

    /* Just "/" with CR immediately after */
    TEST("root with CR delimiter",
         "GET /\r\n", 7, 4, 0, 1);

    /* Just "/" with ? immediately after */
    TEST("root with query",
         "GET /?q=1 HTTP/1.1\r\n", 20, 4, 0, 1);

    /* --- Sub-function tests: find_path_end --- */
    printf("\n--- find_path_end tests ---\n");
    {
        uint8_t buf[] = "/api/login HTTP";
        uint32_t end = find_path_end(buf, 15, 0);
        total++;
        if (end == 10) { printf("  PASS: find_path_end space\n"); pass++; }
        else printf("  FAIL: find_path_end space (expected 10, got %u)\n", (unsigned)(end));
    }
    {
        uint8_t buf[] = "/api/login?foo";
        uint32_t end = find_path_end(buf, 14, 0);
        total++;
        if (end == 10) { printf("  PASS: find_path_end query\n"); pass++; }
        else printf("  FAIL: find_path_end query (expected 10, got %u)\n", (unsigned)(end));
    }
    {
        uint8_t buf[] = "/api/login\rHTTP";
        uint32_t end = find_path_end(buf, 15, 0);
        total++;
        if (end == 10) { printf("  PASS: find_path_end CR\n"); pass++; }
        else printf("  FAIL: find_path_end CR (expected 10, got %u)\n", (unsigned)(end));
    }
    {
        uint8_t buf[] = "nospace";
        uint32_t end = find_path_end(buf, 7, 0);
        total++;
        if (end == 7) { printf("  PASS: find_path_end no delimiter\n"); pass++; }
        else printf("  FAIL: find_path_end no delimiter (expected 7, got %u)\n", (unsigned)(end));
    }

    /* --- Sub-function tests: check_no_traversal --- */
    printf("\n--- check_no_traversal tests ---\n");
    {
        uint8_t buf[] = "/api/login";
        total++;
        if (check_no_traversal(buf, 0, 10, 0)) { printf("  PASS: no traversal clean\n"); pass++; }
        else printf("  FAIL: no traversal clean\n");
    }
    {
        uint8_t buf[] = "/api/../x";
        total++;
        if (!check_no_traversal(buf, 0, 9, 0)) { printf("  PASS: traversal detected\n"); pass++; }
        else printf("  FAIL: traversal detected\n");
    }
    {
        uint8_t buf[] = "/..";
        total++;
        if (!check_no_traversal(buf, 0, 3, 0)) { printf("  PASS: traversal at start\n"); pass++; }
        else printf("  FAIL: traversal at start\n");
    }
    {
        uint8_t buf[] = "/";
        total++;
        if (check_no_traversal(buf, 0, 1, 0)) { printf("  PASS: single char safe\n"); pass++; }
        else printf("  FAIL: single char safe\n");
    }

    /* --- Sub-function tests: check_no_null --- */
    printf("\n--- check_no_null tests ---\n");
    {
        uint8_t buf[] = "/api/login";
        total++;
        if (check_no_null(buf, 10, 0)) { printf("  PASS: no null clean\n"); pass++; }
        else printf("  FAIL: no null clean\n");
    }
    {
        uint8_t buf[] = "/api/\x00x";
        total++;
        if (!check_no_null(buf, 7, 0)) { printf("  PASS: null detected\n"); pass++; }
        else printf("  FAIL: null detected\n");
    }

    printf("\n=== Results: %d/%d passed ===\n", pass, total);
    return (pass == total) ? 0 : 1;
}

void gateway_test_path(GatewayTestStats *s)
{
    pass = total = 0;
    (void)run_original_suite_path();
    s->passed += (uint32_t)pass;
    s->total += (uint32_t)total;
}
