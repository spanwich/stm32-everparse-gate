#include <stdio.h>
#include "gateway_tests.h"
#define printf gateway_test_printf
/* Adapted test harness; original assertion logic retained. */
/*
 * Test harness for F*-verified IPC.Extract module
 *
 * Tests populate_auth_fields() and populate_rate_field():
 *   - Role clamping (verified postcondition: out[6] <= 2)
 *   - Subject ID length clamping (verified postcondition: out[9] <= 32)
 *   - Scope byte copying
 *   - Rate counter population
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * The port links the active generated IPC_Extract.c implementation.
 */

#define OFF_RATE_COUNT      0
#define OFF_ROLE            6
#define OFF_SCOPE_LO        7
#define OFF_SCOPE_HI        8
#define OFF_SUBJECT_ID_LEN  9
#define OFF_SUBJECT_ID      10
#define SUBJECT_ID_MAX      32

#define AUTH_OFF_ROLE       1
#define AUTH_OFF_SCOPE_LO   2
#define AUTH_OFF_SCOPE_HI   3
#define AUTH_OFF_SUB_LEN    4
#define AUTH_OFF_SUB_START  5

#include "IPC_Extract.h"

/* Generated IPC implementation linked by both host and MCU builds. */

static int pass = 0, total = 0;

#define CHECK(name, cond) do { \
    total++; \
    if (cond) { \
        printf("  PASS: %s\n", name); \
        pass++; \
    } else { \
        printf("  FAIL: %s\n", name); \
    } \
} while(0)

static int run_original_suite_ipc_extract(void)
{
    printf("=== IPC.Extract test suite ===\n\n");

    /* --- Auth basic --- */
    printf("--- populate_auth_fields ---\n");
    {
        uint8_t out[175] = {0};
        /* auth_buf: [valid=1][role=2][scope_lo=0x03][scope_hi=0x00][sub_len=5][sub="admin"] */
        uint8_t auth[64] = {1, 2, 0x03, 0x00, 5, 'a','d','m','i','n'};
        populate_auth_fields(out, auth);

        CHECK("auth basic: role=ADMIN(2)",
              out[OFF_ROLE] == 2);
        CHECK("auth basic: scope=0x0003",
              out[OFF_SCOPE_LO] == 0x03 && out[OFF_SCOPE_HI] == 0x00);
        CHECK("auth basic: subject_id_len=5",
              out[OFF_SUBJECT_ID_LEN] == 5);
        CHECK("auth basic: subject_id='admin'",
              memcmp(&out[OFF_SUBJECT_ID], "admin", 5) == 0);
    }

    /* --- Role clamp --- */
    {
        uint8_t out[175] = {0};
        uint8_t auth[64] = {1, 99, 0xFF, 0xFF, 3, 'x','y','z'};
        populate_auth_fields(out, auth);
        CHECK("role clamp: raw=99 -> clamped=2",
              out[OFF_ROLE] == 2);
    }

    /* --- Role boundary: exactly 2 --- */
    {
        uint8_t out[175] = {0};
        uint8_t auth[64] = {1, 2, 0x01, 0x00, 0};
        populate_auth_fields(out, auth);
        CHECK("role boundary: raw=2 -> unchanged=2",
              out[OFF_ROLE] == 2);
    }

    /* --- Subject ID length clamp --- */
    {
        uint8_t out[175] = {0};
        uint8_t auth[64];
        memset(auth, 0, sizeof(auth));
        auth[0] = 1; auth[1] = 1; auth[4] = 50; /* sub_len=50, exceeds 32 */
        for (int i = 0; i < 37; i++) auth[5 + i] = (uint8_t)('A' + (i % 26));
        populate_auth_fields(out, auth);
        CHECK("subject_id_len clamp: raw=50 -> clamped=32",
              out[OFF_SUBJECT_ID_LEN] == 32);
    }

    /* --- Subject ID length zero --- */
    {
        uint8_t out[175];
        memset(out, 0xFF, sizeof(out));  /* fill with 0xFF to detect no-write */
        uint8_t auth[64] = {1, 1, 0x00, 0x00, 0};  /* sub_len=0 */
        populate_auth_fields(out, auth);
        CHECK("subject_id_len zero: len=0",
              out[OFF_SUBJECT_ID_LEN] == 0);
        /* Subject ID region should NOT have been written (still 0xFF) */
        CHECK("subject_id zero: region untouched",
              out[OFF_SUBJECT_ID] == 0xFF);
    }

    /* --- Scope endianness --- */
    {
        uint8_t out[175] = {0};
        /* scope = 0x3F00 -> scope_lo=0x00, scope_hi=0x3F */
        uint8_t auth[64] = {1, 2, 0x00, 0x3F, 0};
        populate_auth_fields(out, auth);
        CHECK("scope endianness: lo=0x00, hi=0x3F",
              out[OFF_SCOPE_LO] == 0x00 && out[OFF_SCOPE_HI] == 0x3F);
    }

    /* --- Rate field --- */
    printf("\n--- populate_rate_field ---\n");
    {
        uint8_t out[175] = {0};
        populate_rate_field(out, 42);
        CHECK("rate basic: val=42",
              out[OFF_RATE_COUNT] == 42);
    }
    {
        uint8_t out[175] = {0xFF};
        populate_rate_field(out, 0);
        CHECK("rate zero: val=0",
              out[OFF_RATE_COUNT] == 0);
    }
    {
        uint8_t out[175] = {0};
        populate_rate_field(out, 255);
        CHECK("rate max: val=255",
              out[OFF_RATE_COUNT] == 255);
    }

    printf("\n=== Results: %d/%d passed ===\n", pass, total);
    return (pass == total) ? 0 : 1;
}

void gateway_test_ipc_extract(GatewayTestStats *s)
{
    pass = total = 0;
    (void)run_original_suite_ipc_extract();
    s->passed += (uint32_t)pass;
    s->total += (uint32_t)total;
}
