/*
 * token_validate.c -- HMAC-SHA256 token validation
 *
 * Token format: <subject_hex>:<role_hex>:<scope_hex>:<hmac_hex>
 * Validation: parse claims from token, recompute HMAC, compare.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "token_validate.h"
#include <string.h>
#include "Hacl_HMAC.h"

/* Same server secret as token_generate.c */
static const uint8_t SERVER_SECRET[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
    0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
};

static int hex_char_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string to bytes. Returns number of bytes written, or 0 on error. */
static int hex_decode(const char *hex, uint8_t hex_len,
                      uint8_t *out, uint8_t out_max)
{
    if (hex_len % 2 != 0) return 0;
    uint8_t nbytes = hex_len / 2;
    if (nbytes > out_max) return 0;

    for (uint8_t i = 0; i < nbytes; i++) {
        int hi = hex_char_val(hex[i * 2]);
        int lo = hex_char_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return nbytes;
}

/* Find next ':' in token starting at pos. Returns index or -1. */
static int find_colon(const char *token, uint8_t token_len, uint8_t start)
{
    for (uint8_t i = start; i < token_len; i++) {
        if (token[i] == ':') return i;
    }
    return -1;
}

int validate_token(const char *token, uint8_t token_len,
                   uint8_t *role, uint16_t *scope,
                   char *subject, uint8_t *subject_len)
{
    /* Parse: <subject_hex>:<role_hex>:<scope_hex>:<hmac_hex> */
    int c1 = find_colon(token, token_len, 0);
    if (c1 < 0) return 0;

    int c2 = find_colon(token, token_len, (uint8_t)(c1 + 1));
    if (c2 < 0) return 0;

    int c3 = find_colon(token, token_len, (uint8_t)(c2 + 1));
    if (c3 < 0) return 0;

    /* Decode subject */
    uint8_t sub_hex_len = (uint8_t)c1;
    uint8_t sub_bytes[32];
    int sub_len = hex_decode(token, sub_hex_len, sub_bytes, 32);
    if (sub_len <= 0) return 0;

    /* Decode role (1 byte = 2 hex chars) */
    uint8_t role_hex_len = (uint8_t)(c2 - c1 - 1);
    uint8_t role_byte;
    if (hex_decode(token + c1 + 1, role_hex_len, &role_byte, 1) != 1)
        return 0;

    /* Decode scope (2 bytes LE = 4 hex chars) */
    uint8_t scope_hex_len = (uint8_t)(c3 - c2 - 1);
    uint8_t scope_bytes[2];
    if (hex_decode(token + c2 + 1, scope_hex_len, scope_bytes, 2) != 2)
        return 0;
    uint16_t scope_val = (uint16_t)scope_bytes[0] |
                         ((uint16_t)scope_bytes[1] << 8);

    /* Decode HMAC */
    uint8_t hmac_hex_len = (uint8_t)(token_len - c3 - 1);
    uint8_t token_hmac[32];
    if (hex_decode(token + c3 + 1, hmac_hex_len, token_hmac, 32) != 32)
        return 0;

    /* Recompute HMAC from parsed claims */
    uint8_t payload[64];
    uint8_t plen = 0;
    memcpy(payload + plen, sub_bytes, (uint8_t)sub_len);
    plen += (uint8_t)sub_len;
    payload[plen++] = role_byte;
    payload[plen++] = scope_bytes[0];
    payload[plen++] = scope_bytes[1];

    uint8_t expected_hmac[32];
    Hacl_HMAC_compute_sha2_256(expected_hmac, (uint8_t *)SERVER_SECRET, 32,
                                payload, plen);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= token_hmac[i] ^ expected_hmac[i];
    }
    if (diff != 0) return 0;

    /* Valid! Set outputs */
    *role = role_byte;
    *scope = scope_val;
    *subject_len = (uint8_t)sub_len;
    memcpy(subject, sub_bytes, (uint8_t)sub_len);
    return 1;
}
