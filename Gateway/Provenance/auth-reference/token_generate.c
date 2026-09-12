/*
 * token_generate.c -- HMAC-SHA256 token generation
 *
 * Token = <subject_hex>:<role_hex>:<scope_hex>:<hmac_hex>
 * HMAC computed over: subject || role || scope (deterministic).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "token_generate.h"
#include <string.h>
#include "Hacl_HMAC.h"

/* Hardcoded server secret (32 bytes) — demo only */
static const uint8_t SERVER_SECRET[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
    0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
};

static const char HEX[] = "0123456789abcdef";

static int hex_encode(const uint8_t *data, uint8_t len,
                      char *out, uint8_t out_max)
{
    if ((uint16_t)len * 2 > out_max) return 0;
    for (uint8_t i = 0; i < len; i++) {
        out[i * 2]     = HEX[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX[data[i] & 0x0F];
    }
    return len * 2;
}

int generate_token(const char *subject, uint8_t subject_len,
                   uint8_t role, uint16_t scope,
                   char *token_out, uint8_t *token_len)
{
    /* Build payload: subject || role || scope_le */
    uint8_t payload[64];
    uint8_t plen = 0;

    if (subject_len > 32) return 0;
    memcpy(payload + plen, subject, subject_len);
    plen += subject_len;
    payload[plen++] = role;
    payload[plen++] = (uint8_t)(scope & 0xFF);
    payload[plen++] = (uint8_t)((scope >> 8) & 0xFF);

    /* Compute HMAC-SHA256 (HACL* verified, void return) */
    uint8_t hmac[32];
    Hacl_HMAC_compute_sha2_256(hmac, (uint8_t *)SERVER_SECRET, 32,
                                payload, plen);

    /* Format: <subject_hex>:<role_hex>:<scope_hex>:<hmac_hex> */
    uint8_t pos = 0;
    uint8_t max = 127; /* token_buf is 128, leave room */

    int n = hex_encode((const uint8_t *)subject, subject_len,
                       token_out + pos, max - pos);
    if (n == 0) return 0;
    pos += n;
    token_out[pos++] = ':';

    n = hex_encode(&role, 1, token_out + pos, max - pos);
    if (n == 0) return 0;
    pos += n;
    token_out[pos++] = ':';

    uint8_t scope_le[2] = { (uint8_t)(scope & 0xFF),
                             (uint8_t)((scope >> 8) & 0xFF) };
    n = hex_encode(scope_le, 2, token_out + pos, max - pos);
    if (n == 0) return 0;
    pos += n;
    token_out[pos++] = ':';

    n = hex_encode(hmac, 32, token_out + pos, max - pos);
    if (n == 0) return 0;
    pos += n;

    *token_len = pos;
    return 1;
}
