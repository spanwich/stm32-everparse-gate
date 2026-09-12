/*
 * extract.h -- Interface for HTTP security parameter extraction.
 *
 * The ExtractionResult enum defines result codes (matching F* Types module).
 * The function extract_security_params() is provided by the KreMLin-extracted
 * HTTP_Extract_Complete.h (F*-verified implementation).
 *
 * Phase 3+: Extended .fst adds extract_bearer_token.
 *   Additionally populates: token_len, token.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EXTRACT_H
#define EXTRACT_H

#include <stdint.h>

typedef enum {
    EXTRACT_OK             = 0,
    EXTRACT_INCOMPLETE     = 1,
    EXTRACT_MALFORMED      = 2,
    EXTRACT_BODY_TOO_LARGE = 3,
    EXTRACT_PATH_TRAVERSAL = 4,
    EXTRACT_METHOD_UNKNOWN = 5
} ExtractionResult;

/*
 * extract_security_params() is now provided by KreMLin-extracted
 * HTTP_Extract_Complete.{c,h} — an F*-verified implementation.
 *
 * Signature (from HTTP_Extract_Complete.h):
 *   uint8_t extract_security_params(
 *       uint8_t *http_buf, uint32_t http_len,
 *       uint8_t *out_buf, uint32_t *out_len);
 *
 * Return values match this enum (0-5). Callers should use:
 *   uint8_t r = extract_security_params(...);
 *   if (r == EXTRACT_OK) { ... }
 */

#endif /* EXTRACT_H */
