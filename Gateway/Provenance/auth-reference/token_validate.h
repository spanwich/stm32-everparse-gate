/*
 * token_validate.h -- HMAC-SHA256 token validation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TOKEN_VALIDATE_H
#define TOKEN_VALIDATE_H

#include <stdint.h>

/*
 * Validate a bearer token. Parses claims, recomputes HMAC, compares.
 * Returns 1 on success (sets role, scope, subject, subject_len).
 * Returns 0 on failure.
 */
int validate_token(const char *token, uint8_t token_len,
                   uint8_t *role, uint16_t *scope,
                   char *subject, uint8_t *subject_len);

#endif /* TOKEN_VALIDATE_H */
