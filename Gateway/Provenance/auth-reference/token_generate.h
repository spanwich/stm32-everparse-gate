/*
 * token_generate.h -- HMAC-SHA256 token generation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TOKEN_GENERATE_H
#define TOKEN_GENERATE_H

#include <stdint.h>

/*
 * Generate a bearer token from subject + role + scope.
 * Token format: <subject_hex>:<role_hex>:<scope_hex>:<hmac_hex>
 * Returns 1 on success, 0 on failure.
 */
int generate_token(const char *subject, uint8_t subject_len,
                   uint8_t role, uint16_t scope,
                   char *token_out, uint8_t *token_len);

#endif /* TOKEN_GENERATE_H */
