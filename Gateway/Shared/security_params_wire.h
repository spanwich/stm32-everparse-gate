/*
 * security_params_wire.h -- Flat, pointer-free security parameters for
 * cross-component SPSC ring (FStarExtractor -> PolicyGate).
 *
 * Phase 1-2: token_len=0, role/scope/subject zeroed (session-based auth).
 * Phase 3-4: token populated from Authorization header; role/scope from PIP.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SECURITY_PARAMS_WIRE_H
#define SECURITY_PARAMS_WIRE_H

#include <stdint.h>

#define AUTH_TOKEN_MAX   128
#define SUBJECT_ID_MAX   32

/*
 * Fixed header: rate_count(1) + path_hash(4) + method(1) + role(1) + scope(2) +
 * subject_id_len(1) + subject_id(32) + token_len(1) + token(128) +
 * body_len(4) = 175 bytes.
 */
#define SECPARAMS_HEADER_SIZE  175
#define MAX_INLINE_BODY        (1536 - SECPARAMS_HEADER_SIZE)  /* 1361 */

typedef struct __attribute__((packed)) {
    uint8_t  rate_count;                  /* rate limiter counter */
    uint32_t path_hash;
    uint8_t  method;                     /* 1=GET, 2=POST, 3=PUT */
    uint8_t  role;                       /* Phase 1-2: 0 */
    uint16_t scope;                      /* Phase 1-2: 0 */
    uint8_t  subject_id_len;             /* Phase 1-2: 0 */
    uint8_t  subject_id[SUBJECT_ID_MAX];
    uint8_t  token_len;                  /* Phase 1-2: 0 */
    uint8_t  token[AUTH_TOKEN_MAX];
    uint32_t body_len;                   /* 0 for GET requests */
    uint8_t  body[];                     /* flexible array member */
} SecurityParamsWire;

static inline uint32_t secparams_wire_size(const SecurityParamsWire *p)
{
    return SECPARAMS_HEADER_SIZE + p->body_len;
}

#endif /* SECURITY_PARAMS_WIRE_H */
