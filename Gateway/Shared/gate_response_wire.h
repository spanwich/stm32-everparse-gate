/*
 * gate_response_wire.h -- PolicyGate -> FStarExtractor response protocol.
 *
 * PolicyGate NEVER generates HTTP. It sends status code + optional body.
 * FStarExtractor maps status to HTTP response and wraps body.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GATE_RESPONSE_WIRE_H
#define GATE_RESPONSE_WIRE_H

#include <stdint.h>

#define GATE_STATUS_OK            1   /* -> HTTP 200 */
#define GATE_STATUS_DENIED        2   /* -> HTTP 403 */
#define GATE_STATUS_RATE_LIMITED   3   /* -> HTTP 429 */
#define GATE_STATUS_NO_AUTH       4   /* -> HTTP 401 */
#define GATE_STATUS_NOT_FOUND     5   /* -> HTTP 404 */
#define GATE_STATUS_ERROR         6   /* -> HTTP 500 */

#define GATE_RESPONSE_HEADER_SIZE 6

typedef struct __attribute__((packed)) {
    uint8_t  conn_id;
    uint8_t  status;              /* GATE_STATUS_* */
    uint32_t body_len;            /* 0 if no body */
    uint8_t  body[];
} GateResponse;

static inline uint32_t gate_response_size(const GateResponse *r)
{
    return GATE_RESPONSE_HEADER_SIZE + r->body_len;
}

#endif /* GATE_RESPONSE_WIRE_H */
