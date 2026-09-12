/*
 * app_wire.h -- Wire format for Link 5: PolicyGate <-> ProtectedApp
 *
 * AppRequest: PolicyGate -> ProtectedApp (authorized request)
 * AppResponse: ProtectedApp -> PolicyGate (application response)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef APP_WIRE_H
#define APP_WIRE_H

#include <stdint.h>

#define SUBJECT_ID_MAX_APP 32

/*
 * AppRequest header:
 *   conn_id(1) + path_hash(4) + method(1) + role(1) + scope(2) +
 *   subject_id_len(1) + subject_id(32) + body_len(4) = 46 bytes
 */
#define APP_REQUEST_HEADER_SIZE 46

typedef struct __attribute__((packed)) {
    uint8_t  conn_id;
    uint32_t path_hash;
    uint8_t  method;
    uint8_t  role;
    uint16_t scope;
    uint8_t  subject_id_len;
    uint8_t  subject_id[SUBJECT_ID_MAX_APP];
    uint32_t body_len;
    uint8_t  body[];
} AppRequest;

/*
 * AppResponse header:
 *   conn_id(1) + status(1) + body_len(4) = 6 bytes
 * Same as GateResponse (reuses the format).
 */
#define APP_RESPONSE_HEADER_SIZE 6

typedef struct __attribute__((packed)) {
    uint8_t  conn_id;
    uint8_t  status;     /* 1=OK, 6=ERROR */
    uint32_t body_len;
    uint8_t  body[];
} AppResponse;

static inline uint32_t app_request_size(const AppRequest *r)
{
    return APP_REQUEST_HEADER_SIZE + r->body_len;
}

static inline uint32_t app_response_size(const AppResponse *r)
{
    return APP_RESPONSE_HEADER_SIZE + r->body_len;
}

#endif /* APP_WIRE_H */
