/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Engine-neutral ABI for the Cedar/EverParse Microkit comparison.
 */
#ifndef CEDAR_GATEWAY_ABI_H
#define CEDAR_GATEWAY_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WEB_FRAME_MTU 1536u
#define RING_SLOTS 4u
#define RING_MASK (RING_SLOTS - 1u)

#define AUTH_TOKEN_MAX 128u
#define SUBJECT_ID_MAX 32u
#define SECURITY_PARAMS_HEADER_SIZE 175u
#define MAX_INLINE_BODY (WEB_FRAME_MTU - SECURITY_PARAMS_HEADER_SIZE)

#define GATE_RESPONSE_HEADER_SIZE 6u
#define APP_REQUEST_HEADER_SIZE 46u
#define APP_RESPONSE_HEADER_SIZE 6u

#define MAX_RULES 8u
#define POLICY_RULE_SIZE 8u
#define POLICY_UPDATE_BODY_SIZE (1u + MAX_RULES * POLICY_RULE_SIZE)
#define ACCESS_REQUEST_SIZE 75u

#define PATH_LOGIN UINT32_C(0x11111111)
#define PATH_LOGOUT UINT32_C(0x22222222)
#define PATH_STATUS UINT32_C(0x33333333)
#define PATH_POLICY UINT32_C(0x44444444)
#define PATH_DEMO UINT32_C(0x55555555)
#define PATH_REPORTS UINT32_C(0x66666666)
#define INACTIVE_PATH_ID UINT32_C(0xDEADDEAD)

#define METHOD_GET UINT8_C(0x01)
#define METHOD_POST UINT8_C(0x02)
#define METHOD_PUT UINT8_C(0x04)
#define METHOD_DELETE UINT8_C(0x08)
#define METHOD_PATCH UINT8_C(0x10)
#define METHOD_HEAD UINT8_C(0x20)
#define METHOD_MASK_ALL UINT8_C(0x3f)

#define ROLE_NONE UINT8_C(0)
#define ROLE_OPERATOR UINT8_C(1)
#define ROLE_ADMIN UINT8_C(2)

#define MAX_RATE UINT8_C(50)

typedef struct {
    uint16_t len;
    uint8_t data[WEB_FRAME_MTU];
} FrameEntry;

typedef struct {
    volatile uint32_t head;
    volatile uint32_t tail;
    FrameEntry frames[RING_SLOTS];
} RingDataport;

typedef struct __attribute__((packed)) {
    uint8_t rate_count;
    uint32_t path_id;
    uint8_t method;
    uint8_t role;
    uint16_t scope;
    uint8_t subject_id_len;
    uint8_t subject_id[SUBJECT_ID_MAX];
    uint8_t token_len;
    uint8_t token[AUTH_TOKEN_MAX];
    uint32_t body_len;
    uint8_t body[];
} SecurityParamsWire;

typedef struct __attribute__((packed)) {
    uint8_t conn_id;
    uint8_t status;
    uint32_t body_len;
    uint8_t body[];
} GateResponse;

typedef struct __attribute__((packed)) {
    uint8_t conn_id;
    uint32_t path_id;
    uint8_t method;
    uint8_t role;
    uint16_t scope;
    uint8_t subject_id_len;
    uint8_t subject_id[SUBJECT_ID_MAX];
    uint32_t body_len;
    uint8_t body[];
} AppRequest;

typedef struct __attribute__((packed)) {
    uint8_t conn_id;
    uint8_t status;
    uint32_t body_len;
    uint8_t body[];
} AppResponse;

typedef struct {
    uint32_t path_id;
    uint8_t method;
    uint8_t role;
    uint16_t scope;
    uint8_t rate_count;
} DecisionInput;

typedef struct {
    uint32_t path_id;
    uint8_t method;
    uint8_t min_role;
    uint16_t required_scope;
} PolicyRule;

typedef struct {
    uint8_t num_rules;
    PolicyRule rules[MAX_RULES];
} CompactPolicy;

typedef enum {
    DECISION_DENY = 0,
    DECISION_ALLOW = 1,
    DECISION_RATE_LIMITED = 2,
    DECISION_INTERNAL_ERROR = 3
} DecisionResult;

typedef enum {
    UPDATE_REJECTED = 0,
    UPDATE_APPLIED = 1,
    UPDATE_INTERNAL_ERROR = 2
} UpdateResult;

typedef enum {
    OUTPUT_NONE = 0,
    OUTPUT_GATE_RESPONSE = 1,
    OUTPUT_APP_REQUEST = 2
} OutputKind;

typedef struct {
    OutputKind kind;
    uint32_t len;
    uint8_t bytes[WEB_FRAME_MTU];
} PipelineOutput;

enum {
    GATE_STATUS_OK = 1,
    GATE_STATUS_DENIED = 2,
    GATE_STATUS_RATE_LIMITED = 3,
    GATE_STATUS_NO_AUTH = 4,
    GATE_STATUS_NOT_FOUND = 5,
    GATE_STATUS_ERROR = 6
};

_Static_assert(sizeof(FrameEntry) == 1538u, "frame ABI changed");
_Static_assert(sizeof(RingDataport) <= 8192u, "ring must fit an 8 KiB region");
_Static_assert(sizeof(PolicyRule) == 8u, "policy rule ABI changed");
_Static_assert(sizeof(SecurityParamsWire) == SECURITY_PARAMS_HEADER_SIZE,
               "security-parameter ABI changed");
_Static_assert(sizeof(AppRequest) == APP_REQUEST_HEADER_SIZE,
               "application request ABI changed");

#endif
