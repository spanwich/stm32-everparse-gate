/*
 * control_pipeline.c -- PolicyGate pure PDP pipeline (Phase 4+5)
 *
 * No sessions, no credentials, no login handling.
 * Role/scope come pre-resolved from Authenticator (via SecurityParamsWire).
 *
 * Pipeline:
 *   1. PUT /api/policy: validate PolicyBlob via EverParse -> update store
 *   2. Else: build AccessRequest -> EverParse validate
 *      -> ACCEPT: build AppRequest -> forward to ProtectedApp
 *      -> DENY: GateResponse with DENIED status
 *
 * Phase 5: Rules are 8 bytes (added req_scope:2). AccessRequest has auth_scope.
 * Match predicate is 4-way conjunction:
 *   path_match AND method_match AND role_sufficient AND scope_sufficient
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "control_pipeline.h"
#include "gateway_routes.h"
#include "../Generated/Policy/RbacPolicyWrapper.h"
#include "gateway_log.h"
#include <string.h>
#include <stdio.h>

/* Buffer layout constants (must match RbacPolicy.3d struct layouts) */
#define POLICY_BLOB_SIZE  70  /* 3 + 64 + 3 */
#define ACCESS_REQ_SIZE   75  /* 4 + 64 + 5 + 2 */

/* Required by EverParse generated wrapper */
void RbacPolicyEverParseError(
    const char *struct_name,
    const char *field_name,
    const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

/* Write a UINT32 in little-endian */
static void write_u32(uint8_t *buf, int offset, uint32_t val)
{
    buf[offset + 0] = (val >>  0) & 0xFF;
    buf[offset + 1] = (val >>  8) & 0xFF;
    buf[offset + 2] = (val >> 16) & 0xFF;
    buf[offset + 3] = (val >> 24) & 0xFF;
}

/* Write a UINT16 in little-endian */
static void write_u16(uint8_t *buf, int offset, uint16_t val)
{
    buf[offset + 0] = (val >> 0) & 0xFF;
    buf[offset + 1] = (val >> 8) & 0xFF;
}

/* Write a policy rule (8 bytes) at offset */
static void write_rule(uint8_t *buf, int offset, const PolicyRule *r)
{
    write_u32(buf, offset, r->path_hash);
    buf[offset + 4] = r->method;
    buf[offset + 5] = r->min_role;
    write_u16(buf, offset + 6, r->req_scope);
}

/* Write all 8 rules starting at offset */
static void write_rules(uint8_t *buf, int offset, const Policy *p)
{
    for (int i = 0; i < MAX_RULES; i++) {
        /* The reference validator evaluates all eight slots, even when
         * num_rules is smaller. The wire carries the complete slot table. */
        write_rule(buf, offset + i * 8, &p->rules[i]);
    }
}

void policy_init_default(Policy *p)
{
    p->num_rules = 4;
    p->rules[0] = (PolicyRule){ PATH_STATUS, METHOD_GET,  ROLE_OPERATOR, 0x0001 }; /* READ_SENSORS */
    p->rules[1] = (PolicyRule){ PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR, 0x0000 }; /* no scope */
    p->rules[2] = (PolicyRule){ PATH_POLICY, METHOD_GET,  ROLE_ADMIN,    0x0004 }; /* CONFIGURE */
    p->rules[3] = (PolicyRule){ GATEWAY_PATH_DEMO, METHOD_GET, ROLE_ADMIN, 0x0001 };
    for (int i = 4; i < MAX_RULES; i++) {
        p->rules[i] = (PolicyRule){ DEAD_HASH, 0, 0, 0x0000 };
    }
}

/* ------------------------------------------------------------------ */
/* GateResponse / AppRequest construction helpers                      */
/* ------------------------------------------------------------------ */

static uint32_t make_gate_response(uint8_t *buf, uint8_t conn_id,
                                    uint8_t status, const char *json_body)
{
    GateResponse *resp = (GateResponse *)buf;
    resp->conn_id = conn_id;
    resp->status = status;
    if (json_body) {
        uint32_t blen = (uint32_t)strlen(json_body);
        resp->body_len = blen;
        memcpy(resp->body, json_body, blen);
        return GATE_RESPONSE_HEADER_SIZE + blen;
    } else {
        resp->body_len = 0;
        return GATE_RESPONSE_HEADER_SIZE;
    }
}

static uint32_t make_app_request(uint8_t *buf,
                                  const SecurityParamsWire *params)
{
    AppRequest *req = (AppRequest *)buf;
    req->conn_id = 0;  /* single-client demo */
    req->path_hash = params->path_hash;
    req->method = params->method;
    req->role = params->role;
    req->scope = params->scope;
    req->subject_id_len = params->subject_id_len;
    memcpy(req->subject_id, params->subject_id, SUBJECT_ID_MAX_APP);
    req->body_len = params->body_len;
    if (params->body_len > 0) {
        memcpy(req->body, params->body, params->body_len);
    }
    return APP_REQUEST_HEADER_SIZE + params->body_len;
}

/* ------------------------------------------------------------------ */
/* Request handlers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Process PUT /api/policy
 * Body format: [num_rules:1][rule_0:8]...[rule_7:8] = 65 bytes
 */
static int handle_policy_update(Policy *p,
                                 const SecurityParamsWire *params,
                                 uint8_t *gate_buf, uint32_t *gate_len)
{
    uint8_t conn_id = 0;  /* single-client demo */
    const uint8_t *body = params->body;
    uint32_t body_len = params->body_len;

    /* Defense-in-depth: rate pre-check for correct HTTP 429 status code.
     * EverParse enforces rate_count < MAX_RATE (RbacPolicy.3d line 144)
     * as the primary verified mechanism — it would reject with generic DENIED.
     * This C pre-check is redundant but maps to the correct HTTP 429 response. */
    if (params->rate_count >= MAX_RATE) {
        *gate_len = make_gate_response(gate_buf, conn_id, GATE_STATUS_RATE_LIMITED,
            "{\"status\":\"rate_limited\",\"message\":\"too many requests\"}");
        return PIPELINE_DENY;
    }

    if (body_len != 65) {
        *gate_len = make_gate_response(gate_buf, conn_id, GATE_STATUS_DENIED,
            "{\"status\":\"denied\",\"message\":\"invalid policy length\"}");
        return PIPELINE_DENY;
    }

    uint8_t num_rules = body[0];

    /* Build PolicyBlob buffer for EverParse.
     * PolicyBlob layout: [auth_state:1][rate_count:1][num_rules:1][rules:64]
     * auth_state and rate_count come from the wire (pre-resolved). */
    uint8_t buf[POLICY_BLOB_SIZE];
    memset(buf, 0, POLICY_BLOB_SIZE);
    buf[0] = params->role;        /* auth_state = role (pre-resolved) */
    buf[1] = params->rate_count;  /* rate_count from RateLimiter */
    buf[2] = num_rules;
    memcpy(buf + 3, body + 1, 64); /* Copy 8 rules (8 bytes each) */

    BOOLEAN accepted = RbacPolicyCheckPolicyBlob(buf, POLICY_BLOB_SIZE);

    if (!accepted) {
        *gate_len = make_gate_response(gate_buf, 0, GATE_STATUS_DENIED,
            "{\"status\":\"denied\",\"message\":\"access denied\"}");
        return PIPELINE_DENY;
    }

    /* Policy format valid and uploader is ADMIN — update active policy */
    p->num_rules = num_rules;
    for (int i = 0; i < MAX_RULES; i++) {
        int off = 1 + i * 8;
        p->rules[i].path_hash =
            (uint32_t)body[off + 0] |
            ((uint32_t)body[off + 1] << 8) |
            ((uint32_t)body[off + 2] << 16) |
            ((uint32_t)body[off + 3] << 24);
        p->rules[i].method = body[off + 4];
        p->rules[i].min_role = body[off + 5];
        p->rules[i].req_scope =
            (uint16_t)body[off + 6] |
            ((uint16_t)body[off + 7] << 8);
    }

    *gate_len = make_gate_response(gate_buf, 0, GATE_STATUS_OK,
        "{\"status\":\"ok\",\"message\":\"policy updated\"}");
    return PIPELINE_POLICY;
}

/*
 * Process general access request (validated by EverParse, forwarded to ProtectedApp).
 *
 * Phase 5 AccessRequest layout:
 *   [auth_state:1][rate_count:1][auth_scope:2][rules:64][path_hash:4][method:1]
 *   [_rate_ok:1][_access_ok:1]
 */
static int handle_access_request(const Policy *p,
                                  const SecurityParamsWire *params,
                                  uint8_t *gate_buf, uint32_t *gate_len,
                                  uint8_t *app_buf, uint32_t *app_len)
{
    uint8_t conn_id = 0;  /* single-client demo */
    uint32_t path_hash = params->path_hash;
    uint8_t method = params->method;

    /* Defense-in-depth: rate pre-check for correct HTTP 429 status code.
     * EverParse enforces rate_count < MAX_RATE (RbacPolicy.3d line 226)
     * as the primary verified mechanism — it would reject with generic DENIED.
     * This C pre-check is redundant but maps to the correct HTTP 429 response. */
    if (params->rate_count >= MAX_RATE) {
        *gate_len = make_gate_response(gate_buf, conn_id, GATE_STATUS_RATE_LIMITED,
            "{\"status\":\"rate_limited\",\"message\":\"too many requests\"}");
        return PIPELINE_DENY;
    }

    /* Build AccessRequest buffer for EverParse.
     * Layout: [auth_state:1][rate_count:1][auth_scope:2][rules:64][path_hash:4][method:1]
     * auth_state = role, auth_scope = scope (both pre-resolved by Authenticator). */
    uint8_t buf[ACCESS_REQ_SIZE];
    memset(buf, 0, ACCESS_REQ_SIZE);
    buf[0] = params->role;        /* auth_state = pre-resolved role */
    buf[1] = params->rate_count;  /* rate_count from RateLimiter */
    write_u16(buf, 2, params->scope); /* auth_scope from SecurityParamsWire */
    write_rules(buf, 4, p);           /* rules at offset 4 */
    write_u32(buf, 68, path_hash);
    buf[72] = method;

    BOOLEAN accepted = RbacPolicyCheckAccessRequest(buf, ACCESS_REQ_SIZE);

    if (!accepted) {
        *gate_len = make_gate_response(gate_buf, 0, GATE_STATUS_DENIED,
            "{\"status\":\"denied\",\"message\":\"access denied\"}");
        return PIPELINE_DENY;
    }

    /* Authorized: build AppRequest for ProtectedApp */
    *app_len = make_app_request(app_buf, params);
    return PIPELINE_FORWARD;
}

/* ------------------------------------------------------------------ */
/* Pipeline entry point                                                */
/* ------------------------------------------------------------------ */

int pipeline_process(Policy *policy,
                     const SecurityParamsWire *params,
                     uint8_t *gate_buf, uint32_t *gate_len,
                     uint8_t *app_buf, uint32_t *app_len)
{
    uint32_t path_hash = params->path_hash;
    uint8_t method = params->method;

    gateway_log("[PolicyGate] path=0x%08lx method=%u role=%s scope=0x%04x\n",
           (unsigned long)path_hash, method, role_name(params->role),
           params->scope);

    *gate_len = 0;
    *app_len = 0;

    /* PUT /api/policy: policy update (handled entirely by PolicyGate) */
    if (path_hash == PATH_POLICY && method == METHOD_PUT) {
        return handle_policy_update(policy, params, gate_buf, gate_len);
    }

    /* All other requests: EverParse access control -> ProtectedApp */
    return handle_access_request(policy, params,
                                  gate_buf, gate_len, app_buf, app_len);
}

const char *role_name(uint8_t role)
{
    switch (role) {
    case ROLE_NONE:     return "NONE";
    case ROLE_OPERATOR: return "OPERATOR";
    case ROLE_ADMIN:    return "ADMIN";
    default:            return "UNKNOWN";
    }
}
