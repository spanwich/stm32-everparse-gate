/*
 * control_pipeline.h -- PolicyGate pure PDP pipeline (Phase 4)
 *
 * No sessions, no credentials, no login handling.
 * SecurityParamsWire arrives with role/scope pre-resolved by Authenticator.
 * PolicyGate only does: EverParse validation + policy enforcement.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CONTROL_PIPELINE_H
#define CONTROL_PIPELINE_H

#include <stdint.h>
#include "security_params_wire.h"
#include "gate_response_wire.h"
#include "app_wire.h"
#include "path_hashes.h"

/* Limits (must match RbacPolicy.3d) */
#define MAX_RATE      50
#define MAX_RULES     8

/* A single policy rule */
typedef struct {
    uint32_t path_hash;
    uint8_t  method;
    uint8_t  min_role;
    uint16_t req_scope;
} PolicyRule;

/* Active policy */
typedef struct {
    uint8_t    num_rules;
    PolicyRule rules[MAX_RULES];
} Policy;

/* Pipeline result codes */
#define PIPELINE_FORWARD  0  /* Authorized: forward AppRequest to ProtectedApp */
#define PIPELINE_DENY     1  /* Denied: send GateResponse back to FStarExtractor */
#define PIPELINE_POLICY   2  /* Policy updated: send GateResponse back */

/*
 * Pipeline entry point for PolicyGate (Phase 4: pure PDP).
 *
 * Accepts SecurityParamsWire (role/scope pre-resolved by Authenticator).
 * Returns PIPELINE_FORWARD with AppRequest in app_buf, or
 *         PIPELINE_DENY/PIPELINE_POLICY with GateResponse in gate_buf.
 *
 * gate_len/app_len set to bytes written.
 */
int pipeline_process(Policy *policy,
                     const SecurityParamsWire *params,
                     uint8_t *gate_buf, uint32_t *gate_len,
                     uint8_t *app_buf, uint32_t *app_len);

void policy_init_default(Policy *p);
const char *role_name(uint8_t role);

#endif /* CONTROL_PIPELINE_H */
