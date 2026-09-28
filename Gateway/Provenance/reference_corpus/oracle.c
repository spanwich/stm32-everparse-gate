/*
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gateway_common.h"

void compact_policy_init_default(CompactPolicy *policy)
{
    policy->num_rules = 3u;
    policy->rules[0] = (PolicyRule){
        PATH_STATUS, METHOD_GET, ROLE_OPERATOR, UINT16_C(0x0001)
    };
    policy->rules[1] = (PolicyRule){
        PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR, UINT16_C(0x0000)
    };
    policy->rules[2] = (PolicyRule){
        PATH_POLICY, METHOD_GET, ROLE_ADMIN, UINT16_C(0x0004)
    };
    for (size_t i = 3u; i < MAX_RULES; ++i) {
        policy->rules[i] = (PolicyRule){
            INACTIVE_PATH_ID, 0u, ROLE_NONE, 0u
        };
    }
}

DecisionResult reference_decide(const CompactPolicy *policy,
                                const DecisionInput *input)
{
    if (input->rate_count >= MAX_RATE) {
        return DECISION_RATE_LIMITED;
    }

    for (size_t i = 0u; i < MAX_RULES; ++i) {
        const PolicyRule *rule = &policy->rules[i];
        if (rule->path_id == input->path_id &&
            (rule->method & input->method) == input->method &&
            input->role >= rule->min_role &&
            (input->scope & rule->required_scope) ==
                rule->required_scope) {
            return DECISION_ALLOW;
        }
    }
    return DECISION_DENY;
}

bool validate_policy_update_fields(const DecisionInput *input,
                                   const uint8_t *body, uint32_t body_len,
                                   CompactPolicy *candidate)
{
    if (input == NULL || body == NULL || candidate == NULL ||
        input->role < ROLE_ADMIN || input->rate_count >= MAX_RATE ||
        body_len < POLICY_UPDATE_BODY_SIZE) {
        return false;
    }

    const uint8_t num_rules = body[0];
    if (num_rules == 0u || num_rules > MAX_RULES) {
        return false;
    }

    candidate->num_rules = num_rules;
    for (size_t i = 0u; i < MAX_RULES; ++i) {
        const size_t offset = 1u + i * POLICY_RULE_SIZE;
        PolicyRule *rule = &candidate->rules[i];
        rule->path_id = read_u32_le(body, offset);
        rule->method = body[offset + 4u];
        rule->min_role = body[offset + 5u];
        rule->required_scope = read_u16_le(body, offset + 6u);
        if (rule->method > METHOD_MASK_ALL || rule->min_role > ROLE_ADMIN) {
            return false;
        }
    }
    return true;
}
