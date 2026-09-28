/*
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gateway_common.h"
#include "gateway_engine.h"

#include <stdio.h>
#include <string.h>

static int failures;
static uint64_t comparisons;
static uint32_t random_state = UINT32_C(0x5eedc0de);

static uint32_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static void expect(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}

static void encode_policy_body(uint8_t body[POLICY_UPDATE_BODY_SIZE],
                               const CompactPolicy *policy)
{
    memset(body, 0, POLICY_UPDATE_BODY_SIZE);
    body[0] = policy->num_rules;
    for (size_t i = 0u; i < MAX_RULES; ++i) {
        const size_t offset = 1u + i * POLICY_RULE_SIZE;
        const PolicyRule *rule = &policy->rules[i];
        write_u32_le(body, offset, rule->path_id);
        body[offset + 4u] = rule->method;
        body[offset + 5u] = rule->min_role;
        write_u16_le(body, offset + 6u, rule->required_scope);
    }
}

static void install_policy(const CompactPolicy *policy)
{
    uint8_t body[POLICY_UPDATE_BODY_SIZE];
    const DecisionInput administrator = {
        .path_id = PATH_POLICY,
        .method = METHOD_PUT,
        .role = ROLE_ADMIN,
        .scope = UINT16_MAX,
        .rate_count = 0u,
    };
    encode_policy_body(body, policy);
    expect(engine_update(&administrator, body, sizeof(body)) == UPDATE_APPLIED,
           "valid policy update should apply");
}

static bool policies_equal(const CompactPolicy *left,
                           const CompactPolicy *right)
{
    if (left->num_rules != right->num_rules) {
        return false;
    }
    for (size_t slot = 0u; slot < MAX_RULES; ++slot) {
        const PolicyRule *a = &left->rules[slot];
        const PolicyRule *b = &right->rules[slot];
        if (a->path_id != b->path_id || a->method != b->method ||
            a->min_role != b->min_role ||
            a->required_scope != b->required_scope) {
            return false;
        }
    }
    return true;
}

static void test_policy_readback(void)
{
    CompactPolicy expected;
    CompactPolicy observed = {0};
    compact_policy_init_default(&expected);

    expect(engine_get_policy(NULL) != 0,
           "null policy readback output must be rejected");
    expect(engine_get_policy(&observed) == 0,
           "default policy should be readable");
    expect(policies_equal(&observed, &expected),
           "default policy readback must match the active rules");

    expected.num_rules = 5u;
    expected.rules[3] = (PolicyRule){
        PATH_DEMO, METHOD_GET, ROLE_OPERATOR, UINT16_C(0x0001)
    };
    expected.rules[4] = (PolicyRule){
        PATH_REPORTS, METHOD_GET, ROLE_ADMIN, UINT16_C(0x0004)
    };
    install_policy(&expected);
    expect(engine_get_policy(&observed) == 0,
           "updated policy should be readable");
    expect(policies_equal(&observed, &expected),
           "readback must reflect every installed policy slot");

    uint8_t body[POLICY_UPDATE_BODY_SIZE];
    encode_policy_body(body, &expected);
    body[1u + 5u] = ROLE_ADMIN + 1u;
    const DecisionInput administrator = {
        PATH_POLICY, METHOD_PUT, ROLE_ADMIN, UINT16_MAX, 0u
    };
    expect(engine_update(&administrator, body, sizeof(body)) ==
               UPDATE_REJECTED,
           "invalid readback test update must be rejected");
    expect(engine_get_policy(&observed) == 0 &&
               policies_equal(&observed, &expected),
           "rejected update must preserve policy readback");

    compact_policy_init_default(&expected);
    install_policy(&expected);
}

static void test_default_scenarios(void)
{
    CompactPolicy policy;
    compact_policy_init_default(&policy);
    install_policy(&policy);

    const DecisionInput cases[] = {
        { PATH_STATUS, METHOD_GET, ROLE_OPERATOR, 0x0001u, 0u },
        { PATH_STATUS, METHOD_GET, ROLE_NONE, 0x0001u, 0u },
        { PATH_STATUS, METHOD_GET, ROLE_OPERATOR, 0x0000u, 0u },
        { PATH_STATUS, METHOD_POST, ROLE_ADMIN, 0xffffu, 0u },
        { UINT32_C(0xfeedbeef), METHOD_GET, ROLE_ADMIN, 0xffffu, 0u },
        { PATH_STATUS, METHOD_GET, ROLE_ADMIN, 0xffffu, MAX_RATE },
    };

    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const DecisionResult expected = reference_decide(&policy, &cases[i]);
        const DecisionResult observed = engine_decide(&cases[i]);
        ++comparisons;
        if (observed != expected) {
            fprintf(stderr,
                    "FAIL: default case %zu expected=%d observed=%d\n",
                    i, expected, observed);
            ++failures;
        }
    }
}

static void test_method_masks(void)
{
    CompactPolicy policy = { .num_rules = 1u };
    for (size_t i = 0u; i < MAX_RULES; ++i) {
        policy.rules[i] = (PolicyRule){
            INACTIVE_PATH_ID, 0u, ROLE_ADMIN, UINT16_MAX
        };
    }
    policy.rules[0].path_id = PATH_STATUS;
    policy.rules[0].min_role = ROLE_NONE;
    policy.rules[0].required_scope = 0u;

    for (uint16_t rule_mask = 0u; rule_mask <= METHOD_MASK_ALL; ++rule_mask) {
        policy.rules[0].method = (uint8_t)rule_mask;
        install_policy(&policy);
        for (uint16_t request_mask = 0u;
             request_mask <= METHOD_MASK_ALL; ++request_mask) {
            const DecisionInput input = {
                PATH_STATUS, (uint8_t)request_mask, ROLE_NONE, 0u, 0u
            };
            const DecisionResult expected = reference_decide(&policy, &input);
            const DecisionResult observed = engine_decide(&input);
            ++comparisons;
            if (observed != expected) {
                fprintf(stderr,
                        "FAIL: method rule=0x%02x request=0x%02x "
                        "expected=%d observed=%d\n",
                        rule_mask, request_mask, expected, observed);
                ++failures;
                return;
            }
        }
    }
}

static void test_role_scope_and_slot_positions(void)
{
    static const uint16_t scope_values[] = {
        0u, 1u, 2u, 4u, 0x00ffu, 0xff00u, 0xaaaau, 0xffffu
    };
    CompactPolicy policy = { .num_rules = 1u };

    for (size_t slot = 0u; slot < MAX_RULES; ++slot) {
        for (size_t i = 0u; i < MAX_RULES; ++i) {
            policy.rules[i] = (PolicyRule){
                INACTIVE_PATH_ID, 0u, ROLE_ADMIN, UINT16_MAX
            };
        }
        policy.rules[slot] = (PolicyRule){
            PATH_STATUS, METHOD_MASK_ALL, ROLE_OPERATOR, 0xaaaau
        };
        install_policy(&policy);

        for (uint8_t role = ROLE_NONE; role <= ROLE_ADMIN; ++role) {
            for (size_t i = 0u;
                 i < sizeof(scope_values) / sizeof(scope_values[0]); ++i) {
                const DecisionInput input = {
                    PATH_STATUS, METHOD_GET, role, scope_values[i], 0u
                };
                const DecisionResult expected =
                    reference_decide(&policy, &input);
                const DecisionResult observed = engine_decide(&input);
                ++comparisons;
                if (observed != expected) {
                    fprintf(stderr,
                            "FAIL: slot=%zu role=%u scope=0x%04x "
                            "expected=%d observed=%d\n",
                            slot, role, scope_values[i], expected, observed);
                    ++failures;
                    return;
                }
            }
        }
    }
}

static void test_num_rules_compatibility(void)
{
    CompactPolicy policy = { .num_rules = 1u };
    for (size_t i = 0u; i < MAX_RULES; ++i) {
        policy.rules[i] = (PolicyRule){
            INACTIVE_PATH_ID, 0u, ROLE_ADMIN, UINT16_MAX
        };
    }
    policy.rules[7] = (PolicyRule){
        PATH_STATUS, METHOD_GET, ROLE_NONE, 0u
    };
    install_policy(&policy);

    const DecisionInput input = {
        PATH_STATUS, METHOD_GET, ROLE_NONE, 0u, 0u
    };
    expect(engine_decide(&input) == DECISION_ALLOW,
           "compatibility profile must evaluate slot seven when num_rules=1");
    ++comparisons;
}

static void test_update_rollback(void)
{
    CompactPolicy policy;
    uint8_t body[POLICY_UPDATE_BODY_SIZE];
    compact_policy_init_default(&policy);
    install_policy(&policy);
    encode_policy_body(body, &policy);
    body[0] = 0u;

    const DecisionInput administrator = {
        PATH_POLICY, METHOD_PUT, ROLE_ADMIN, UINT16_MAX, 0u
    };
    expect(engine_update(&administrator, body, sizeof(body)) ==
               UPDATE_REJECTED,
           "zero-rule update must be rejected");

    const DecisionInput access = {
        PATH_STATUS, METHOD_GET, ROLE_OPERATOR, 0x0001u, 0u
    };
    expect(engine_decide(&access) == DECISION_ALLOW,
           "failed update must preserve the active policy");
}

static void test_wire_decoder(void)
{
    uint8_t frame[SECURITY_PARAMS_HEADER_SIZE] = {0};
    uint8_t max_frame[WEB_FRAME_MTU] = {0};
    SecurityParamsWire *max_wire = (SecurityParamsWire *)(void *)max_frame;
    SecurityParamsWire *wire = (SecurityParamsWire *)(void *)frame;
    const SecurityParamsWire *decoded = NULL;
    DecisionInput input = {0};

    wire->path_id = PATH_STATUS;
    wire->method = METHOD_GET;
    wire->role = ROLE_OPERATOR;
    wire->scope = 1u;
    expect(validate_security_params(frame, sizeof(frame), &decoded, &input),
           "minimal valid frame should decode");

    wire->body_len = 1u;
    expect(!validate_security_params(frame, sizeof(frame), &decoded, &input),
           "truncated body must be rejected");
    wire->body_len = 0u;
    wire->subject_id_len = SUBJECT_ID_MAX + 1u;

    max_wire->path_id = PATH_STATUS;
    max_wire->method = METHOD_GET;
    max_wire->role = ROLE_OPERATOR;
    max_wire->subject_id_len = SUBJECT_ID_MAX;
    max_wire->token_len = AUTH_TOKEN_MAX;
    max_wire->body_len = MAX_INLINE_BODY;
    expect(validate_security_params(max_frame, sizeof(max_frame),
                                    &decoded, &input),
           "maximum legal frame must decode");
    expect(!validate_security_params(frame, sizeof(frame), &decoded, &input),
           "oversized subject id must be rejected");
}

static void test_rate_role_and_scope_boundaries(void)
{
    CompactPolicy policy = { .num_rules = 1u };
    for (size_t i = 0u; i < MAX_RULES; ++i) {
        policy.rules[i] = (PolicyRule){
            INACTIVE_PATH_ID, 0u, ROLE_ADMIN, UINT16_MAX
        };
    }
    policy.rules[0] = (PolicyRule){
        PATH_STATUS, METHOD_MASK_ALL, ROLE_OPERATOR, 0u
    };
    install_policy(&policy);

    const uint8_t rates[] = { 49u, 50u, 255u };
    for (size_t i = 0u; i < sizeof(rates) / sizeof(rates[0]); ++i) {
        const DecisionInput input = {
            PATH_STATUS, METHOD_GET, ROLE_OPERATOR, 0u, rates[i]
        };
        const DecisionResult expected = reference_decide(&policy, &input);
        expect(engine_decide(&input) == expected, "rate boundary mismatch");
        ++comparisons;
    }

    for (uint8_t role = ROLE_NONE; role <= ROLE_ADMIN; ++role) {
        const DecisionInput input = {
            PATH_STATUS, METHOD_GET, role, 0u, 0u
        };
        const DecisionResult expected = reference_decide(&policy, &input);
        expect(engine_decide(&input) == expected, "role boundary mismatch");
        ++comparisons;
    }

    for (uint8_t bit = 0u; bit < 16u; ++bit) {
        policy.rules[0].required_scope = (uint16_t)(UINT16_C(1) << bit);
        install_policy(&policy);
        const DecisionInput exact = {
            PATH_STATUS, METHOD_GET, ROLE_OPERATOR,
            (uint16_t)(UINT16_C(1) << bit), 0u
        };
        const DecisionInput missing = {
            PATH_STATUS, METHOD_GET, ROLE_OPERATOR, 0u, 0u
        };
        expect(engine_decide(&exact) == reference_decide(&policy, &exact),
               "scope-bit allow mismatch");
        expect(engine_decide(&missing) == reference_decide(&policy, &missing),
               "scope-bit deny mismatch");
        comparisons += 2u;
    }

    policy.rules[0].required_scope = 0u;
    install_policy(&policy);
    const DecisionInput high_method = {
        PATH_STATUS, UINT8_C(0x40), ROLE_OPERATOR, UINT16_MAX, 0u
    };
    const DecisionInput high_role = {
        PATH_STATUS, METHOD_GET, UINT8_MAX, UINT16_MAX, 0u
    };
    expect(engine_decide(&high_method) ==
               reference_decide(&policy, &high_method),
           "raw method-bit domain mismatch");
    expect(engine_decide(&high_role) == reference_decide(&policy, &high_role),
           "raw role domain mismatch");
    comparisons += 2u;
}

static void test_update_boundaries(void)
{
    CompactPolicy policy;
    compact_policy_init_default(&policy);
    uint8_t body[POLICY_UPDATE_BODY_SIZE + 1u] = {0};
    encode_policy_body(body, &policy);
    const DecisionInput admin = {
        PATH_POLICY, METHOD_PUT, ROLE_ADMIN, UINT16_MAX, 0u
    };

    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE - 1u) ==
               UPDATE_REJECTED,
           "64-byte policy body must be rejected");
    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_APPLIED,
           "65-byte policy body must be accepted");
    expect(engine_update(&admin, body, sizeof(body)) == UPDATE_APPLIED,
           "policy body suffix must be ignored for deployed compatibility");

    body[0] = 0u;
    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "zero rules must be rejected");
    body[0] = 9u;
    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "nine rules must be rejected");
    encode_policy_body(body, &policy);
    body[1u + 4u] = UINT8_C(0x40);
    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "invalid method mask must be rejected");
    encode_policy_body(body, &policy);
    body[1u + 5u] = 3u;
    expect(engine_update(&admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "invalid minimum role must be rejected");
    encode_policy_body(body, &policy);
    DecisionInput non_admin = admin;
    non_admin.role = ROLE_OPERATOR;
    expect(engine_update(&non_admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "non-admin policy update must be rejected");
    DecisionInput limited_admin = admin;
    limited_admin.rate_count = MAX_RATE;
    expect(engine_update(&limited_admin, body, POLICY_UPDATE_BODY_SIZE) ==
               UPDATE_REJECTED,
           "rate-limited policy update must be rejected");

    const DecisionInput access = {
        PATH_STATUS, METHOD_GET, ROLE_OPERATOR, UINT16_C(1), 0u
    };
    expect(engine_decide(&access) == DECISION_ALLOW,
           "failed updates must preserve the last valid policy");
}

static void test_deterministic_randomized(void)
{
    const uint32_t seed = random_state;
    for (size_t policy_index = 0u; policy_index < 128u; ++policy_index) {
        CompactPolicy policy = {
            .num_rules = (uint8_t)(1u + next_random() % MAX_RULES)
        };
        for (size_t slot = 0u; slot < MAX_RULES; ++slot) {
            policy.rules[slot] = (PolicyRule){
                .path_id = next_random(),
                .method = (uint8_t)(next_random() & METHOD_MASK_ALL),
                .min_role = (uint8_t)(next_random() % 3u),
                .required_scope = (uint16_t)next_random(),
            };
        }
        install_policy(&policy);

        for (size_t request_index = 0u; request_index < 64u;
             ++request_index) {
            const size_t selected = next_random() % MAX_RULES;
            DecisionInput input = {
                .path_id = (next_random() & 1u)
                    ? policy.rules[selected].path_id : next_random(),
                .method = (uint8_t)(next_random() & METHOD_MASK_ALL),
                .role = (uint8_t)(next_random() % 3u),
                .scope = (uint16_t)next_random(),
                .rate_count = (uint8_t)(next_random() % 52u),
            };
            const DecisionResult expected = reference_decide(&policy, &input);
            const DecisionResult observed = engine_decide(&input);
            ++comparisons;
            if (expected != observed) {
                fprintf(stderr,
                        "FAIL: randomized seed=0x%08x policy=%zu request=%zu "
                        "expected=%d observed=%d\n",
                        seed, policy_index, request_index,
                        expected, observed);
                ++failures;
                return;
            }
        }
    }
}

int main(void)
{
    expect(engine_init() == 0, "EverParse engine should initialize");
    test_default_scenarios();
    test_policy_readback();
    test_method_masks();
    test_role_scope_and_slot_positions();
    test_num_rules_compatibility();
    test_update_rollback();
    test_wire_decoder();
    test_rate_role_and_scope_boundaries();
    test_update_boundaries();
    test_deterministic_randomized();

    if (failures != 0) {
        fprintf(stderr, "EQUIVALENCE_FAIL,comparisons=%llu,failures=%d\n",
                (unsigned long long)comparisons, failures);
        return 1;
    }
    printf("EQUIVALENCE_OK,engine=%s,comparisons=%llu\n",
           engine_name(), (unsigned long long)comparisons);
    return 0;
}
