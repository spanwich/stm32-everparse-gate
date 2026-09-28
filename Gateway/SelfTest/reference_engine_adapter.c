/* Board/host diagnostic adapter to the MCU-linked reference validator.
 * This is separate from the production HTTP path and accepts raw method masks
 * and synthetic identities so the paper's exact corpus can run unchanged. */
#define write_u16_le paper_write_u16_le
#define write_u32_le paper_write_u32_le
#define read_u16_le paper_read_u16_le
#define read_u32_le paper_read_u32_le
#include "../Provenance/reference_corpus/gateway_common.h"
#include "../Provenance/reference_corpus/gateway_engine.h"
#include "../Generated/Policy/RbacPolicyWrapper.h"
#include <string.h>

extern bool gateway_mediation_check(uint8_t kind, uint8_t *bytes, uint32_t length);
static CompactPolicy active_policy;
static bool initialized;

static void encode_rules(uint8_t *out, size_t offset, const CompactPolicy *policy)
{
    for (size_t i = 0; i < MAX_RULES; ++i) {
        const PolicyRule *rule = &policy->rules[i];
        size_t pos = offset + i * POLICY_RULE_SIZE;
        write_u32_le(out, pos, rule->path_id);
        out[pos + 4] = rule->method;
        out[pos + 5] = rule->min_role;
        write_u16_le(out, pos + 6, rule->required_scope);
    }
}

int engine_init(void)
{
    compact_policy_init_default(&active_policy);
    initialized = true;
    return 0;
}

DecisionResult engine_decide(const DecisionInput *input)
{
    if (!initialized || !input) return DECISION_INTERNAL_ERROR;
    if (input->rate_count >= MAX_RATE) return DECISION_RATE_LIMITED;
    uint8_t bytes[ACCESS_REQUEST_SIZE] = {0};
    bytes[0] = input->role;
    bytes[1] = input->rate_count;
    write_u16_le(bytes, 2, input->scope);
    encode_rules(bytes, 4, &active_policy);
    write_u32_le(bytes, 68, input->path_id);
    bytes[72] = input->method;
    return gateway_mediation_check(2, bytes, sizeof(bytes)) ? DECISION_ALLOW : DECISION_DENY;
}

UpdateResult engine_update(const DecisionInput *input, const uint8_t *body, uint32_t body_len)
{
    if (!initialized || !input || !body || body_len < POLICY_UPDATE_BODY_SIZE)
        return UPDATE_REJECTED;
    uint8_t bytes[70] = {0};
    CompactPolicy candidate;
    bytes[0] = input->role;
    bytes[1] = input->rate_count;
    memcpy(bytes + 2, body, POLICY_UPDATE_BODY_SIZE);
    if (!gateway_mediation_check(3, bytes, sizeof(bytes)) ||
        !validate_policy_update_fields(input, body, body_len, &candidate))
        return UPDATE_REJECTED;
    active_policy = candidate;
    return UPDATE_APPLIED;
}

int engine_get_policy(CompactPolicy *policy)
{
    if (!initialized || !policy) return -1;
    *policy = active_policy;
    return 0;
}

const char *engine_name(void) { return "stm32-linked-everparse"; }
