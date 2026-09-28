/*
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gateway_common.h"

void write_u16_le(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1u] = (uint8_t)(value >> 8);
}

void write_u32_le(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1u] = (uint8_t)(value >> 8);
    buffer[offset + 2u] = (uint8_t)(value >> 16);
    buffer[offset + 3u] = (uint8_t)(value >> 24);
}

uint16_t read_u16_le(const uint8_t *buffer, size_t offset)
{
    return (uint16_t)buffer[offset] |
           ((uint16_t)buffer[offset + 1u] << 8);
}

uint32_t read_u32_le(const uint8_t *buffer, size_t offset)
{
    return (uint32_t)buffer[offset] |
           ((uint32_t)buffer[offset + 1u] << 8) |
           ((uint32_t)buffer[offset + 2u] << 16) |
           ((uint32_t)buffer[offset + 3u] << 24);
}

bool validate_security_params(const uint8_t *frame, uint32_t frame_len,
                              const SecurityParamsWire **wire,
                              DecisionInput *input)
{
    if (frame == NULL || wire == NULL || input == NULL ||
        frame_len < SECURITY_PARAMS_HEADER_SIZE ||
        frame_len > WEB_FRAME_MTU) {
        return false;
    }

    const SecurityParamsWire *candidate =
        (const SecurityParamsWire *)(const void *)frame;
    if (candidate->subject_id_len > SUBJECT_ID_MAX ||
        candidate->token_len > AUTH_TOKEN_MAX ||
        candidate->body_len > MAX_INLINE_BODY ||
        SECURITY_PARAMS_HEADER_SIZE + candidate->body_len != frame_len ||
        candidate->role > ROLE_ADMIN ||
        candidate->method > METHOD_MASK_ALL) {
        return false;
    }

    input->path_id = candidate->path_id;
    input->method = candidate->method;
    input->role = candidate->role;
    input->scope = candidate->scope;
    input->rate_count = candidate->rate_count;
    *wire = candidate;
    return true;
}
