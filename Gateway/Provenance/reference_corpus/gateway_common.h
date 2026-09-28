/*
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef CEDAR_GATEWAY_COMMON_H
#define CEDAR_GATEWAY_COMMON_H

#include "gateway_abi.h"

void compact_policy_init_default(CompactPolicy *policy);

DecisionResult reference_decide(const CompactPolicy *policy,
                                const DecisionInput *input);

bool validate_security_params(const uint8_t *frame, uint32_t frame_len,
                              const SecurityParamsWire **wire,
                              DecisionInput *input);

bool validate_policy_update_fields(const DecisionInput *input,
                                   const uint8_t *body, uint32_t body_len,
                                   CompactPolicy *candidate);

int pipeline_process_frame(const uint8_t *frame, uint32_t frame_len,
                           PipelineOutput *output);

void write_u16_le(uint8_t *buffer, size_t offset, uint16_t value);
void write_u32_le(uint8_t *buffer, size_t offset, uint32_t value);
uint16_t read_u16_le(const uint8_t *buffer, size_t offset);
uint32_t read_u32_le(const uint8_t *buffer, size_t offset);

#endif
