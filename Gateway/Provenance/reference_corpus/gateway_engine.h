/*
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef CEDAR_GATEWAY_ENGINE_H
#define CEDAR_GATEWAY_ENGINE_H

#include "gateway_abi.h"

int engine_init(void);
DecisionResult engine_decide(const DecisionInput *input);
UpdateResult engine_update(const DecisionInput *input,
                           const uint8_t *body, uint32_t body_len);
int engine_get_policy(CompactPolicy *policy);
const char *engine_name(void);

#if defined(GATEWAY_TIMING_BENCHMARK) && GATEWAY_TIMING_BENCHMARK
/* Benchmark-only policy installation; never part of the production ABI. */
int engine_benchmark_configure(void);
int engine_benchmark_restore(void);
#endif

#endif
