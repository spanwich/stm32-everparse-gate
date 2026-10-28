#ifndef GATEWAY_PAPER_RUNTIME53_H
#define GATEWAY_PAPER_RUNTIME53_H
/* Runtime-loaded 53-partition policy (labelled variant GATEWAY_PAPER_RUNTIME53).
 * See Gateway/Paper/paper_runtime53.c. All entry points are no-ops unless the
 * flag is set. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_RUNTIME53
#include "gateway_core.h"
#include "gateway_http.h"
#include "FreeRTOS.h"
#include "task.h"

/* Privileged one-time init: deny-all live store + enable DWT. Called from
 * gateway_r4_boundary_start (privileged) before the GATE task serves requests. */
void gateway_runtime53_init(void);

/* Privileged: create the DWT-timing worker task and its two queues, and grant
 * the GATE task access to them. Called from gateway_r4_boundary_start after the
 * GATE task is created. */
void gateway_runtime53_start(TaskHandle_t gate);

/* Handle a labelled /gate53 request in the GATE task. Sets *handled=1 and
 * returns the HTTP status (writing a GateResponse into c->gate) when the request
 * is for /gate53; otherwise sets *handled=0 and returns 0. */
int gateway_runtime53_endpoint(const GatewayHttp *h, GatewayContext *c, int *handled);
#endif
#endif
