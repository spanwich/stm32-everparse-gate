#ifndef GATEWAY_R4_BOUNDARY_H
#define GATEWAY_R4_BOUNDARY_H
#include "gateway_http.h"
#include "gateway_audit.h"

typedef struct {
    int status;
    uint32_t gate_len;
    uint8_t gate[GATEWAY_WIRE_CAPACITY];
    GatewayAuditRecord audit;
    bool dashboard, script, demo;
} GatewayR4Reply;

void gateway_r4_boundary_start(void);
void gateway_r4_network_drop_privilege(void);
const GatewayR4Reply *gateway_r4_submit(const GatewayHttp *assembled);
bool gateway_r4_app_dispatch(GatewayContext *gate);
void gateway_r4_fault_before_validator(uint8_t *validator_input);
#endif
