#ifndef GATEWAY_AUDIT_H
#define GATEWAY_AUDIT_H
#include <stdbool.h>
#include <stdint.h>
#include "gateway_core.h"

/* Research observation only. This state is trusted C outside the Low* model.
 * The gateway task owns an active record from begin through finish. */
typedef struct {
    uint32_t request_id;
    uint32_t acceptances;
    uint32_t effects;
    uint32_t violations;
} GatewayAuditRecord;

void gateway_audit_begin(GatewayContext *context);
void gateway_audit_accept(uint8_t kind, uint32_t length,
                          const uint8_t request[1536], const uint8_t policy[65],
                          const uint8_t login[106]);
void gateway_audit_effect(uint8_t kind, uint32_t length,
                          const uint8_t request[1536], const uint8_t policy[65],
                          const uint8_t login[106], const GatewayContext *context);
GatewayAuditRecord gateway_audit_finish(void);

#endif
