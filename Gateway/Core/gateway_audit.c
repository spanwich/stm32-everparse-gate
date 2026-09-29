/* M4/M5 instrumented-image observation. No heap, callbacks or retained input
 * pointers. A mismatch is counted, not suppressed, so tests can see failures. */
#include "gateway_audit.h"
#include "gateway_clear.h"
#include <string.h>

static struct {
    GatewayAuditRecord record;
    GatewayContext *context;
    uint8_t request[1536];
    uint8_t policy[65];
    uint8_t login[106];
    uint8_t kind;
    uint32_t length;
    bool active;
} audit __attribute__((section(".gateway_gate")));
static uint32_t next_request_id __attribute__((section(".gateway_gate")));

void gateway_audit_begin(GatewayContext *context)
{
    audit.record=(GatewayAuditRecord){.request_id=++next_request_id};
    audit.context=context;
    audit.active=true;
}

void gateway_audit_accept(uint8_t kind, uint32_t length,
                          const uint8_t request[1536], const uint8_t policy[65],
                          const uint8_t login[106])
{
    if (!audit.active) return;
    if (++audit.record.acceptances!=1) ++audit.record.violations;
    audit.kind=kind; audit.length=length;
    memcpy(audit.request,request,sizeof(audit.request));
    memcpy(audit.policy,policy,sizeof(audit.policy));
    memcpy(audit.login,login,sizeof(audit.login));
}

void gateway_audit_effect(uint8_t kind, uint32_t length,
                          const uint8_t request[1536], const uint8_t policy[65],
                          const uint8_t login[106], const GatewayContext *context)
{
    if (!audit.active) return;
    if (++audit.record.effects!=1 || audit.record.acceptances!=1 ||
        context!=audit.context || kind!=audit.kind || length!=audit.length ||
        memcmp(request,audit.request,sizeof(audit.request)) ||
        memcmp(policy,audit.policy,sizeof(audit.policy)) ||
        memcmp(login,audit.login,sizeof(audit.login)))
        ++audit.record.violations;
}

GatewayAuditRecord gateway_audit_finish(void)
{
    GatewayAuditRecord result=audit.record;
    if (result.effects>result.acceptances) ++result.violations;
    audit.active=false;
    audit.context=NULL;
    gateway_clear(audit.request,sizeof(audit.request));
    gateway_clear(audit.policy,sizeof(audit.policy));
    gateway_clear(audit.login,sizeof(audit.login));
    return result;
}
