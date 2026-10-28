/* This translation unit includes only the extractor's generated runtime. */
#include "gateway_core.h"
#include "HTTP_Extract_Complete.h"
#include "IPC_Extract.h"
#include "gateway_glue.h"
#include <string.h>

GatewayResult gateway_extract(GatewayContext *c)
{
    if (!c) return GATEWAY_REJECTED;
    c->security_len = c->app_len = c->gate_len = 0;
    c->result = GATEWAY_REJECTED;
    c->extraction_code = EXTRACT_MALFORMED;
    memset(c->security, 0, sizeof(c->security));
    memset(c->auth, 0, sizeof(c->auth));
    if (!gateway_guards_ok(c) || c->request_len > sizeof(c->request)) return c->result;
    c->extraction_code = extract_security_params(c->request, c->request_len,
                                                 c->security, &c->security_len);
    if (c->extraction_code == EXTRACT_OK && gateway_guards_ok(c) &&
        c->security_len >= SECPARAMS_HEADER_SIZE && c->security_len <= sizeof(c->security))
        c->result = GATEWAY_EXTRACTED;
    else c->security_len = 0;
    return c->result;
}

GatewayResult gateway_set_identity(GatewayContext *c, const GatewayIdentity *id, uint8_t rate)
{
    if (!c) return GATEWAY_REJECTED;
    GatewayResult previous = c->result;
    c->result = GATEWAY_REJECTED;
    c->app_len = c->gate_len = 0;
    /* Never leave a stale role/scope/subject or rate after a failed identity. */
    memset(c->security + 6, 0, 36);
    c->security[0] = 0;
    memset(c->auth, 0, sizeof(c->auth));
    if (!gateway_guards_ok(c) || (previous != GATEWAY_EXTRACTED && previous != GATEWAY_IDENTIFIED) ||
        c->security_len < SECPARAMS_HEADER_SIZE || c->security_len > sizeof(c->security) ||
        !id || !id->valid || id->role > ROLE_ADMIN || id->subject_len > SUBJECT_ID_MAX)
        return c->result;
    /* Place role/scope/subject (bytes 6-41) and rate (byte 0) through the
     * verified front code. The role<=ROLE_ADMIN and subject_len<=32 checks above
     * are kept (finding c: the old populate_auth_fields clamped an out-of-range
     * role to admin; here such a role is already rejected). id->subject is a
     * 32-byte zero-padded buffer; GlueFrontSetIdentity copies subject_len of it
     * and zero-fills the rest. */
    gateway_glue_set_identity(c->security, rate, id->role, id->scope,
                              id->subject_len, (uint8_t *)id->subject);
    c->result = GATEWAY_IDENTIFIED;
    return c->result;
}
