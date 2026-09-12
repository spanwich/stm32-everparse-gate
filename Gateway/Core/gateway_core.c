#include "gateway_core.h"
#include "gateway_routes.h"
#include <string.h>
#include <stdio.h>

_Static_assert(sizeof(SecurityParamsWire) == SECPARAMS_HEADER_SIZE, "wire header");
_Static_assert(sizeof(AppRequest) == APP_REQUEST_HEADER_SIZE, "application header");
_Static_assert(APP_REQUEST_HEADER_SIZE + MAX_INLINE_BODY <= GATEWAY_WIRE_CAPACITY,
               "application request capacity");

bool gateway_guards_ok(const GatewayContext *c)
{
    return c && c->guard_start == GATEWAY_GUARD && c->guard_request == GATEWAY_GUARD
        && c->guard_security == GATEWAY_GUARD && c->guard_auth == GATEWAY_GUARD
        && c->guard_app == GATEWAY_GUARD && c->guard_gate == GATEWAY_GUARD;
}

void gateway_begin_request(GatewayContext *c)
{
    memset(c->request, 0, sizeof(c->request));
    memset(c->security, 0, sizeof(c->security));
    memset(c->auth, 0, sizeof(c->auth));
    memset(c->app, 0, sizeof(c->app));
    memset(c->gate, 0, sizeof(c->gate));
    c->request_len = c->security_len = c->app_len = c->gate_len = 0;
    c->extraction_code = EXTRACT_INCOMPLETE;
    c->result = GATEWAY_IDLE;
}

void gateway_init(GatewayContext *c)
{
    memset(c, 0, sizeof(*c));
    c->guard_start = c->guard_request = c->guard_security = GATEWAY_GUARD;
    c->guard_auth = c->guard_app = c->guard_gate = GATEWAY_GUARD;
    gateway_begin_request(c);
    policy_init_default(&c->policy);
}

static GatewayResult reject(GatewayContext *c)
{
    c->app_len = c->gate_len = 0;
    c->result = GATEWAY_REJECTED;
    return c->result;
}

GatewayResult gateway_evaluate(GatewayContext *c)
{
    if (!c) return GATEWAY_REJECTED;
    c->app_len = c->gate_len = 0;
    if (!gateway_guards_ok(c) || c->result != GATEWAY_IDENTIFIED ||
        c->security_len < SECPARAMS_HEADER_SIZE || c->security_len > sizeof(c->security))
        return reject(c);
    const SecurityParamsWire *p = (const SecurityParamsWire *)c->security;
    if (p->body_len > MAX_INLINE_BODY ||
        c->security_len != SECPARAMS_HEADER_SIZE + p->body_len ||
        p->subject_id_len > SUBJECT_ID_MAX || p->token_len > AUTH_TOKEN_MAX ||
        p->role > ROLE_ADMIN || p->method < METHOD_GET || p->method > METHOD_PUT ||
        c->policy.num_rules == 0 || c->policy.num_rules > MAX_RULES)
        return reject(c);
    for (unsigned i = 0; i < MAX_RULES; ++i)
        if (c->policy.rules[i].method > METHOD_PUT || c->policy.rules[i].min_role > ROLE_ADMIN)
            return reject(c);
    /* Transactional update: an error or denial cannot mutate the live policy. */
    Policy candidate = c->policy;
    int r = pipeline_process(&candidate, p, c->gate, &c->gate_len, c->app, &c->app_len);
    if (!gateway_guards_ok(c) || c->app_len > sizeof(c->app) || c->gate_len > sizeof(c->gate))
        return reject(c);
    if (r == PIPELINE_FORWARD) c->result = GATEWAY_FORWARD;
    else if (r == PIPELINE_DENY) c->result = GATEWAY_DENIED;
    else if (r == PIPELINE_POLICY) {
        c->policy = candidate;
        c->result = GATEWAY_POLICY_UPDATED;
    } else return reject(c);
    return c->result;
}

bool gateway_dispatch(GatewayContext *c)
{
    if (!c || c->result != GATEWAY_FORWARD) return false;
    if (!gateway_guards_ok(c) || c->app_len < APP_REQUEST_HEADER_SIZE || c->app_len > sizeof(c->app)) {
        reject(c); return false;
    }
    const AppRequest *req = (const AppRequest *)c->app;
    if (req->body_len > MAX_INLINE_BODY || c->app_len != APP_REQUEST_HEADER_SIZE + req->body_len) {
        reject(c); return false;
    }
    /* Port of the reference ProtectedApp's response behavior, reached only here. */
    GateResponse *resp = (GateResponse *)c->gate;
    char *body = (char *)resp->body;
    size_t capacity = sizeof(c->gate) - GATE_RESPONSE_HEADER_SIZE;
    int n;
    if (req->path_hash == PATH_STATUS && req->method == METHOD_GET)
        n = snprintf(body, capacity, "{\"status\":\"ok\",\"role\":\"%s\"}", role_name(req->role));
    else if (req->path_hash == GATEWAY_PATH_DEMO && req->method == METHOD_GET)
        n = snprintf(body, capacity, "Policy gate demo: access allowed.\n");
    else if (req->path_hash == PATH_POLICY && req->method == METHOD_GET) {
        n = snprintf(body, capacity, "{\"status\":\"ok\",\"message\":\"policy read ok\",\"rules\":[");
        for(unsigned i=0;i<c->policy.num_rules;++i) {
            if(n<0 || (size_t)n>=capacity) { reject(c); return false; }
            const PolicyRule *r=&c->policy.rules[i];
            int z=snprintf(body+n,capacity-(size_t)n,"%s{\"id\":%lu,\"method\":%u,\"min_role\":%u,\"scope\":%u}",
                i?",":"",(unsigned long)r->path_hash,r->method,r->min_role,r->req_scope);
            if(z<0 || (size_t)z>=capacity-(size_t)n) { reject(c); return false; }
            n+=z;
        }
        if(n<0 || (size_t)n>=capacity) { reject(c); return false; }
        int z=snprintf(body+n,capacity-(size_t)n,"]}");
        if(z<0 || (size_t)z>=capacity-(size_t)n) { reject(c); return false; }
        n+=z;
    }
    else n = snprintf(body, capacity, "{\"status\":\"ok\"}");
    if (n < 0 || (size_t)n >= capacity) { reject(c); return false; }
    resp->conn_id = 0;
    resp->status = GATE_STATUS_OK;
    resp->body_len = (uint32_t)n;
    c->gate_len = GATE_RESPONSE_HEADER_SIZE + (uint32_t)n;
    c->dispatch_count++;
    c->result = GATEWAY_DISPATCHED;
    return true;
}
