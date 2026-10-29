/* Handwritten bounded HTTP transport adapter; not covered by generated proofs. */
#include "gateway_http.h"
#include "gateway_login.h"
#ifdef STM32F767xx
#include "gateway_d1_auth.h"
#endif
#include "gateway_clear.h"
#include "gateway_routes.h"
#include "gateway_glue.h"
#include "gateway_mediation.h"
#include "paper_runtime53.h"
#include <string.h>
#include <stdio.h>

static unsigned lower(unsigned c) { return c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c; }
static int equal(const uint8_t *p, size_t n, const char *s)
{
    if (n != strlen(s)) return 0;
    for (size_t i=0; i<n; ++i) if (lower(p[i]) != lower((unsigned char)s[i])) return 0;
    return 1;
}
static bool token_char(unsigned c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || strchr("-.\x5f~+/", (int)c) != NULL;
}
static bool field_char(unsigned c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || (c && strchr("!#$%&'*+-.^_`|~", (int)c));
}
static int append(GatewayContext *c, const void *p, size_t n)
{
    if (n > sizeof(c->request) - c->request_len) return 0;
    memcpy(c->request + c->request_len, p, n); c->request_len += (uint32_t)n; return 1;
}
static int headers(GatewayHttp *h, GatewayContext *c)
{
    const uint8_t *p=h->raw; size_t end=h->header_end, e=0;
    while (e+1<end && !(p[e]=='\r' && p[e+1]=='\n')) ++e;
    size_t a=0; while(a<e && p[a]!=' ') ++a;
    size_t b=a+1; while(b<e && p[b]!=' ') ++b;
    if (a==0 || b<=a+1 || b>=e || p[a+1]!='/') return 400;
    bool get=a==3 && !memcmp(p,"GET",3);
    bool post=a==4 && !memcmp(p,"POST",4);
    bool put=a==3 && !memcmp(p,"PUT",3);
    if (!get && !post && !put) return 400;
    /* Match the reference extractor: '?' ends the authorization path, while
     * '#' is an ordinary path byte and therefore never aliases a known path. */
    for(size_t i=a+1;i<b;++i)
        if(p[i]<=32 || p[i]>=127) return 400;
    size_t path_end=a+1;
    while(path_end<b && p[path_end]!='?') ++path_end;
    size_t path_len=path_end-(a+1);
    bool v11=e-b-1==8 && !memcmp(p+b+1,"HTTP/1.1",8);
    if (!v11 && !(e-b-1==8 && !memcmp(p+b+1,"HTTP/1.0",8))) return 400;
    h->dashboard=get && path_len==1 && p[a+1]=='/';
    h->script=get && path_len==13 && !memcmp(p+a+1,"/dashboard.js",13);
    h->demo=path_len==5 && !memcmp(p+a+1,"/demo",5);
    if(h->demo && !get) return 400;
    c->request_len=0;
    /* The verified extractor retains its original fixed route set. This exact,
     * bounded alias lets it extract headers/body; the distinct route ID below
     * is supplied by handwritten integration, never by a client attribute. */
    if(h->demo) {
        if(!append(c,"GET /api/status",15) ||
           !append(c,p+path_end,b-path_end) || !append(c,p+b,e+2-b)) return 413;
    } else if(!append(c,p,e+2)) return 413;
    size_t pos=e+2; unsigned auth=0, content=0, host=0;
    while(pos+2<end) {
        e=pos; while(e+1<end && !(p[e]=='\r' && p[e+1]=='\n')) ++e;
        size_t colon=pos; while(colon<e && p[colon]!=':') {
            if(!field_char(p[colon])) return 400;
            ++colon;
        }
        if(colon==pos || colon==e) return 400;
        size_t v=colon+1, ve=e;
        while(v<ve && (p[v]==' ' || p[v]=='\t')) ++v;
        while(ve>v && (p[ve-1]==' ' || p[ve-1]=='\t')) --ve;
        for(size_t i=v;i<ve;++i) if((p[i]<32 && p[i]!='\t') || p[i]==127) return 400;
        if(equal(p+pos,colon-pos,"content-length")) {
            if(content++ || v==ve) return 400;
            uint32_t n=0;
            for(size_t i=v;i<ve;++i) {
                if(p[i]<'0' || p[i]>'9') return 400;
                if(n > (MAX_INLINE_BODY-(p[i]-'0'))/10U) return 413;
                n=n*10U+(p[i]-'0');
            }
            h->body_len=n;
            char digits[10]; size_t d=0;
            do { digits[d++]=(char)('0'+n%10U); n/=10U; } while(n);
            if(!append(c,"Content-Length: ",16)) return 413;
            while(d) if(!append(c,&digits[--d],1)) return 413;
            if(!append(c,"\r\n",2)) return 413;
        } else if(equal(p+pos,colon-pos,"authorization")) {
            if(auth++) return 400;
            size_t sp=v; while(sp<ve && p[sp]!=' ') ++sp;
            if(!equal(p+v,sp-v,"bearer")) return 401;
            while(sp<ve && p[sp]==' ') ++sp;
            if(sp==ve || ve-sp>AUTH_TOKEN_MAX) return 401;
            bool padding=false;
            for(size_t i=sp;i<ve;++i) {
                if(p[i]=='=') padding=true;
                else if(padding || !token_char(p[i])) return 400;
            }
            if(!append(c,"Authorization: Bearer ",22) || !append(c,p+sp,ve-sp) || !append(c,"\r\n",2)) return 413;
        } else {
            if(equal(p+pos,colon-pos,"transfer-encoding")) return 400;
            if(equal(p+pos,colon-pos,"expect")) return 417;
            if(equal(p+pos,colon-pos,"host") && (host++ || v==ve)) return 400;
            if(!append(c,p+pos,e-pos+2)) return 413;
        }
        pos=e+2;
    }
    if(v11 && host!=1) return 400;
    if((post || put) && !content) return 400;
    if(get && h->body_len) return 400;
    if(!append(c,"\r\n",2) || h->body_len > sizeof(c->request)-c->request_len ||
        h->header_end+h->body_len>sizeof(h->raw)) return 413;
    h->canonical_header=c->request_len;
    return 0;
}
void gateway_http_init(GatewayHttp *h) { memset(h,0,sizeof(*h)); }
int gateway_http_feed(GatewayHttp *h, GatewayContext *c, const void *data, size_t n)
{
    if(h->status) return h->status;
    if(n>sizeof(h->raw)-h->used) return h->status=413;
    uint32_t old=h->used;
    if(n) memcpy(h->raw+h->used,data,n);
    h->used+=(uint32_t)n;
    if(!h->header_end) {
        uint32_t i=old>3?old-3:0;
        for(;i+3<h->used;++i) if(!memcmp(h->raw+i,"\r\n\r\n",4)) { h->header_end=i+4; break; }
        if(!h->header_end) return h->status=h->used==sizeof(h->raw)?413:0;
        h->status=headers(h,c);
        if(h->status) return h->status;
    }
    uint32_t expected=h->header_end+h->body_len;
    if(h->used>expected) return h->status=400;
    if(h->used<expected) return 0;
    if(!append(c,h->raw+h->header_end,h->body_len)) return h->status=413;
    return h->status=1;
}
bool gateway_bearer_check(const uint8_t *token,size_t n,GatewayIdentity *id)
{
    memset(id,0,sizeof(*id));
#ifdef STM32F767xx
    return gateway_d1_auth_identify(token,n,id);
#else
#if GATEWAY_LAB_AUTH
    /* Lab fixtures carry no rate: the request rate is the verified windowed
     * counter (byte 0), set downstream in gateway_set_identity. */
    static const struct { const char *token,*subject; uint8_t role; uint16_t scope; } rows[]={
        {"pg-lab-operator","lab-operator",ROLE_OPERATOR,1},
        {"pg-lab-admin","lab-admin",ROLE_ADMIN,7}};
    for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);++i) {
        if(n!=strlen(rows[i].token)) continue;
        unsigned diff=0; for(size_t j=0;j<n;++j) diff|=token[j]^(uint8_t)rows[i].token[j];
        if(diff) continue;
        id->valid=true; id->role=rows[i].role; id->scope=rows[i].scope;
        id->subject_len=(uint8_t)strlen(rows[i].subject); memcpy(id->subject,rows[i].subject,id->subject_len);
        return true;
    }
#else
    (void)token; (void)n;
#endif
    return gateway_login_validate(token,n,id);
#endif
}
/* /api/policy partition selector: "?part=J" in the request-line query (J decimal,
 * 1-based). Returns 0 and sets *part (default 1 when absent), or -1 for a malformed
 * or duplicated selector. Other query parameters are ignored (same resource). The
 * range 1 <= J <= N is NOT checked here: the verified GlueLowMediate update branch
 * rejects an out-of-range J, and the readback range-checks in the adapter. */
static int gateway_parse_part(const GatewayContext *c, uint32_t *part)
{
    const uint8_t *r=c->request; uint32_t n=c->request_len, i=0;
    *part=1U;
    while(i<n && r[i]!=' ') ++i;                       /* method */
    ++i;
    while(i<n && r[i]!=' ' && r[i]!='?' && r[i]!='\r') ++i;   /* path */
    if(i>=n || r[i]!='?') return 0;
    ++i;
    unsigned seen=0;
    while(i<n && r[i]!=' ' && r[i]!='\r') {
        uint32_t s=i;
        while(i<n && r[i]!='&' && r[i]!=' ' && r[i]!='\r') ++i;
        if(i-s>=5U && memcmp(r+s,"part=",5)==0) {
            if(++seen>1U) return -1;
            uint32_t d=s+5U, v=0;
            if(d==i || i-d>9U) return -1;              /* empty or too long (>9 digits) */
            for(;d<i;++d) { if(r[d]<'0' || r[d]>'9') return -1; v=v*10U+(uint32_t)(r[d]-'0'); }
            *part=v;
        } else if(i-s==4U && memcmp(r+s,"part",4)==0) return -1;   /* "part" with no value */
        if(i<n && r[i]=='&') ++i;
    }
    return 0;
}
int gateway_http_process(GatewayHttp *h,GatewayContext *c)
{
    if(h->status!=1) return h->status?h->status:400;
    h->status=400; /* Consume transport authorization exactly once. */
    gateway_glue_set_part(1U);   /* request-scoped; reset here (GATE context), not in begin_request (NET) */
    if(h->dashboard || h->script) {
        SecurityParamsWire *public_request=(SecurityParamsWire *)c->security;
        memset(c->security,0,sizeof(c->security));
        public_request->path_hash=h->script?GATEWAY_PATH_SCRIPT:GATEWAY_PATH_DASHBOARD;
        public_request->method=METHOD_GET;
        c->security_len=SECPARAMS_HEADER_SIZE; c->result=GATEWAY_EXTRACTED;
        return gateway_mediate(c,GATEWAY_PUBLIC);
    }
#if GATEWAY_PAPER_RUNTIME53
    /* Labelled variant: the /gate53 diagnostic endpoint is handled before the
     * verified extractor (it carries raw rule paths the extractor does not know). */
    { int handled=0; int st=gateway_runtime53_endpoint(h,c,&handled);
      if(handled){ gateway_clear(h->raw,sizeof(h->raw)); return st; } }
#endif
    if(gateway_extract(c)!=GATEWAY_EXTRACTED) return 400;
    SecurityParamsWire *p=(SecurityParamsWire *)c->security;
    if(h->demo) p->path_hash=GATEWAY_PATH_DEMO;
    if(p->path_hash==PATH_LOGIN && p->method==METHOD_POST) {
        int status=gateway_mediate(c,GATEWAY_LOGIN);
        gateway_clear(c->request,sizeof(c->request));
        gateway_clear(c->security,sizeof(c->security));
        gateway_clear(h->raw,sizeof(h->raw));
        return status;
    }
    GatewayIdentity identity; uint32_t part=1U;
    if(!gateway_bearer_check(p->token,p->token_len,&identity)) return 401;
    if(p->path_hash==PATH_POLICY && p->method==METHOD_GET && identity.role!=ROLE_ADMIN) return 403;
    if(p->path_hash==PATH_POLICY && gateway_parse_part(c,&part)!=0) return 400;
    gateway_glue_set_part(part);
    if(gateway_set_identity(c,&identity,gateway_tick_ms())!=GATEWAY_IDENTIFIED) return 500;
    return gateway_mediate(c,p->path_hash==PATH_POLICY && p->method==METHOD_PUT?
                           GATEWAY_UPDATE:GATEWAY_ACCESS);
}
int gateway_http_typed_header(char *out,size_t cap,int status,size_t n,const char *type)
{
    const char *reason="Internal Server Error";
    switch(status) {
    case 200:reason="OK";break; case 400:reason="Bad Request";break;
    case 401:reason="Unauthorized";break; case 403:reason="Forbidden";break;
    case 404:reason="Not Found";break; case 408:reason="Request Timeout";break;
    case 413:reason="Content Too Large";break; case 417:reason="Expectation Failed";break;
    case 429:reason="Too Many Requests";break;
    }
    int z=snprintf(out,cap,"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n%s\r\n",status,reason,type,(unsigned long)n,
        status==401?"WWW-Authenticate: Bearer realm=\"policy_gate\"\r\n":"");
    return z>=0 && (size_t)z<cap?z:-1;
}

int gateway_http_response_header(char *out,size_t cap,int status,size_t n)
{
    return gateway_http_typed_header(out,cap,status,n,"application/json");
}
int gateway_http_html_header(char *out,size_t cap,size_t n)
{
    return gateway_http_typed_header(out,cap,200,n,"text/html; charset=utf-8");
}
