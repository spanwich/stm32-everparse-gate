#include "gateway_http.h"
#include "gateway_login.h"
#include "gateway_glue.h"
#include "gateway_tests.h"
#include "credential_store.h"
#include <stdio.h>
#include <string.h>
extern GatewayContext gateway_test_context;
extern GatewayHttp gateway_http_fixture;
static char request[2048];
/* Independent Python hmac.sha256 known-answer vector for the reference lab key. */
static const char admin_token[]="61646d696e-02-3f00-5db8d1206eb47ee2ebe4c72ad85a259243334f15181f8d3f11b21c4a98f95232";
static int call(const char *method,const char *path,const char *token,const char *body)
{
    GatewayContext *c=&gateway_test_context; GatewayHttp *h=&gateway_http_fixture;
    gateway_init(c); gateway_http_init(h);
    gateway_policy_store_load(&c->policy);   /* decision reads the live store; start from the default */
    int n=snprintf(request,sizeof(request),"%s %s HTTP/1.1\r\nHost: board\r\n%s%s%sContent-Length: %lu\r\n\r\n%s",
        method,path,token?"Authorization: Bearer ":"",token?token:"",token?"\r\n":"",
        (unsigned long)strlen(body),body);
    if(n<0 || (size_t)n>=sizeof(request)) return 500;
    for(int i=0;i<n;++i) {
        int r=gateway_http_feed(h,c,request+i,1);
        if(r>1) return r;
    }
    return gateway_http_process(h,c);
}
static bool returned_token(char *token)
{
    const GateResponse *r=(const GateResponse *)gateway_test_context.gate;
    const char *p=strstr((const char *)r->body,"\"token\":\"");
    if(!p) return false;
    p+=9; const char *e=strchr(p,'"');
    if(!e || e==p || e-p>127) return false;
    memcpy(token,p,(size_t)(e-p)); token[e-p]=0; return true;
}
void gateway_test_login(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
    CHECK("Dashboard served without authentication",call("GET","/",NULL,"")==200 && gateway_http_fixture.dashboard);
    CHECK("Dashboard cannot bypass incomplete framing",gateway_http_process(&gateway_http_fixture,&gateway_test_context)==400);
    CHECK("Dashboard POST is not a public route",call("POST","/",NULL,"{}")==401);
    CHECK("Dashboard rejects body",call("GET","/",NULL,"x")==400);
    CHECK("Dashboard rejects lookalike route",call("GET","/evil",NULL,"")==400);
    char header[256];
    CHECK("HTML header",gateway_http_html_header(header,sizeof(header),3600)>0 && strstr(header,"text/html") && strstr(header,"Content-Length: 3600"));
    CHECK("HTML header bounds",gateway_http_html_header(header,8,3600)==-1);
#if !GATEWAY_LAB_AUTH
    CHECK("Disabled authentication rejects login",call("POST","/api/login",NULL,"{\"username\":\"admin\",\"password\":\"admin456\"}")==401);
    GatewayIdentity disabled_id;
    CHECK("Disabled authentication rejects issued token",!gateway_login_validate((const uint8_t *)admin_token,strlen(admin_token),&disabled_id) && !disabled_id.valid);
    CHECK("Disabled issued token HTTP",call("GET","/api/status",admin_token,"")==401);
    return;
#endif
    char token[128]={0};
    CHECK("Admin login with byte fragmentation",call("POST","/api/login",NULL,"{\"username\":\"admin\",\"password\":\"admin456\"}")==200 && returned_token(token));
    CHECK("Issued token matches independent HMAC vector",!strcmp(token,admin_token));
    CHECK("Issued token Bearer encoding",strlen(token)==83 && strchr(token,'-') && !strchr(token,':'));
    CHECK("Issued admin token status",call("GET","/api/status",token,"")==200);
    CHECK("Issued admin token policy",call("GET","/api/policy",token,"")==200);
    CHECK("Issued admin token logout",call("POST","/api/logout",token,"{}")==200);
    CHECK("Original stateless logout retains token validity",call("GET","/api/status",token,"")==200);
    for(size_t i=0;i<strlen(token);++i) {
        if(token[i]=='-') continue;
        char saved=token[i]; token[i]=saved=='0'?'1':'0';
        int r=call("GET","/api/status",token,""); token[i]=saved;
        if(r!=401) { CHECK("Every token nibble authenticated",0); goto tested; }
    }
    CHECK("Every token nibble authenticated",1);
 tested:;
    CHECK("Operator login accepts whitespace/order/ASCII escape",call("POST","/api/login",NULL," { \"password\" : \"oper789\", \"username\" : \"\\u006fperator\" } ")==200 && returned_token(token));
    CHECK("Issued operator status",call("GET","/api/status",token,"")==200);
    CHECK("Issued operator denied policy",call("GET","/api/policy",token,"")==403);
    const struct {const char *body;int status;} cases[]={
        {"{\"username\":\"admin\",\"password\":\"wrong\"}",401},
        {"{\"username\":\"nobody\",\"password\":\"admin456\"}",401},
        {"{\"username\":\"admin\",\"password\":\"\"}",400},
        {"{\"username\":\"admin\"}",400},
        {"{\"username\":\"admin\",\"username\":\"admin\"}",400},
        {"{\"username\":\"admin\",\"password\":\"admin456\",\"extra\":0}",400},
        {"{\"username\":\"admin\",\"password\":\"admin456\"}x",400},
        {"{\"username\":\"admin\",\"password\":\"admin456}",400},
        {"{\"username\":\"admin\",\"password\":null}",400},
        {"{\"username\":\"admin\",\"password\":\"\\u0000\"}",400},
        {"{\"username\":\"admin\",\"password\":\"\\u0100\"}",400},
        {"{\"username\":\"admin\",\"password\":\"\\q\"}",400},
        {"[]",400}, {"",400}
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        char name[48]; snprintf(name,sizeof(name),"Login JSON/credential rejection %u",i);
        CHECK(name,call("POST","/api/login",NULL,cases[i].body)==cases[i].status);
    }
    char body[400],pass[258]; memset(pass,'x',sizeof(pass));
    for(unsigned n=64;n<=257;n+=(n==64?1:192)) {
        pass[n]=0; snprintf(body,sizeof(body),"{\"username\":\"admin\",\"password\":\"%s\"}",pass);
        CHECK("Password length boundary",call("POST","/api/login",NULL,body)==(n==64?401:400)); pass[n]='x';
    }
    GatewayIdentity id={0};
    CHECK("Credential helper enforces its own bound",!verify_credentials("admin",5,pass,65,&id.role,&id.scope,id.subject,&id.subject_len));
    char output[256];
    const char *good="{\"username\":\"admin\",\"password\":\"admin456\"}";
    bool ok=true;
    for(size_t n=0;n<strlen(good);++n) ok &= gateway_login((const uint8_t *)good,n,output,sizeof(output))==400;
    CHECK("Every truncated login body rejected",ok);
    CHECK("Login output bounds",gateway_login((const uint8_t *)good,strlen(good),output,8)==500);
    CHECK("Login leaves guards intact",gateway_guards_ok(&gateway_test_context));
#undef CHECK
}
