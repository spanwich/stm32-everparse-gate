/* Handwritten bounded login adapter, owned by the gateway task. Demo accounts/key. */
#include "gateway_login.h"
#include "gateway_mediation.h"
#include "gateway_http.h"
#include "gateway_clear.h"
#include "credential_store.h"
#include "token_generate.h"
#include "token_validate.h"
#ifdef STM32F767xx
#include "gateway_d1_auth.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct { const uint8_t *p; size_t n, i; } Json;
static void space(Json *j)
{
    while (j->i < j->n && (j->p[j->i]==' ' || j->p[j->i]=='\t' ||
           j->p[j->i]=='\r' || j->p[j->i]=='\n')) ++j->i;
}
static bool take(Json *j, unsigned c)
{
    space(j);
    if (j->i == j->n || j->p[j->i] != c) return false;
    ++j->i; return true;
}
static int hex(unsigned c)
{
    if(c>='0' && c<='9') return (int)c-'0';
    if(c>='a' && c<='f') return (int)c-'a'+10;
    if(c>='A' && c<='F') return (int)c-'A'+10;
    return -1;
}
static bool string(Json *j, char *out, size_t capacity, uint8_t *length)
{
    size_t n=0;
    if(!take(j,'"')) return false;
    while(j->i < j->n) {
        unsigned c=j->p[j->i++];
        if(c=='"') { out[n]=0; *length=(uint8_t)n; return true; }
        if(c=='\\') {
            if(j->i==j->n) return false;
            c=j->p[j->i++];
            if(c=='u') {
                if(j->n-j->i<4) return false;
                c=0;
                for(unsigned k=0;k<4;++k) {
                    int v=hex(j->p[j->i++]); if(v<0) return false;
                    c=(c<<4)|(unsigned)v;
                }
            } else if(c!='"' && c!='\\' && c!='/') return false;
        }
        if(c<32 || c>126 || n+1>=capacity) return false;
        out[n++]=(char)c;
    }
    return false;
}
static bool credentials(const uint8_t *body, size_t length, char *user, uint8_t *ulen,
                        char *pass, uint8_t *plen)
{
    Json j={body,length,0}; unsigned seen=0;
    if(!take(&j,'{')) return false;
    for(unsigned i=0;i<2;++i) {
        char key[9]; uint8_t len=0;
        if(!string(&j,key,sizeof(key),&len) || !take(&j,':')) return false;
        if(!strcmp(key,"username") && !(seen&1)) {
            if(!string(&j,user,33,ulen) || !*ulen) return false;
            seen|=1;
        } else if(!strcmp(key,"password") && !(seen&2)) {
            if(!string(&j,pass,65,plen) || !*plen) return false;
            seen|=2;
        } else return false;
        if(i==0 && !take(&j,',')) return false;
    }
    if(!take(&j,'}')) return false;
    space(&j); return seen==3 && j.i==j.n;
}
bool gateway_login_prepare(const uint8_t *body, size_t length,
                           uint8_t envelope[106], uint32_t *envelope_length)
{
    char user[33]={0}, pass[65]={0};
    uint8_t ulen=0, plen=0;
    memset(envelope,0,106); *envelope_length=0;
    bool ok=credentials(body,length,user,&ulen,pass,&plen);
    if(ok) {
        envelope[8]=ulen;
        memcpy(envelope+9,user,ulen);
        envelope[9+ulen]=plen;
        memcpy(envelope+10+ulen,pass,plen);
        *envelope_length=10U+ulen+plen;
    }
    gateway_clear(user,sizeof(user)); gateway_clear(pass,sizeof(pass));
    return ok;
}
int gateway_auth_issue_token(const uint8_t *body, size_t length,
                             char *token, uint8_t *token_length)
{
    char user[33]={0}, pass[65]={0};
    uint8_t ulen=0,plen=0; GatewayIdentity id={0}; int status=400;
    *token_length=0;
    if(!credentials(body,length,user,&ulen,pass,&plen)) goto done;
    status=401;
#if GATEWAY_LAB_AUTH
    if(verify_credentials(user,ulen,pass,plen,&id.role,&id.scope,id.subject,&id.subject_len) &&
       generate_token((const char *)id.subject,id.subject_len,id.role,id.scope,
                      token,token_length)) status=200;
#endif
 done:;
    gateway_clear(user,sizeof(user)); gateway_clear(pass,sizeof(pass));
    gateway_clear(&id,sizeof(id));
    return status;
}
int gateway_login(const uint8_t *body, size_t length, char *response, size_t capacity)
{
    char token[128]={0}; uint8_t tlen=0;
#ifdef STM32F767xx
    int status=gateway_d1_auth_login(body,length,token,&tlen);
#else
    int status=gateway_auth_issue_token(body,length,token,&tlen);
#endif
    static const char prefix[]="{\"status\":\"ok\",\"token\":\"";
    static const char suffix[]="\"}";
    const char *error=status==400?
        "{\"status\":\"error\",\"message\":\"invalid login JSON\"}":
        "{\"status\":\"error\",\"message\":\"invalid credentials\"}";
    size_t n;
    if(status==200) {
        n=sizeof(prefix)-1U+tlen+sizeof(suffix)-1U;
        if(n<capacity) {
            memcpy(response,prefix,sizeof(prefix)-1U);
            memcpy(response+sizeof(prefix)-1U,token,tlen);
            memcpy(response+sizeof(prefix)-1U+tlen,suffix,sizeof(suffix)-1U);
            response[n]=0;
        }
    } else {
        n=strlen(error);
        if(n<capacity) memcpy(response,error,n+1U);
    }
    gateway_clear(token,sizeof(token));
    return n>=capacity?500:status;
}
bool gateway_login_validate(const uint8_t *token, size_t length, GatewayIdentity *identity)
{
    memset(identity,0,sizeof(*identity));
#ifdef STM32F767xx
    uint8_t rate=0;
    return gateway_d1_auth_identify(token,length,identity,&rate);
#else
#if GATEWAY_LAB_AUTH
    if(length>127 || !length) return false;
    identity->valid=validate_token((const char *)token,(uint8_t)length,&identity->role,
        &identity->scope,(char *)identity->subject,&identity->subject_len)!=0;
#else
    (void)token; (void)length;
#endif
    return identity->valid;
#endif
}
