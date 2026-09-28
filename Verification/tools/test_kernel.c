/* Independent C oracle for the byte format, plus real EverParse integration.
 * This is executable evidence, not a second formal specification. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "Mediation_Wrapper.h"
#include "Mediation_Format.h"
#include "Mediation_Extern.h"
static unsigned checks, effects, cases;
static uint8_t *expected_request, *expected_policy, *expected_login;
static uint8_t expected_kind;
static bool last_accepted;
static uint8_t captured[106];
bool gateway_mediation_check(uint8_t kind,uint8_t *bytes,uint32_t length);
void RbacPolicyEverParseError(const char *a,const char *b,const char *c) {(void)a;(void)b;(void)c;}
bool Mediation_Extern_check(uint8_t k,uint32_t n,uint8_t *r,uint8_t *p,uint8_t *l,uint8_t *e)
{
    assert(r==expected_request && p==expected_policy && l==expected_login && k==expected_kind);
    checks++; memcpy(captured,e,106);
    last_accepted=gateway_mediation_check(k,e,n);
    return last_accepted;
}
uint32_t Mediation_Extern_invoke(uint8_t k,uint32_t n,uint8_t *r,uint8_t *p,uint8_t *l,uint8_t *ctx)
{
    (void)n;
    assert(checks==1 && last_accepted && effects==0);
    assert(r==expected_request && p==expected_policy && l==expected_login && k==expected_kind);
    effects++; ctx[0]++; return 200;
}
static void reference(uint8_t kind,const uint8_t *r,const uint8_t *p,const uint8_t *l,uint8_t out[106])
{
    memset(out,0,106);
    if(kind==3) {out[0]=r[6];out[1]=r[0];memcpy(out+2,r+175,65);return;}
    if(kind==1) {
        out[0]=r[6];out[1]=r[0];memcpy(out+2,r+1,4);out[6]=r[5];
        memcpy(out+8,l+8,98);return;
    }
    if(kind==0) {
        memset(out+4,0x66,4);out[8]=1;
        memset(out+12,0x77,4);out[16]=1;
    } else {
        out[0]=r[6];out[1]=r[0];memcpy(out+2,r+7,2);
        for(unsigned i=0;i<8 && i<p[0];i++)memcpy(out+4+i*8,p+1+i*8,8);
    }
    memcpy(out+68,r+1,4);out[72]=r[5];
}
static void run(uint8_t k,uint32_t n,uint8_t *r,uint8_t *p,uint8_t *l,bool allow)
{
    _Alignas(4) uint8_t context[8864]={0x31};
    uint8_t envelope[106],want[106],oldr[1536],oldp[65],oldl[106];
    memcpy(oldr,r,1536);memcpy(oldp,p,65);memcpy(oldl,l,106);
    expected_request=r;expected_policy=p;expected_login=l;expected_kind=k;
    checks=effects=0;last_accepted=false;
    Mediation_Wrapper_result v=Mediation_Wrapper_run(k,n,r,p,l,context,envelope);
    assert(checks==1 && effects==(unsigned)allow && v.invoked==allow);
    assert(v.status==(allow?200U:403U) && context[0]==0x31+(unsigned)allow);
    assert(!memcmp(oldr,r,1536) && !memcmp(oldp,p,65) && !memcmp(oldl,l,106));
    reference(k,r,p,l,want);assert(!memcmp(captured,want,106));
    cases++;
}
static void path(uint8_t *r,uint8_t b) {memset(r+1,b,4);}
int main(void)
{
    uint8_t r[1536]={0},p[65]={0},l[106]={0};
    const uint8_t rates[]={0,49,50,255};
    /* Access: role, rate, all rule slots, scopes, and inactive matching slots. */
    for(unsigned role=0;role<3;role++)for(unsigned rate=0;rate<4;rate++)
    for(unsigned count=1;count<=8;count++)for(unsigned slot=0;slot<8;slot++)
    for(unsigned scope=0;scope<4;scope++) {
        memset(r,0,sizeof(r));memset(p,0,sizeof(p));
        path(r,0x55);r[5]=1;r[6]=(uint8_t)role;r[0]=rates[rate];r[7]=(uint8_t)scope;
        p[0]=(uint8_t)count;memset(p+1+8*slot,0x55,4);p[5+8*slot]=1;p[6+8*slot]=1;p[7+8*slot]=3;
        run(2,75,r,p,l,role>=1 && rates[rate]<50 && slot<count && scope==3);
    }
    for(unsigned role=0;role<3;role++)for(unsigned rate=0;rate<4;rate++)
    for(unsigned count=0;count<=9;count++)for(unsigned bad=0;bad<3;bad++) {
        memset(r,0,sizeof(r));r[6]=(uint8_t)role;r[0]=rates[rate];r[175]=(uint8_t)count;r[171]=65;
        if(bad==1)r[175+5]=4;
        if(bad==2)r[175+6]=3;
        run(3,70,r,p,l,role==2 && rates[rate]<50 && count>=1 && count<=8 && !bad);
    }
    for(unsigned route=0;route<3;route++)for(unsigned method=1;method<4;method++) {
        memset(r,0,sizeof(r));path(r,route==0?0x66:route==1?0x77:0x33);r[5]=(uint8_t)method;
        /* Hostile mutable policy cannot grant a public API route. */
        memset(p,0xff,sizeof(p));p[0]=8;run(0,75,r,p,l,route<2 && method==1);
    }
    for(unsigned u=0;u<=33;u++)for(unsigned pass=0;pass<=65;pass++) {
        memset(r,0,sizeof(r));memset(l,0,sizeof(l));path(r,0x11);r[5]=2;
        l[8]=(uint8_t)u;memset(l+9,'u',u);l[9+u]=(uint8_t)pass;
        unsigned n=10+u+pass;
        if(n<=106) {memset(l+10+u,'p',pass);run(1,n,r,p,l,u>=1 && u<=32 && pass>=1 && pass<=64);}
    }
    memset(r,0,sizeof(r));memset(l,0,sizeof(l));path(r,0x11);r[5]=2;l[8]=1;l[9]='u';l[10]=1;l[11]='p';
    run(1,12,r,p,l,true);run(1,13,r,p,l,false); /* exact framing */
    r[0]=50;run(1,12,r,p,l,false);r[0]=0;r[5]=1;run(1,12,r,p,l,false);
    path(r,0x33);r[5]=2;run(1,12,r,p,l,false);
    puts("Kernel integration PASS");printf("%u cases: independent byte oracle, real validators, exact snapshots, denial without effects\n",cases);
    return 0;
}
