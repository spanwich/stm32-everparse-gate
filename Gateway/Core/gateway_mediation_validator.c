/* Small trusted FFI bridge. Generated EverParse runtime stays in a separate
 * translation unit from KaRaMeL's runtime headers. */
#include <stdbool.h>
#include <stdint.h>
#include "../Generated/Policy/RbacPolicyWrapper.h"
#include "../Generated/Policy/Blob.h"
#include "paper_experiment.h"
bool gateway_gate_decide_envelope(const uint8_t *e, uint32_t length);
bool gateway_mediation_check(uint8_t kind, uint8_t *bytes, uint32_t length)
{
    if(kind==0 || kind==2)
#if GATEWAY_VERIFIED_GATE
        return gateway_gate_decide_envelope(bytes,length);
#else
        return length==75 && RbacPolicyCheckAccessRequest(bytes,length);
#endif
    if(kind==3)
        return length==70 && RbacPolicyCheckPolicyBlob(bytes,length);
    if(kind==1) {
        /* The generated wrapper accepts a valid prefix. Require exact framing. */
        if(length<12 || length>106 || bytes[8]<1 || bytes[8]>32) return false;
        unsigned password_offset=9U+bytes[8];
        if(password_offset>=length || bytes[password_offset]<1 || bytes[password_offset]>64 ||
           password_offset+1U+bytes[password_offset]!=length) return false;
        return RbacPolicyCheckLoginRequest(bytes,length);
    }
    return false;
}

/* Verified policy-update commit (paper-experiments/verified-policyblob):
 * BlobLowUpdateDecide rebuilds the PolicyBlob buffer, runs the generated
 * validator, and decodes the eight rules only on acceptance. Returns 1 with
 * the decoded rules, otherwise 0 or 2 (fail closed) and writes nothing. */
uint8_t gateway_policy_update(uint8_t role, uint8_t count, uint8_t *body,
                              uint32_t paths[8], uint8_t masks[8],
                              uint8_t min_roles[8], uint16_t scopes[8],
                              uint8_t *num_rules)
{
    BLOB_SPEC_SESSION s={role,count};
    BLOB_SPEC_RULE pol[8];
    uint8_t nr=0, ctxt=0;
    uint8_t r=BlobLowUpdateDecide(s,body,pol,&nr,&ctxt);
    if(r!=1) return r;
    for(unsigned i=0;i<8;++i) {
        paths[i]=pol[i].path; masks[i]=pol[i].mask;
        min_roles[i]=pol[i].min_role; scopes[i]=pol[i].rscope;
    }
    *num_rules=nr;
    return 1;
}
