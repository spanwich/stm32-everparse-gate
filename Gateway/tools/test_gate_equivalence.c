/* Host check for section 14: on the same 75-byte access envelope, the verified
 * composed gate (through gateway_gate_adapter.c) and the monolithic RbacPolicy
 * access validator must return the same decision. Structured envelopes use the
 * production domains (roles 0..2, one method bit, sentinel slots, rate around
 * the threshold); raw envelopes are uniformly random bytes. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../Generated/Policy/RbacPolicyWrapper.h"

bool gateway_gate_decide_envelope(const uint8_t *e, uint32_t length);
void RbacPolicyEverParseError(const char *s, const char *f, const char *r) { (void)s; (void)f; (void)r; }

static uint64_t st = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return (uint32_t)st; }
static void put32(uint8_t *b, uint32_t x) { for (int i = 0; i < 4; i++) b[i] = (uint8_t)(x >> (8 * i)); }
static void put16(uint8_t *b, uint16_t x) { b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8); }

static void structured(uint8_t *e)
{
    static const uint32_t paths[] = { 0x00010001u, 0x00010002u, 0x00020001u, 0x00030001u };
    uint32_t rp = paths[rnd() % 4];
    for (int i = 0; i < 8; i++) {
        uint8_t *r = e + 4 + 8 * i;
        if (rnd() % 4 == 0) { put32(r, 0xDEADDEADu); r[4] = 0; r[5] = 0xFF; put16(r + 6, 0xFFFF); continue; }
        put32(r, rnd() % 3 ? paths[rnd() % 4] : rp);
        r[4] = (uint8_t)(rnd() & 0x3F); r[5] = (uint8_t)(rnd() % 3); put16(r + 6, (uint16_t)(rnd() & 0x7));
    }
    e[0] = (uint8_t)(rnd() % 3); e[1] = (uint8_t)(rnd() % 2 ? rnd() % 50 : 45 + rnd() % 10);
    put16(e + 2, (uint16_t)(rnd() & 0x7));
    put32(e + 68, rnd() % 8 ? rp : 0x7FFF0001u);
    e[72] = (uint8_t)(1u << (rnd() % 6));
    e[73] = e[74] = 0;
}

int main(void)
{
    uint8_t e[75];
    unsigned long n = 0, accepts = 0, mismatches = 0;
    for (int mode = 0; mode < 2; mode++)
        for (int i = 0; i < 500000; i++) {
            if (mode == 0) structured(e); else for (int k = 0; k < 75; k++) e[k] = (uint8_t)rnd();
            bool a = gateway_gate_decide_envelope(e, 75);
            bool b = RbacPolicyCheckAccessRequest(e, 75);
            n++; accepts += a;
            if (a != b && mismatches++ < 5) {
                fprintf(stderr, "MISMATCH mode=%d gate=%d monolithic=%d:", mode, a, b);
                for (int k = 0; k < 75; k++) fprintf(stderr, " %02x", e[k]);
                fprintf(stderr, "\n");
            }
        }
    printf("envelopes=%lu gate_accepts=%lu mismatches=%lu\n", n, accepts, mismatches);
    return mismatches != 0;
}
