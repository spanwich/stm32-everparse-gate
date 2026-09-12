/*
 * credential_store.c -- Hardcoded credential store with salted SHA-256
 *
 * Credentials:
 *   admin    / admin456  -> ADMIN(2),    scope=0x3F
 *   operator / oper789   -> OPERATOR(1), scope=0x03
 *
 * Password storage: salt(16) + SHA-256(salt || password).
 * Salt is per-user, pre-computed.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "credential_store.h"
#include <string.h>
#include "Hacl_Hash_SHA2.h"

#define SALT_LEN   16
#define DIGEST_LEN 32

typedef struct {
    const char *username;
    uint8_t     username_len;
    uint8_t     salt[SALT_LEN];
    uint8_t     hash[DIGEST_LEN];   /* SHA-256(salt || password) */
    uint8_t     role;
    uint16_t    scope;
} CredEntry;

/*
 * Pre-computed salts and hashes.
 * Generated via: SHA-256(salt || "admin456") and SHA-256(salt || "oper789")
 * We compute them at init time in a static init function instead.
 */
static CredEntry cred_table[2];
static int cred_table_init_done = 0;

/* Compute SHA-256(salt || password) */
static void compute_salted_hash(const uint8_t *salt, uint8_t salt_len,
                                const char *password, uint8_t pass_len,
                                uint8_t *out)
{
    uint8_t buf[SALT_LEN + 64]; /* salt(16) + max password */
    memcpy(buf, salt, salt_len);
    memcpy(buf + salt_len, password, pass_len);
    Hacl_Hash_SHA2_hash_256(out, buf, (uint32_t)(salt_len + pass_len));
}

static void init_cred_table(void)
{
    if (cred_table_init_done) return;

    /* admin / admin456 -> ADMIN, scope=0x3F */
    static const uint8_t admin_salt[SALT_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    cred_table[0].username     = "admin";
    cred_table[0].username_len = 5;
    memcpy(cred_table[0].salt, admin_salt, SALT_LEN);
    compute_salted_hash(admin_salt, SALT_LEN, "admin456", 8,
                        cred_table[0].hash);
    cred_table[0].role  = ROLE_ADMIN;
    cred_table[0].scope = 0x3F;

    /* operator / oper789 -> OPERATOR, scope=0x03 */
    static const uint8_t oper_salt[SALT_LEN] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    cred_table[1].username     = "operator";
    cred_table[1].username_len = 8;
    memcpy(cred_table[1].salt, oper_salt, SALT_LEN);
    compute_salted_hash(oper_salt, SALT_LEN, "oper789", 7,
                        cred_table[1].hash);
    cred_table[1].role  = ROLE_OPERATOR;
    cred_table[1].scope = 0x03;

    cred_table_init_done = 1;
}

int verify_credentials(const char *user, uint8_t ulen,
                       const char *pass, uint8_t plen,
                       uint8_t *role, uint16_t *scope,
                       uint8_t *subject_id, uint8_t *subject_id_len)
{
    init_cred_table();

    for (int i = 0; i < 2; i++) {
        const CredEntry *e = &cred_table[i];
        if (ulen != e->username_len) continue;
        if (memcmp(user, e->username, ulen) != 0) continue;

        /* Compute SHA-256(salt || password) and compare */
        uint8_t test_hash[DIGEST_LEN];
        compute_salted_hash(e->salt, SALT_LEN, pass, plen, test_hash);

        if (memcmp(test_hash, e->hash, DIGEST_LEN) != 0) continue;

        /* Match! */
        *role  = e->role;
        *scope = e->scope;
        *subject_id_len = e->username_len;
        memcpy(subject_id, e->username, e->username_len);
        return 1;
    }

    return 0;
}
