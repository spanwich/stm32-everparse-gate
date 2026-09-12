/*
 * credential_store.h -- Hardcoded credential store with salted SHA-256
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CREDENTIAL_STORE_H
#define CREDENTIAL_STORE_H

#include <stdint.h>
#include "path_hashes.h"

#define SUBJECT_ID_MAX 32

/*
 * Verify credentials against the store.
 * Returns 1 on success (sets role, scope, subject_id, subject_id_len).
 * Returns 0 on failure.
 */
int verify_credentials(const char *user, uint8_t ulen,
                       const char *pass, uint8_t plen,
                       uint8_t *role, uint16_t *scope,
                       uint8_t *subject_id, uint8_t *subject_id_len);

#endif /* CREDENTIAL_STORE_H */
