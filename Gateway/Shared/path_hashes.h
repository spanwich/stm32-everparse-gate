/*
 * path_hashes.h -- Single source of truth for path hash constants.
 *
 * Sentinel path hash constants -- MUST match HTTP.Extract.Types.fst.
 * These are NOT DJB2 hashes. They are fixed lookup values assigned
 * by the F*-verified extractor for known endpoints.
 * DO NOT CHANGE without re-verifying HTTP.Extract.Path.fst.
 *
 * HTTP method codes -- MUST match HTTP.Extract.Types.fst.
 * Role levels -- MUST match RbacPolicy.3d.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PATH_HASHES_H
#define PATH_HASHES_H

#include <stdint.h>

/* Sentinel path hash constants */
#define PATH_LOGIN    0x11111111u
#define PATH_LOGOUT   0x22222222u
#define PATH_STATUS   0x33333333u
#define PATH_POLICY   0x44444444u
#define DEAD_HASH     0xDEADDEADu  /* unused rule slot sentinel */
#define INACTIVE_PATH_ID DEAD_HASH

/* HTTP method codes */
#define METHOD_GET    0x01u
#define METHOD_POST   0x02u
#define METHOD_PUT    0x04u
#define METHOD_DELETE 0x08u
#define METHOD_PATCH  0x10u
#define METHOD_HEAD   0x20u
#define METHOD_MASK_ALL 0x3fu

/* Role levels */
#define ROLE_NONE     0
#define ROLE_OPERATOR 1
#define ROLE_ADMIN    2

#endif /* PATH_HASHES_H */
