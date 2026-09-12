(*
 * HTTP.Extract.Types - Shared constants and types for verified HTTP extractor
 *
 * All constants must match the C headers exactly:
 *   - security_params_wire.h (wire format, field offsets)
 *   - extract.h (ExtractionResult enum values)
 *   - control_pipeline.h (PATH_LOGIN, PATH_LOGOUT, etc.)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Types

module U8 = FStar.UInt8
module U32 = FStar.UInt32

(* ============================================================
 * HTTP method codes — must match extract.c
 * ============================================================ *)
inline_for_extraction let method_get:  U8.t = 1uy
inline_for_extraction let method_post: U8.t = 2uy
inline_for_extraction let method_put:  U8.t = 3uy

(* ============================================================
 * Path hash sentinel constants — must match control_pipeline.h
 * These are NOT DJB2 hashes. They are fixed lookup values.
 * ============================================================ *)
inline_for_extraction let path_login:  U32.t = 0x11111111ul
inline_for_extraction let path_logout: U32.t = 0x22222222ul
inline_for_extraction let path_status: U32.t = 0x33333333ul
inline_for_extraction let path_policy: U32.t = 0x44444444ul

(* ============================================================
 * SecurityParamsWire format — must match security_params_wire.h
 * ============================================================ *)
inline_for_extraction let secparams_header_size: U32.t = 175ul
inline_for_extraction let max_inline_body: U32.t = 1361ul  (* 1536 - 175 *)

(* Field offsets within SecurityParamsWire *)
inline_for_extraction let off_rate_count:     U32.t = 0ul
inline_for_extraction let off_path_hash:      U32.t = 1ul
inline_for_extraction let off_method:         U32.t = 5ul
inline_for_extraction let off_role:           U32.t = 6ul
inline_for_extraction let off_scope_lo:       U32.t = 7ul
inline_for_extraction let off_scope_hi:       U32.t = 8ul
inline_for_extraction let off_subject_id_len: U32.t = 9ul
inline_for_extraction let off_subject_id:     U32.t = 10ul
inline_for_extraction let subject_id_max:     U32.t = 32ul
inline_for_extraction let off_token_len:      U32.t = 42ul
inline_for_extraction let off_token:          U32.t = 43ul
inline_for_extraction let off_body_len:       U32.t = 171ul

(* Bearer token maximum length — must match AUTH_TOKEN_MAX in security_params_wire.h *)
inline_for_extraction let auth_token_max:     U32.t = 128ul

(* ============================================================
 * ExtractionResult codes — must match extract.h enum
 * ============================================================ *)
inline_for_extraction let extract_ok:             U8.t = 0uy
inline_for_extraction let extract_incomplete:     U8.t = 1uy
inline_for_extraction let extract_malformed:      U8.t = 2uy
inline_for_extraction let extract_body_too_large: U8.t = 3uy
inline_for_extraction let extract_path_traversal: U8.t = 4uy
inline_for_extraction let extract_method_unknown: U8.t = 5uy

(* ============================================================
 * Method parse result (returned by parse_method)
 * ============================================================ *)
type method_result = {
  mr_code: U8.t;   (* 0 = unknown, 1 = GET, 2 = POST, 3 = PUT *)
  mr_end: U32.t;   (* offset after method + space; 0 if unknown *)
}

(* ============================================================
 * Path extraction result (returned by extract_path_hash)
 * ============================================================ *)
type path_result = {
  pr_hash: U32.t;   (* sentinel hash, 0 = unknown/rejected *)
  pr_is_root: bool;  (* true if path is exactly "/" *)
}
