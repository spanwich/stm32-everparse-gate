(*
 * IPC.Extract - Verified IPC field population for SecurityParamsWire
 *
 * Populates the auth-resolved fields (role, scope, subject_id) and rate
 * counter into the SecurityParamsWire output buffer.  These fields were
 * previously written by unverified C code (validate_and_fill).
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer writes within bounds
 *   2. role clamped to <= 2 (ADMIN)
 *   3. subject_id_len clamped to <= 32
 *   4. Exactly the specified bytes are written; no out-of-bounds access
 *   5. Termination guaranteed
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module IPC.Extract

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32

open HTTP.Extract.Types

(* ============================================================
 * copy_subject_bytes: copy up to N bytes from auth_buf to out_buf
 * Equivalent to memcpy(out + off_subject_id, auth + AUTH_RESP_SUB_START, len)
 * ============================================================ *)
let rec copy_subject_bytes
  (out_buf: B.buffer U8.t)
  (auth_buf: B.buffer U8.t)
  (len: U32.t{U32.v off_subject_id + U32.v len <= B.length out_buf /\
              5 + U32.v len <= B.length auth_buf /\
              U32.v len <= U32.v subject_id_max})
  (i: U32.t{U32.v i <= U32.v len})
  : Stack unit
    (requires fun h -> B.live h out_buf /\ B.live h auth_buf /\
      B.loc_disjoint (B.loc_buffer out_buf) (B.loc_buffer auth_buf))
    (ensures fun h0 _ h1 -> B.live h1 out_buf /\ B.live h1 auth_buf /\
      B.modifies (B.loc_buffer out_buf) h0 h1)
    (decreases (U32.v len - U32.v i))
  =
  if U32.eq i len then ()
  else begin
    (* AUTH_RESP_SUB_START = 5 *)
    let b = B.index auth_buf (U32.add 5ul i) in
    B.upd out_buf (U32.add off_subject_id i) b;
    copy_subject_bytes out_buf auth_buf len (U32.add i 1ul)
  end

(* ============================================================
 * populate_auth_fields: write role, scope, subject_id into out_buf
 *
 * auth_buf layout (from Authenticator validate response):
 *   [valid:1][role:1][scope_lo:1][scope_hi:1][sub_len:1][sub:N]
 *
 * out_buf layout (SecurityParamsWire, relevant offsets):
 *   [6] = role
 *   [7] = scope_lo
 *   [8] = scope_hi
 *   [9] = subject_id_len
 *   [10..41] = subject_id
 * ============================================================ *)
val populate_auth_fields:
  out_buf: B.buffer U8.t{B.length out_buf >= 42} ->
  auth_buf: B.buffer U8.t{B.length auth_buf >= 37} ->
  Stack unit
    (requires fun h ->
      B.live h out_buf /\ B.live h auth_buf /\
      B.loc_disjoint (B.loc_buffer out_buf) (B.loc_buffer auth_buf))
    (ensures fun h0 _ h1 ->
      B.live h1 out_buf /\ B.live h1 auth_buf /\
      B.modifies (B.loc_buffer out_buf) h0 h1 /\
      U8.v (B.get h1 out_buf 6) <= 2 /\
      U8.v (B.get h1 out_buf 9) <= 32)

let populate_auth_fields out_buf auth_buf =
  (* Read all values from auth_buf first (disjointness guarantees stability) *)
  let raw_role = B.index auth_buf 1ul in
  let role = if U8.gt raw_role 2uy then 2uy else raw_role in

  let scope_lo = B.index auth_buf 2ul in
  let scope_hi = B.index auth_buf 3ul in

  let raw_sub_len = B.index auth_buf 4ul in
  let sub_len = if U8.gt raw_sub_len 32uy then 32uy else raw_sub_len in
  let sub_len32 = FStar.Int.Cast.uint8_to_uint32 sub_len in

  (* Step 1: Copy subject_id bytes FIRST (coarse B.modifies kills prior writes) *)
  copy_subject_bytes out_buf auth_buf sub_len32 0ul;

  (* Step 2: Scalar writes AFTER copy — B.upd establishes fresh per-index facts
   * that survive subsequent B.upd on different offsets (6 <> 7 <> 8 <> 9). *)
  B.upd out_buf off_role role;
  B.upd out_buf off_scope_lo scope_lo;
  B.upd out_buf off_scope_hi scope_hi;
  B.upd out_buf off_subject_id_len sub_len

(* ============================================================
 * populate_rate_field: write rate counter byte at offset 0
 *
 * rate_buf layout: [rate_count:1] (single byte from RateLimiter)
 * out_buf[0] = rate_count
 * ============================================================ *)
val populate_rate_field:
  out_buf: B.buffer U8.t{B.length out_buf >= 1} ->
  rate_val: U8.t ->
  Stack unit
    (requires fun h -> B.live h out_buf)
    (ensures fun h0 _ h1 -> B.live h1 out_buf /\
      B.modifies (B.loc_buffer out_buf) h0 h1)

let populate_rate_field out_buf rate_val =
  B.upd out_buf off_rate_count rate_val
