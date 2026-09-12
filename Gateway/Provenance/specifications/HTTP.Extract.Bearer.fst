(*
 * HTTP.Extract.Bearer - Verified bearer token extraction
 *
 * Scans HTTP headers for "Authorization: Bearer " (case-sensitive, RFC 7235)
 * and copies token bytes until \r\n, capped at AUTH_TOKEN_MAX (128).
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads within bounds
 *   2. Token length <= AUTH_TOKEN_MAX (128)
 *   3. Input buffer is read-only (never modified)
 *   4. Output buffer only modified within [0, AUTH_TOKEN_MAX)
 *   5. Termination guaranteed
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Bearer

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module Cast = FStar.Int.Cast

open HTTP.Extract.Types

(* ============================================================
 * check_auth_bearer: check if 22 bytes at position h match
 * "Authorization: Bearer " (case-sensitive)
 *
 * Hex: 41 75 74 68 6F 72 69 7A 61 74 69 6F 6E 3A 20
 *      42 65 61 72 65 72 20
 * ============================================================ *)
let check_auth_bearer
  (buf: B.buffer U8.t)
  (h: U32.t{U32.v h + 22 <= B.length buf})
  : Stack bool
    (requires fun h0 -> B.live h0 buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let b0  = B.index buf h in
  let b1  = B.index buf (U32.add h 1ul) in
  let b2  = B.index buf (U32.add h 2ul) in
  let b3  = B.index buf (U32.add h 3ul) in
  let b4  = B.index buf (U32.add h 4ul) in
  let b5  = B.index buf (U32.add h 5ul) in
  let b6  = B.index buf (U32.add h 6ul) in
  let b7  = B.index buf (U32.add h 7ul) in
  let b8  = B.index buf (U32.add h 8ul) in
  let b9  = B.index buf (U32.add h 9ul) in
  let b10 = B.index buf (U32.add h 10ul) in
  let b11 = B.index buf (U32.add h 11ul) in
  let b12 = B.index buf (U32.add h 12ul) in
  let b13 = B.index buf (U32.add h 13ul) in
  let b14 = B.index buf (U32.add h 14ul) in
  let b15 = B.index buf (U32.add h 15ul) in
  let b16 = B.index buf (U32.add h 16ul) in
  let b17 = B.index buf (U32.add h 17ul) in
  let b18 = B.index buf (U32.add h 18ul) in
  let b19 = B.index buf (U32.add h 19ul) in
  let b20 = B.index buf (U32.add h 20ul) in
  let b21 = B.index buf (U32.add h 21ul) in
  (* A  u  t  h  o  r  i  z  a  t  i  o  n  :  SP B  e  a  r  e  r  SP *)
  U8.eq b0 0x41uy && U8.eq b1 0x75uy && U8.eq b2 0x74uy &&
  U8.eq b3 0x68uy && U8.eq b4 0x6Fuy && U8.eq b5 0x72uy &&
  U8.eq b6 0x69uy && U8.eq b7 0x7Auy && U8.eq b8 0x61uy &&
  U8.eq b9 0x74uy && U8.eq b10 0x69uy && U8.eq b11 0x6Fuy &&
  U8.eq b12 0x6Euy && U8.eq b13 0x3Auy && U8.eq b14 0x20uy &&
  U8.eq b15 0x42uy && U8.eq b16 0x65uy && U8.eq b17 0x61uy &&
  U8.eq b18 0x72uy && U8.eq b19 0x65uy && U8.eq b20 0x72uy &&
  U8.eq b21 0x20uy

(* ============================================================
 * copy_token_bytes: copy token bytes from buf[pos..] to out[i..]
 * Stops at \r, header_end, or AUTH_TOKEN_MAX (128) bytes.
 * Returns the number of bytes copied as U8.t.
 * ============================================================ *)
let rec copy_token_bytes
  (buf: B.buffer U8.t)
  (out: B.buffer U8.t{B.length out >= 128})
  (header_end: U32.t{U32.v header_end <= B.length buf})
  (pos: U32.t{U32.v pos <= U32.v header_end})
  (i: U32.t{U32.v i <= 128})
  : Stack U8.t
    (requires fun h -> B.live h buf /\ B.live h out /\
      B.loc_disjoint (B.loc_buffer buf) (B.loc_buffer out))
    (ensures fun h0 result h1 ->
      B.live h1 buf /\ B.live h1 out /\
      B.modifies (B.loc_buffer out) h0 h1 /\
      U8.v result <= 128)
    (decreases (128 - U32.v i))
  =
  if U32.eq i 128ul then
    128uy  (* Token truncated at AUTH_TOKEN_MAX *)
  else if U32.eq pos header_end then
    Cast.uint32_to_uint8 i  (* End of headers — return bytes copied *)
  else begin
    let b = B.index buf pos in
    if U8.eq b 0x0Duy then  (* \r = end of header value *)
      Cast.uint32_to_uint8 i
    else begin
      B.upd out i b;
      copy_token_bytes buf out header_end (U32.add pos 1ul) (U32.add i 1ul)
    end
  end

(* ============================================================
 * scan_for_bearer: scan headers for \r\nAuthorization: Bearer
 * If found, copy token bytes to out and return length.
 * Returns 0uy if not found.
 * ============================================================ *)
let rec scan_for_bearer
  (buf: B.buffer U8.t)
  (header_end: U32.t{U32.v header_end <= B.length buf})
  (out: B.buffer U8.t{B.length out >= 128})
  (i: U32.t{U32.v i <= U32.v header_end})
  : Stack U8.t
    (requires fun h -> B.live h buf /\ B.live h out /\
      B.loc_disjoint (B.loc_buffer buf) (B.loc_buffer out))
    (ensures fun h0 result h1 ->
      B.live h1 buf /\ B.live h1 out /\
      B.modifies (B.loc_buffer out) h0 h1 /\
      U8.v result <= 128)
    (decreases (U32.v header_end - U32.v i))
  =
  (* Need \r\n (2 bytes) + "Authorization: Bearer " (22 bytes) = 24 bytes minimum *)
  if U32.lt (U32.sub header_end i) 24ul then
    0uy  (* Not enough space for the header *)
  else begin
    let b0 = B.index buf i in
    let b1 = B.index buf (U32.add i 1ul) in
    if U8.eq b0 0x0Duy && U8.eq b1 0x0Auy then begin
      let h = U32.add i 2ul in
      if U32.lte (U32.add h 22ul) header_end then begin
        let is_bearer = check_auth_bearer buf h in
        if is_bearer then begin
          let token_start = U32.add h 22ul in
          copy_token_bytes buf out header_end token_start 0ul
        end else
          scan_for_bearer buf header_end out (U32.add i 1ul)
      end else
        0uy
    end else
      scan_for_bearer buf header_end out (U32.add i 1ul)
  end

(* ============================================================
 * extract_bearer_token: main entry point
 *
 * Given an HTTP request buffer and header_end offset,
 * find Authorization: Bearer header and extract token bytes.
 * Returns 0 if no bearer token found.
 * Returns token length (capped at AUTH_TOKEN_MAX = 128).
 * ============================================================ *)
val extract_bearer_token:
  buf: B.buffer U8.t ->
  header_end: U32.t{U32.v header_end <= B.length buf} ->
  out_token: B.buffer U8.t{B.length out_token >= 128} ->
  Stack U8.t
    (requires fun h -> B.live h buf /\ B.live h out_token /\
      B.loc_disjoint (B.loc_buffer buf) (B.loc_buffer out_token))
    (ensures fun h0 result h1 ->
      B.live h1 buf /\ B.live h1 out_token /\
      B.modifies (B.loc_buffer out_token) h0 h1 /\
      U8.v result <= 128)

let extract_bearer_token buf header_end out_token =
  scan_for_bearer buf header_end out_token 0ul
