(*
 * HTTP.Extract.Method - Verified HTTP method parser
 *
 * Matches GET, POST, PUT, DELETE, PATCH, HEAD at the start of an HTTP
 * request buffer.  Returns a power-of-two bitmask code (one bit per method).
 * No loops — just bounded byte comparisons.
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads within bounds
 *   2. Result code is 0 or a known method bitmask (power of two in 0x01..0x20)
 *   3. If method found, offset <= len (safe for subsequent parsing)
 *   4. Read-only: buffer never modified
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Method

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32

open HTTP.Extract.Types

(*
 * parse_method: identify HTTP method from request line
 *
 * Matches: "GET " (4), "PUT " (4), "POST " (5), "HEAD " (5),
 *          "PATCH " (6), "DELETE " (7)
 * Returns method_result with code 0 for unrecognized methods.
 *)
val parse_method:
  buf: B.buffer U8.t ->
  len: U32.t{U32.v len <= B.length buf} ->
  Stack method_result
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      (result.mr_code = 0uy \/
       result.mr_code = method_get \/
       result.mr_code = method_post \/
       result.mr_code = method_put \/
       result.mr_code = method_delete \/
       result.mr_code = method_patch \/
       result.mr_code = method_head) /\
      (U8.v result.mr_code > 0 ==> U32.v result.mr_end <= U32.v len) /\
      (U8.v result.mr_code = 0 ==> U32.v result.mr_end = 0))

let parse_method buf len =
  if U32.lt len 4ul then
    { mr_code = 0uy; mr_end = 0ul }
  else begin
    (* Read first 4 bytes — safe because len >= 4 *)
    let b0 = B.index buf 0ul in
    let b1 = B.index buf 1ul in
    let b2 = B.index buf 2ul in
    let b3 = B.index buf 3ul in
    (* GET = 0x47 0x45 0x54 0x20 *)
    if U8.eq b0 0x47uy && U8.eq b1 0x45uy && U8.eq b2 0x54uy && U8.eq b3 0x20uy then
      { mr_code = method_get; mr_end = 4ul }
    (* PUT = 0x50 0x55 0x54 0x20 *)
    else if U8.eq b0 0x50uy && U8.eq b1 0x55uy && U8.eq b2 0x54uy && U8.eq b3 0x20uy then
      { mr_code = method_put; mr_end = 4ul }
    (* Methods needing 5+ bytes *)
    else if U32.gte len 5ul then begin
      let b4 = B.index buf 4ul in
      (* POST = 0x50 0x4F 0x53 0x54 0x20 *)
      if U8.eq b0 0x50uy && U8.eq b1 0x4Fuy && U8.eq b2 0x53uy && U8.eq b3 0x54uy && U8.eq b4 0x20uy then
        { mr_code = method_post; mr_end = 5ul }
      (* HEAD = 0x48 0x45 0x41 0x44 0x20 *)
      else if U8.eq b0 0x48uy && U8.eq b1 0x45uy && U8.eq b2 0x41uy && U8.eq b3 0x44uy && U8.eq b4 0x20uy then
        { mr_code = method_head; mr_end = 5ul }
      (* Methods needing 6+ bytes *)
      else if U32.gte len 6ul then begin
        let b5 = B.index buf 5ul in
        (* PATCH = 0x50 0x41 0x54 0x43 0x48 0x20 *)
        if U8.eq b0 0x50uy && U8.eq b1 0x41uy && U8.eq b2 0x54uy && U8.eq b3 0x43uy && U8.eq b4 0x48uy && U8.eq b5 0x20uy then
          { mr_code = method_patch; mr_end = 6ul }
        (* Methods needing 7+ bytes *)
        else if U32.gte len 7ul then begin
          let b6 = B.index buf 6ul in
          (* DELETE = 0x44 0x45 0x4C 0x45 0x54 0x45 0x20 *)
          if U8.eq b0 0x44uy && U8.eq b1 0x45uy && U8.eq b2 0x4Cuy && U8.eq b3 0x45uy && U8.eq b4 0x54uy && U8.eq b5 0x45uy && U8.eq b6 0x20uy then
            { mr_code = method_delete; mr_end = 7ul }
          else
            { mr_code = 0uy; mr_end = 0ul }
        end
        else
          { mr_code = 0uy; mr_end = 0ul }
      end
      else
        { mr_code = 0uy; mr_end = 0ul }
    end
    else
      { mr_code = 0uy; mr_end = 0ul }
  end
