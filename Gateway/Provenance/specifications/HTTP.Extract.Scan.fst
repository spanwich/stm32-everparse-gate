(*
 * HTTP.Extract.Scan - Verified HTTP header boundary scanner
 *
 * Finds the offset of \r\n\r\n (header/body separator) in an HTTP message.
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads are within bounds
 *   2. If found, offset <= len - 4
 *   3. Termination guaranteed (decreasing metric on loop index)
 *   4. Read-only: buffer is never modified
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Scan

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32

(* CR and LF byte constants *)
inline_for_extraction let cr : U8.t = 0x0Duy
inline_for_extraction let lf : U8.t = 0x0Auy

(*
 * scan_loop: recursive scan for \r\n\r\n starting at position i
 *
 * Invariants:
 * - len >= 4 (room for the 4-byte pattern)
 * - i <= len - 3 (loop bound)
 * - Terminates: (len - i) strictly decreases each iteration
 *
 * Returns len if not found, otherwise the offset where \r\n\r\n starts.
 *)
let rec scan_loop
  (buf: B.buffer U8.t)
  (len: U32.t{U32.v len <= B.length buf /\ U32.v len >= 4})
  (i: U32.t{U32.v i <= U32.v len - 3})
  : Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      U32.v result <= U32.v len /\
      (U32.v result < U32.v len ==> U32.v result <= U32.v len - 4))
    (decreases (U32.v len - U32.v i))
  =
  if U32.gt i (U32.sub len 4ul) then
    len  (* Past last valid check position — not found *)
  else begin
    (* i <= len - 4, so i, i+1, i+2, i+3 are all < len <= B.length buf *)
    let b0 = B.index buf i in
    let b1 = B.index buf (U32.add i 1ul) in
    let b2 = B.index buf (U32.add i 2ul) in
    let b3 = B.index buf (U32.add i 3ul) in
    if U8.eq b0 cr && U8.eq b1 lf && U8.eq b2 cr && U8.eq b3 lf then
      i  (* Found \r\n\r\n at offset i *)
    else
      scan_loop buf len (U32.add i 1ul)
  end

(*
 * find_header_end: find the offset of \r\n\r\n in an HTTP buffer
 *
 * Returns: offset of first \r\n\r\n if found, len if not found.
 *
 * VERIFIED:
 *   - All buffer accesses within bounds (B.index preconditions discharged)
 *   - found ==> offset <= len - 4 (pattern fits in remaining bytes)
 *   - Termination (decreasing metric on scan_loop)
 *   - Read-only (h0 == h1)
 *)
val find_header_end:
  buf: B.buffer U8.t ->
  len: U32.t{U32.v len <= B.length buf} ->
  Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      U32.v result <= U32.v len /\
      (U32.v result < U32.v len ==> U32.v result <= U32.v len - 4))

let find_header_end buf len =
  if U32.lt len 4ul then
    len  (* Too short to contain \r\n\r\n *)
  else
    scan_loop buf len 0ul
