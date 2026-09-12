(*
 * HTTP.Extract.Header - Verified Content-Length header parsing
 *
 * Scans HTTP headers for Content-Length and parses its decimal value.
 * Supports both "Content-Length:" and "content-length:" forms.
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads within bounds
 *   2. Decimal parsing cannot overflow (clamped to max_inline_body + 1)
 *   3. Read-only: buffer never modified
 *   4. Termination for all loops
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Header

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module Cast = FStar.Int.Cast

open HTTP.Extract.Types

(* ============================================================
 * parse_digits: parse decimal digits starting at position j
 * Returns parsed value, clamped to max_inline_body + 1.
 * ============================================================ *)
let rec parse_digits
  (buf: B.buffer U8.t)
  (header_end: U32.t{U32.v header_end <= B.length buf})
  (j: U32.t{U32.v j <= U32.v header_end})
  (acc: U32.t{U32.v acc <= U32.v max_inline_body})
  : Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
    (decreases (U32.v header_end - U32.v j))
  =
  if U32.eq j header_end then acc
  else begin
    let b = B.index buf j in
    if U8.gte b 0x30uy && U8.lte b 0x39uy then begin
      (* acc <= 1361, so acc * 10 + 9 <= 13619 < 2^32 — no overflow *)
      let digit = Cast.uint8_to_uint32 (U8.sub b 0x30uy) in
      let new_acc = U32.add (U32.mul acc 10ul) digit in
      if U32.gt new_acc max_inline_body then
        U32.add max_inline_body 1ul  (* Clamped: signals body too large *)
      else
        parse_digits buf header_end (U32.add j 1ul) new_acc
    end else
      acc
  end

(* ============================================================
 * skip_spaces: advance past space characters (0x20)
 * ============================================================ *)
let rec skip_spaces
  (buf: B.buffer U8.t)
  (header_end: U32.t{U32.v header_end <= B.length buf})
  (j: U32.t{U32.v j <= U32.v header_end})
  : Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      U32.v j <= U32.v result /\
      U32.v result <= U32.v header_end)
    (decreases (U32.v header_end - U32.v j))
  =
  if U32.eq j header_end then j
  else begin
    let b = B.index buf j in
    if U8.eq b 0x20uy then
      skip_spaces buf header_end (U32.add j 1ul)
    else
      j
  end

(* ============================================================
 * check_content_length_upper: check if bytes at h match
 * "Content-Length:" (15 bytes, title case)
 * ============================================================ *)
let check_content_length_upper
  (buf: B.buffer U8.t)
  (h: U32.t{U32.v h + 15 <= B.length buf})
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
  (* C o n t e n t - L e n g t h : *)
  U8.eq b0 0x43uy && U8.eq b1 0x6Fuy && U8.eq b2 0x6Euy &&
  U8.eq b3 0x74uy && U8.eq b4 0x65uy && U8.eq b5 0x6Euy &&
  U8.eq b6 0x74uy && U8.eq b7 0x2Duy && U8.eq b8 0x4Cuy &&
  U8.eq b9 0x65uy && U8.eq b10 0x6Euy && U8.eq b11 0x67uy &&
  U8.eq b12 0x74uy && U8.eq b13 0x68uy && U8.eq b14 0x3Auy

(* ============================================================
 * check_content_length_lower: check if bytes at h match
 * "content-length:" (15 bytes, all lowercase)
 * ============================================================ *)
let check_content_length_lower
  (buf: B.buffer U8.t)
  (h: U32.t{U32.v h + 15 <= B.length buf})
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
  (* c o n t e n t - l e n g t h : *)
  U8.eq b0 0x63uy && U8.eq b1 0x6Fuy && U8.eq b2 0x6Euy &&
  U8.eq b3 0x74uy && U8.eq b4 0x65uy && U8.eq b5 0x6Euy &&
  U8.eq b6 0x74uy && U8.eq b7 0x2Duy && U8.eq b8 0x6Cuy &&
  U8.eq b9 0x65uy && U8.eq b10 0x6Euy && U8.eq b11 0x67uy &&
  U8.eq b12 0x74uy && U8.eq b13 0x68uy && U8.eq b14 0x3Auy

(* ============================================================
 * scan_for_content_length: scan headers for Content-Length
 *
 * Looks for \r\n followed by "Content-Length:" or "content-length:"
 * Returns parsed value (clamped), or 0 if not found.
 * ============================================================ *)
let rec scan_for_content_length
  (buf: B.buffer U8.t)
  (header_end: U32.t{U32.v header_end <= B.length buf})
  (i: U32.t{U32.v i <= U32.v header_end})
  : Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
    (decreases (U32.v header_end - U32.v i))
  =
  (* Need i + 16 < header_end to check \r\n + 15 bytes of header name
     (i.e., at least 17 bytes from i) *)
  if U32.lt (U32.sub header_end i) 17ul then
    0ul  (* Not enough space for \r\nContent-Length: *)
  else begin
    let b0 = B.index buf i in
    let b1 = B.index buf (U32.add i 1ul) in
    if U8.eq b0 0x0Duy && U8.eq b1 0x0Auy then begin
      let h = U32.add i 2ul in
      (* Check if remaining bytes are enough for the header name *)
      if U32.lte (U32.add h 15ul) header_end then begin
        let is_upper = check_content_length_upper buf h in
        let is_lower = check_content_length_lower buf h in
        if is_upper || is_lower then begin
          let val_start = U32.add h 15ul in
          let val_start' = skip_spaces buf header_end val_start in
          parse_digits buf header_end val_start' 0ul
        end else
          scan_for_content_length buf header_end (U32.add i 1ul)
      end else
        0ul  (* Not enough space for header name *)
    end else
      scan_for_content_length buf header_end (U32.add i 1ul)
  end

(* ============================================================
 * parse_content_length: main entry point
 *
 * Given an HTTP request buffer and header_end offset,
 * find and parse the Content-Length header value.
 * Returns 0 if no Content-Length header found.
 * Returns max_inline_body + 1 if value exceeds limit.
 * ============================================================ *)
val parse_content_length:
  buf: B.buffer U8.t ->
  header_end: U32.t{U32.v header_end <= B.length buf} ->
  Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)

let parse_content_length buf header_end =
  scan_for_content_length buf header_end 0ul
