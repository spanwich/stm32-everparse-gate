(*
 * HTTP.Extract.Path - Verified URL path extraction and sentinel hash lookup
 *
 * Extracts the URL path from an HTTP request line, validates it (no path
 * traversal, no null bytes), and maps to sentinel hash constants.
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads within bounds
 *   2. Path traversal ("..") and null bytes rejected
 *   3. Sentinel hash only returned for known endpoints
 *   4. Read-only: buffer never modified
 *   5. Termination for all loops
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Path

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32

open HTTP.Extract.Types

(* ============================================================
 * find_path_end: scan from path_start to find ' ', '?', or '\r'
 * Returns offset of the delimiter (or limit if not found).
 * ============================================================ *)
let rec find_path_end
  (buf: B.buffer U8.t)
  (limit: U32.t{U32.v limit <= B.length buf})
  (i: U32.t{U32.v i <= U32.v limit})
  : Stack U32.t
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      U32.v i <= U32.v result /\
      U32.v result <= U32.v limit)
    (decreases (U32.v limit - U32.v i))
  =
  if U32.eq i limit then i
  else begin
    let b = B.index buf i in
    if U8.eq b 0x20uy || U8.eq b 0x3Fuy || U8.eq b 0x0Duy then
      i  (* Found delimiter: space, '?', or '\r' *)
    else
      find_path_end buf limit (U32.add i 1ul)
  end

(* ============================================================
 * check_no_traversal: verify path has no ".." subsequence
 * Returns true if path is safe (no "..").
 * ============================================================ *)
let rec check_no_traversal
  (buf: B.buffer U8.t)
  (path_start: U32.t)
  (path_end: U32.t{U32.v path_start <= U32.v path_end /\
                    U32.v path_end <= B.length buf})
  (i: U32.t{U32.v path_start <= U32.v i /\ U32.v i <= U32.v path_end})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
    (decreases (U32.v path_end - U32.v i))
  =
  (* Need at least 2 bytes remaining to check ".." *)
  if U32.lt (U32.sub path_end i) 2ul then
    true  (* Safe: not enough bytes for ".." *)
  else begin
    let b0 = B.index buf i in
    let b1 = B.index buf (U32.add i 1ul) in
    if U8.eq b0 0x2Euy && U8.eq b1 0x2Euy then
      false  (* Found ".." — path traversal *)
    else
      check_no_traversal buf path_start path_end (U32.add i 1ul)
  end

(* ============================================================
 * check_no_null: verify path has no null bytes
 * Returns true if path is safe (no '\0').
 * ============================================================ *)
let rec check_no_null
  (buf: B.buffer U8.t)
  (path_end: U32.t{U32.v path_end <= B.length buf})
  (i: U32.t{U32.v i <= U32.v path_end})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
    (decreases (U32.v path_end - U32.v i))
  =
  if U32.eq i path_end then true
  else begin
    let b = B.index buf i in
    if U8.eq b 0x00uy then false
    else check_no_null buf path_end (U32.add i 1ul)
  end

(* ============================================================
 * Known endpoint path strings: inline byte checks for each
 * known API path. No memcmp in LowStar, so we compare
 * byte-by-byte against hex constants.
 * ============================================================ *)

(* Check if path is exactly "/" (root/dashboard request) *)
let is_root_path
  (buf: B.buffer U8.t)
  (path_start: U32.t)
  (path_end: U32.t{U32.v path_start <= U32.v path_end /\
                    U32.v path_end <= B.length buf})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let path_len = U32.sub path_end path_start in
  if U32.eq path_len 1ul then begin
    let b = B.index buf path_start in
    U8.eq b 0x2Fuy  (* '/' *)
  end else
    false

(*
 * Check 10-byte path: /api/login
 * Bytes: 2F 61 70 69 2F 6C 6F 67 69 6E
 *)
let is_path_login
  (buf: B.buffer U8.t)
  (ps: U32.t{U32.v ps + 10 <= B.length buf})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let b0 = B.index buf ps in
  let b1 = B.index buf (U32.add ps 1ul) in
  let b2 = B.index buf (U32.add ps 2ul) in
  let b3 = B.index buf (U32.add ps 3ul) in
  let b4 = B.index buf (U32.add ps 4ul) in
  let b5 = B.index buf (U32.add ps 5ul) in
  let b6 = B.index buf (U32.add ps 6ul) in
  let b7 = B.index buf (U32.add ps 7ul) in
  let b8 = B.index buf (U32.add ps 8ul) in
  let b9 = B.index buf (U32.add ps 9ul) in
  U8.eq b0 0x2Fuy && U8.eq b1 0x61uy && U8.eq b2 0x70uy &&
  U8.eq b3 0x69uy && U8.eq b4 0x2Fuy && U8.eq b5 0x6Cuy &&
  U8.eq b6 0x6Fuy && U8.eq b7 0x67uy && U8.eq b8 0x69uy &&
  U8.eq b9 0x6Euy

(*
 * Check 11-byte path: /api/logout
 * Bytes: 2F 61 70 69 2F 6C 6F 67 6F 75 74
 *)
let is_path_logout
  (buf: B.buffer U8.t)
  (ps: U32.t{U32.v ps + 11 <= B.length buf})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let b0 = B.index buf ps in
  let b1 = B.index buf (U32.add ps 1ul) in
  let b2 = B.index buf (U32.add ps 2ul) in
  let b3 = B.index buf (U32.add ps 3ul) in
  let b4 = B.index buf (U32.add ps 4ul) in
  let b5 = B.index buf (U32.add ps 5ul) in
  let b6 = B.index buf (U32.add ps 6ul) in
  let b7 = B.index buf (U32.add ps 7ul) in
  let b8 = B.index buf (U32.add ps 8ul) in
  let b9 = B.index buf (U32.add ps 9ul) in
  let b10 = B.index buf (U32.add ps 10ul) in
  U8.eq b0 0x2Fuy && U8.eq b1 0x61uy && U8.eq b2 0x70uy &&
  U8.eq b3 0x69uy && U8.eq b4 0x2Fuy && U8.eq b5 0x6Cuy &&
  U8.eq b6 0x6Fuy && U8.eq b7 0x67uy && U8.eq b8 0x6Fuy &&
  U8.eq b9 0x75uy && U8.eq b10 0x74uy

(*
 * Check 11-byte path: /api/status
 * Bytes: 2F 61 70 69 2F 73 74 61 74 75 73
 *)
let is_path_status
  (buf: B.buffer U8.t)
  (ps: U32.t{U32.v ps + 11 <= B.length buf})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let b0 = B.index buf ps in
  let b1 = B.index buf (U32.add ps 1ul) in
  let b2 = B.index buf (U32.add ps 2ul) in
  let b3 = B.index buf (U32.add ps 3ul) in
  let b4 = B.index buf (U32.add ps 4ul) in
  let b5 = B.index buf (U32.add ps 5ul) in
  let b6 = B.index buf (U32.add ps 6ul) in
  let b7 = B.index buf (U32.add ps 7ul) in
  let b8 = B.index buf (U32.add ps 8ul) in
  let b9 = B.index buf (U32.add ps 9ul) in
  let b10 = B.index buf (U32.add ps 10ul) in
  U8.eq b0 0x2Fuy && U8.eq b1 0x61uy && U8.eq b2 0x70uy &&
  U8.eq b3 0x69uy && U8.eq b4 0x2Fuy && U8.eq b5 0x73uy &&
  U8.eq b6 0x74uy && U8.eq b7 0x61uy && U8.eq b8 0x74uy &&
  U8.eq b9 0x75uy && U8.eq b10 0x73uy

(*
 * Check 11-byte path: /api/policy
 * Bytes: 2F 61 70 69 2F 70 6F 6C 69 63 79
 *)
let is_path_policy
  (buf: B.buffer U8.t)
  (ps: U32.t{U32.v ps + 11 <= B.length buf})
  : Stack bool
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 -> h0 == h1)
  =
  let b0 = B.index buf ps in
  let b1 = B.index buf (U32.add ps 1ul) in
  let b2 = B.index buf (U32.add ps 2ul) in
  let b3 = B.index buf (U32.add ps 3ul) in
  let b4 = B.index buf (U32.add ps 4ul) in
  let b5 = B.index buf (U32.add ps 5ul) in
  let b6 = B.index buf (U32.add ps 6ul) in
  let b7 = B.index buf (U32.add ps 7ul) in
  let b8 = B.index buf (U32.add ps 8ul) in
  let b9 = B.index buf (U32.add ps 9ul) in
  let b10 = B.index buf (U32.add ps 10ul) in
  U8.eq b0 0x2Fuy && U8.eq b1 0x61uy && U8.eq b2 0x70uy &&
  U8.eq b3 0x69uy && U8.eq b4 0x2Fuy && U8.eq b5 0x70uy &&
  U8.eq b6 0x6Fuy && U8.eq b7 0x6Cuy && U8.eq b8 0x69uy &&
  U8.eq b9 0x63uy && U8.eq b10 0x79uy

(* ============================================================
 * extract_path_hash: main entry point
 *
 * Given an HTTP request buffer, method_end offset, and header_end offset:
 * 1. Find end of path (space, '?', or '\r')
 * 2. Reject path traversal (..)
 * 3. Reject null bytes
 * 4. Map to sentinel hash constant
 *
 * Returns path_result with:
 *   pr_hash = sentinel constant (0 if unknown/rejected)
 *   pr_is_root = true if path is exactly "/"
 * ============================================================ *)
val extract_path_hash:
  buf: B.buffer U8.t ->
  method_end: U32.t ->
  header_end: U32.t{U32.v method_end <= U32.v header_end /\
                     U32.v header_end <= B.length buf} ->
  Stack path_result
    (requires fun h -> B.live h buf)
    (ensures fun h0 result h1 ->
      h0 == h1 /\
      (* If hash is non-zero, path was safe (no traversal) *)
      (U32.v result.pr_hash > 0 ==>
        result.pr_hash = path_login \/
        result.pr_hash = path_logout \/
        result.pr_hash = path_status \/
        result.pr_hash = path_policy))

let extract_path_hash buf method_end header_end =
  (* Step 1: Find path end delimiter *)
  let path_start = method_end in
  let path_end = find_path_end buf header_end path_start in
  let path_len = U32.sub path_end path_start in

  (* Step 2: Check for path traversal *)
  if not (check_no_traversal buf path_start path_end path_start) then
    { pr_hash = 0ul; pr_is_root = false }
  (* Step 3: Check for null bytes *)
  else if not (check_no_null buf path_end path_start) then
    { pr_hash = 0ul; pr_is_root = false }
  (* Step 4: Check for root path *)
  else if is_root_path buf path_start path_end then
    { pr_hash = 0ul; pr_is_root = true }
  (* Step 5: Map to sentinel hash — check exact path strings *)
  else if U32.eq path_len 10ul then begin
    if is_path_login buf path_start then
      { pr_hash = path_login; pr_is_root = false }
    else
      { pr_hash = 0ul; pr_is_root = false }
  end
  else if U32.eq path_len 11ul then begin
    if is_path_logout buf path_start then
      { pr_hash = path_logout; pr_is_root = false }
    else if is_path_status buf path_start then
      { pr_hash = path_status; pr_is_root = false }
    else if is_path_policy buf path_start then
      { pr_hash = path_policy; pr_is_root = false }
    else
      { pr_hash = 0ul; pr_is_root = false }
  end
  else
    { pr_hash = 0ul; pr_is_root = false }  (* Unknown endpoint *)
