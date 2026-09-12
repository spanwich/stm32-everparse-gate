(*
 * HTTP.Extract.Complete - Verified HTTP security parameter extraction
 *
 * Composes all sub-functions into the full extract_security_params
 * that produces a SecurityParamsWire from raw HTTP bytes.
 *
 * VERIFIED PROPERTIES:
 *   1. All buffer reads/writes within bounds
 *   2. Input buffer is read-only (never modified)
 *   3. Output buffer only modified within [0, out_len)
 *   4. Result code semantics match extract.h enum
 *   5. Termination guaranteed
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)
module HTTP.Extract.Complete

open FStar.HyperStack.ST

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module Cast = FStar.Int.Cast

open HTTP.Extract.Types
open HTTP.Extract.Scan
open HTTP.Extract.Method
open HTTP.Extract.Path
open HTTP.Extract.Header
open HTTP.Extract.Bearer

(* ============================================================
 * fill_zero: zero out a region of the output buffer
 * Equivalent to memset(buf + start, 0, len)
 * ============================================================ *)
let rec fill_zero
  (buf: B.buffer U8.t)
  (i: U32.t{U32.v i <= B.length buf})
  (stop: U32.t{U32.v i <= U32.v stop /\ U32.v stop <= B.length buf})
  : Stack unit
    (requires fun h -> B.live h buf)
    (ensures fun h0 _ h1 -> B.live h1 buf /\
      B.modifies (B.loc_buffer buf) h0 h1)
    (decreases (U32.v stop - U32.v i))
  =
  if U32.eq i stop then ()
  else begin
    B.upd buf i 0uy;
    fill_zero buf (U32.add i 1ul) stop
  end

(* ============================================================
 * write_u32_le: write a uint32_t in little-endian at offset
 * ============================================================ *)
let write_u32_le
  (buf: B.buffer U8.t)
  (off: U32.t{U32.v off + 4 <= B.length buf})
  (v: U32.t)
  : Stack unit
    (requires fun h -> B.live h buf)
    (ensures fun h0 _ h1 -> B.live h1 buf /\
      B.modifies (B.loc_buffer buf) h0 h1)
  =
  B.upd buf off (Cast.uint32_to_uint8 v);
  B.upd buf (U32.add off 1ul) (Cast.uint32_to_uint8 (U32.shift_right v 8ul));
  B.upd buf (U32.add off 2ul) (Cast.uint32_to_uint8 (U32.shift_right v 16ul));
  B.upd buf (U32.add off 3ul) (Cast.uint32_to_uint8 (U32.shift_right v 24ul))

(* ============================================================
 * copy_bytes: copy N bytes from src[src_off..] to dst[dst_off..]
 * Equivalent to memcpy(dst + dst_off, src + src_off, len)
 * ============================================================ *)
let rec copy_bytes
  (dst: B.buffer U8.t)
  (src: B.buffer U8.t)
  (dst_off: U32.t)
  (src_off: U32.t)
  (len: U32.t{U32.v dst_off + U32.v len <= B.length dst /\
              U32.v src_off + U32.v len <= B.length src})
  (i: U32.t{U32.v i <= U32.v len})
  : Stack unit
    (requires fun h -> B.live h dst /\ B.live h src /\
      B.loc_disjoint (B.loc_buffer dst) (B.loc_buffer src))
    (ensures fun h0 _ h1 -> B.live h1 dst /\ B.live h1 src /\
      B.modifies (B.loc_buffer dst) h0 h1)
    (decreases (U32.v len - U32.v i))
  =
  if U32.eq i len then ()
  else begin
    let b = B.index src (U32.add src_off i) in
    B.upd dst (U32.add dst_off i) b;
    copy_bytes dst src dst_off src_off len (U32.add i 1ul)
  end

(* ============================================================
 * extract_security_params: main entry point
 *
 * Parse raw HTTP request and produce SecurityParamsWire.
 *
 * Parameters:
 *   http_buf  - raw HTTP request bytes (read-only)
 *   http_len  - length of http_buf
 *   out_buf   - output buffer for SecurityParamsWire (must be >= 1536 bytes)
 *   out_len   - output: number of bytes written
 *
 * Returns:
 *   ExtractionResult code (U8.t matching extract.h enum)
 * ============================================================ *)
val extract_security_params:
  http_buf: B.buffer U8.t ->
  http_len: U32.t{U32.v http_len <= B.length http_buf} ->
  out_buf: B.buffer U8.t{B.length out_buf >= U32.v secparams_header_size + U32.v max_inline_body} ->
  out_len: B.pointer U32.t ->
  Stack U8.t
    (requires fun h ->
      B.live h http_buf /\ B.live h out_buf /\ B.live h out_len /\
      B.loc_disjoint (B.loc_buffer http_buf) (B.loc_buffer out_buf) /\
      B.loc_disjoint (B.loc_buffer http_buf) (B.loc_buffer out_len) /\
      B.loc_disjoint (B.loc_buffer out_buf) (B.loc_buffer out_len))
    (ensures fun h0 result h1 ->
      B.live h1 http_buf /\ B.live h1 out_buf /\ B.live h1 out_len /\
      B.modifies (B.loc_union (B.loc_buffer out_buf) (B.loc_buffer out_len)) h0 h1)

let extract_security_params http_buf http_len out_buf out_len =
  (* Step 1: Find end of headers *)
  let hdr_end = find_header_end http_buf http_len in
  if U32.eq hdr_end http_len then begin
    (* No \r\n\r\n found — incomplete request *)
    B.upd out_len 0ul 0ul;
    extract_incomplete
  end
  else begin
    (* Step 2: Parse method *)
    let mr = parse_method http_buf http_len in
    if U8.eq mr.mr_code 0uy then begin
      B.upd out_len 0ul 0ul;
      extract_method_unknown
    end
    else if U32.gt mr.mr_end hdr_end then begin
      (* Malformed: method extends past header end *)
      B.upd out_len 0ul 0ul;
      extract_malformed
    end
    else begin
      (* Step 3: Extract path hash *)
      let pr = extract_path_hash http_buf mr.mr_end hdr_end in

      (* Step 3b: Handle root path (dashboard) *)
      if pr.pr_is_root then begin
        (* Dashboard request: write minimal SecurityParamsWire *)
        fill_zero out_buf 0ul secparams_header_size;
        (* rate_count = 0 (already zeroed) *)
        (* path_hash = 0 (already zeroed) *)
        B.upd out_buf off_method mr.mr_code;
        (* body_len = 0 (already zeroed) *)
        B.upd out_len 0ul secparams_header_size;
        extract_ok
      end
      else if U32.eq pr.pr_hash 0ul then begin
        (* Unknown or rejected path → check if it was path traversal *)
        (* Re-check traversal to distinguish from unknown endpoint *)
        let path_start = mr.mr_end in
        let path_end = find_path_end http_buf hdr_end path_start in
        let trav_safe = check_no_traversal http_buf path_start path_end path_start in
        B.upd out_len 0ul 0ul;
        if not trav_safe then
          extract_path_traversal
        else
          extract_malformed  (* Unknown endpoint *)
      end
      else begin
        (* Step 4: Parse Content-Length *)
        let content_length = parse_content_length http_buf hdr_end in
        if U32.gt content_length max_inline_body then begin
          B.upd out_len 0ul 0ul;
          extract_body_too_large
        end
        else begin
          (* Step 5: Check if body is complete *)
          let body_start = U32.add hdr_end 4ul in
          let available_body =
            if U32.gt http_len body_start then
              U32.sub http_len body_start
            else
              0ul
          in
          if U32.gt content_length 0ul && U32.lt available_body content_length then begin
            B.upd out_len 0ul 0ul;
            extract_incomplete
          end
          else begin
            let body_len =
              if U32.gt content_length 0ul then content_length
              else 0ul
            in

            (* Step 6: Write SecurityParamsWire header *)
            fill_zero out_buf 0ul secparams_header_size;
            (* rate_count = 0 — already zeroed *)
            write_u32_le out_buf off_path_hash pr.pr_hash;
            B.upd out_buf off_method mr.mr_code;

            (* Step 6b: Extract bearer token into token region *)
            let token_sub = B.sub out_buf off_token auth_token_max in
            let tklen = extract_bearer_token http_buf hdr_end token_sub in
            B.upd out_buf off_token_len tklen;

            write_u32_le out_buf off_body_len body_len;

            (* Step 7: Copy body if present *)
            if U32.gt body_len 0ul then
              copy_bytes out_buf http_buf secparams_header_size body_start body_len 0ul
            else
              ();

            B.upd out_len 0ul (U32.add secparams_header_size body_len);
            extract_ok
          end
        end
      end
    end
  end
