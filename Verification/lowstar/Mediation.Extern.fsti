module Mediation.Extern
open FStar.HyperStack.ST
open FStar.Mul
module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module S = FStar.Seq
module F = Mediation.Format

(* Caller-side C obligations: ctx covers a complete aligned GatewayContext,
   with its actual target ABI size (8860 on ARM, 8864 on this host). The bridge
   checks supported sizes. This is not evidence of caller verification:
   gateway_mediate is explicitly trusted. *)
val context_object: F.context -> GTot Type0
let input_valid (r:S.seq U8.t{S.length r=1536})
                (p:S.seq U8.t{S.length p=65}) : GTot Type0 =
 let byte i = U8.v (S.index r i) in
 let body_length = byte 171 + 256 * byte 172 + 65536 * byte 173 + 16777216 * byte 174 in
 body_length <= 1361 /\ byte 9 <= 32 /\ byte 42 <= 128 /\
 byte 6 <= 2 /\
 (byte 5 = 1 \/ byte 5 = 2 \/ byte 5 = 4 \/ byte 5 = 8 \/ byte 5 = 16 \/ byte 5 = 32) /\
 1 <= U8.v (S.index p 0) /\ U8.v (S.index p 0) <= 8

(* Explicit trusted boundary, not a proved implementation. authorized means the
   corresponding real EverParse validator accepts F.expected for these exact
   snapshots and length. Authentication and HTTP interpretation are upstream. *)
val authorized: F.kind -> U32.t -> S.seq U8.t -> S.seq U8.t -> S.seq U8.t -> GTot Type0

val check: k:F.kind -> n:U32.t{U32.v n<=106} ->
 r:F.request -> p:F.policy -> l:F.login -> e:F.envelope ->
 Stack bool
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h e /\
   input_valid (B.as_seq h r) (B.as_seq h p) /\
   (forall j. j<106 ==> B.get h e j == F.expected h r p l k j))
 (ensures fun h0 ok h1 -> h0==h1 /\
   (ok ==> authorized k n (B.as_seq h0 r) (B.as_seq h0 p) (B.as_seq h0 l)))

(* Only response/context storage may be changed. A handler must act on the
   supplied snapshots, perform at most its one selected operation, and must not
   retain references. These leaf semantics are trusted, separately audited. *)
val invoke: k:F.kind -> n:U32.t{U32.v n<=106} ->
 r:F.request -> p:F.policy -> l:F.login -> ctx:F.context ->
 Stack U32.t
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h ctx /\ context_object ctx /\
   input_valid (B.as_seq h r) (B.as_seq h p) /\
   B.disjoint ctx r /\ B.disjoint ctx p /\ B.disjoint ctx l /\
   authorized k n (B.as_seq h r) (B.as_seq h p) (B.as_seq h l))
 (ensures fun h0 _ h1 -> B.live h1 ctx /\ B.modifies (B.loc_buffer ctx) h0 h1)
