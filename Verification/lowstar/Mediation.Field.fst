module Mediation.Field
open FStar.HyperStack.ST
module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module F = Mediation.Format

let access_value (h:FStar.HyperStack.mem) (r:F.request) (p:F.policy)
                 (i:nat{i<106}) : GTot U8.t =
 if i=0 then B.get h r 6 else if i=1 then B.get h r 0
 else if i=2 then B.get h r 7 else if i=3 then B.get h r 8
 else if i<68 then B.get h p (i-3)
 else if i<72 then B.get h r (i-67)
 else if i=72 then B.get h r 5 else 0uy

let access_equal (h:FStar.HyperStack.mem) (r:F.request) (p:F.policy)
                 (l:F.login) (i:nat{i<106})
 : Lemma (access_value h r p i == F.expected h r p l 2uy i) = ()

(* The access envelope's 64-byte policy field is copied as one field.  The
   loop has no per-byte source selector or source-record construction. *)
let rec copy_policy (p:F.policy) (e:F.envelope)
                    (i:U32.t{4 <= U32.v i /\ U32.v i <= 68})
 : Stack unit
 (requires fun h -> B.live h p /\ B.live h e /\ B.disjoint e p)
 (ensures fun h0 _ h1 -> B.live h1 e /\ B.modifies (B.loc_buffer e) h0 h1 /\
   (forall j. U32.v i <= j /\ j < 68 ==> B.get h1 e j == B.get h0 p (j-3)) /\
   (forall j. j < U32.v i \/ 68 <= j /\ j < 106 ==> B.get h1 e j == B.get h0 e j))
 (decreases (68 - U32.v i)) =
 if U32.lt i 68ul then (
   let v=B.index p (U32.sub i 3ul) in
   B.upd e i v;
   copy_policy p e (U32.add i 1ul)
 )

let rec clear_tail (e:F.envelope)
                   (i:U32.t{73 <= U32.v i /\ U32.v i <= 106})
 : Stack unit
 (requires fun h -> B.live h e)
 (ensures fun h0 _ h1 -> B.live h1 e /\ B.modifies (B.loc_buffer e) h0 h1 /\
   (forall j. U32.v i <= j /\ j < 106 ==> B.get h1 e j == 0uy) /\
   (forall j. j < U32.v i ==> B.get h1 e j == B.get h0 e j))
 (decreases (106 - U32.v i)) =
 if U32.lt i 106ul then (
   B.upd e i 0uy;
   clear_tail e (U32.add i 1ul)
 )

let build_access (r:F.request) (p:F.policy) (l:F.login) (e:F.envelope)
 : Stack unit
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h e /\
                   B.disjoint e r /\ B.disjoint e p /\ B.disjoint e l)
 (ensures fun h0 _ h1 -> B.live h1 e /\ B.modifies (B.loc_buffer e) h0 h1 /\
   (forall j. j < 106 ==> B.get h1 e j == F.expected h0 r p l 2uy j)) =
 B.upd e 0ul (B.index r 6ul);
 B.upd e 1ul (B.index r 0ul);
 B.upd e 2ul (B.index r 7ul);
 B.upd e 3ul (B.index r 8ul);
 copy_policy p e 4ul;
 B.upd e 68ul (B.index r 1ul);
 B.upd e 69ul (B.index r 2ul);
 B.upd e 70ul (B.index r 3ul);
 B.upd e 71ul (B.index r 4ul);
 B.upd e 72ul (B.index r 5ul);
 clear_tail e 73ul
