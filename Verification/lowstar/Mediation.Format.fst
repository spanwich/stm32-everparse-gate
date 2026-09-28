module Mediation.Format
open FStar.HyperStack.ST
module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module S = FStar.Seq
module Cast = FStar.Int.Cast

type kind = k:U8.t{U8.v k <= 3}
type request = b:B.buffer U8.t{B.length b = 1536}
type policy = b:B.buffer U8.t{B.length b = 65}
type login = b:B.buffer U8.t{B.length b = 106}
type context = b:B.buffer U8.t{B.length b = 8860 \/ B.length b = 8864}
type envelope = b:B.buffer U8.t{B.length b = 106}
type source = { which: U8.t; offset: U32.t; literal: U8.t }
let zero = {which=0uy;offset=0ul;literal=0uy}
let req (i:U32.t) = {which=1uy;offset=i;literal=0uy}
let pol (i:U32.t) = {which=2uy;offset=i;literal=0uy}
let cred (i:U32.t) = {which=3uy;offset=i;literal=0uy}
let lit (x:U8.t) = {which=0uy;offset=0ul;literal=x}

(* The reference AccessRequest evaluates all eight slots. Unused slots carry
   INACTIVE_PATH_ID=0xDEADDEAD and method=0. For the access path, policy holds
   all eight uploaded slots exactly; count is metadata, not a match bound.
   Public slots are fixed, not supplied by the mutable policy. *)
let inactive (i:U32.t{4 <= U32.v i /\ U32.v i < 68}) : Tot source =
 let slotbyte=U32.rem (U32.sub i 4ul) 8ul in
 if slotbyte=0ul || slotbyte=2ul then lit 0xaduy
 else if slotbyte=1ul || slotbyte=3ul then lit 0xdeuy
 else zero

let select (k:kind) (count:U8.t) (i:U32.t{U32.v i < 106})
 : Tot (s:source{(s.which=1uy ==> U32.v s.offset < 1536) /\
                 (s.which=2uy ==> U32.v s.offset < 65) /\
                 (s.which=3uy ==> U32.v s.offset < 106)}) =
 if k=3uy then
   if i=0ul then req 6ul else if i=1ul then req 0ul
   else if U32.lt i 67ul then req (U32.add i 173ul) else zero
 else if k=1uy then
   if i=0ul then req 6ul else if i=1ul then req 0ul
   else if U32.lt i 6ul then req (U32.sub i 1ul)
   else if i=6ul then req 5ul else if i=7ul then zero else cred i
 else
   if U32.lt i 4ul then
     if k=0uy then zero
     else if i=0ul then req 6ul else if i=1ul then req 0ul
     else req (U32.add i 5ul)
   else if U32.lt i 68ul then
     if k=0uy then
       if U32.lt i 20ul then
         let slotbyte=U32.rem (U32.sub i 4ul) 8ul in
         if U32.lt slotbyte 4ul then lit (if U32.lt i 12ul then 0x66uy else 0x77uy)
         else if slotbyte=4ul then lit 1uy else zero
       else inactive i
     else pol (U32.sub i 3ul)
   else if U32.lt i 72ul then req (U32.sub i 67ul)
   else if i=72ul then req 5ul else zero

let expected (h:FStar.HyperStack.mem) (r:request) (p:policy) (l:login)
             (k:kind) (i:nat{i<106}) : GTot U8.t =
 let s=select k (B.get h p 0) (U32.uint_to_t i) in
 if s.which=1uy then B.get h r (U32.v s.offset)
 else if s.which=2uy then B.get h p (U32.v s.offset)
 else if s.which=3uy then B.get h l (U32.v s.offset) else s.literal

let read (r:request) (p:policy) (l:login) (k:kind) (i:U32.t{U32.v i<106})
 : Stack U8.t
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l)
 (ensures fun h0 v h1 -> h0==h1 /\ v==expected h0 r p l k (U32.v i)) =
 let count=B.index p 0ul in
 let s=select k count i in
 if s.which=1uy then B.index r s.offset
 else if s.which=2uy then B.index p s.offset
 else if s.which=3uy then B.index l s.offset else s.literal

let rec build_from (r:request) (p:policy) (l:login) (k:kind) (e:envelope)
                   (i:U32.t{U32.v i<=106})
 : Stack unit
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h e /\
                   B.disjoint e r /\ B.disjoint e p /\ B.disjoint e l)
 (ensures fun h0 _ h1 -> B.live h1 e /\ B.modifies (B.loc_buffer e) h0 h1 /\
   (forall j. U32.v i <= j /\ j < 106 ==> B.get h1 e j == expected h0 r p l k j) /\
   (forall j. j < U32.v i ==> B.get h1 e j == B.get h0 e j))
 (decreases (106 - U32.v i)) =
 if U32.lt i 106ul then (
   let v=read r p l k i in
   B.upd e i v;
   build_from r p l k e (U32.add i 1ul)
 )

let build (r:request) (p:policy) (l:login) (k:kind) (e:envelope)
 : Stack unit
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h e /\
                   B.disjoint e r /\ B.disjoint e p /\ B.disjoint e l)
 (ensures fun h0 _ h1 -> B.live h1 e /\ B.modifies (B.loc_buffer e) h0 h1 /\
   (forall j. j < 106 ==> B.get h1 e j == expected h0 r p l k j)) =
 build_from r p l k e 0ul
