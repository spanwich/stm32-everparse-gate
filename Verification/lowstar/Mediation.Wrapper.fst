module Mediation.Wrapper
open FStar.HyperStack.ST
module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module F = Mediation.Format
module E = Mediation.Extern

type result = { invoked:bool; status:U32.t }
let run (k:F.kind) (n:U32.t{U32.v n<=106})
        (r:F.request) (p:F.policy) (l:F.login) (ctx:F.context) (e:F.envelope)
 : Stack result
 (requires fun h -> B.live h r /\ B.live h p /\ B.live h l /\ B.live h ctx /\ E.context_object ctx /\
   E.input_valid (B.as_seq h r) (B.as_seq h p) /\
   B.disjoint ctx r /\ B.disjoint ctx p /\ B.disjoint ctx l /\
   B.live h e /\ B.disjoint e ctx /\ B.disjoint e r /\ B.disjoint e p /\ B.disjoint e l)
 (ensures fun h0 v h1 -> B.live h1 ctx /\ B.modifies (B.loc_union (B.loc_buffer ctx) (B.loc_buffer e)) h0 h1 /\
   (v.invoked ==> E.authorized k n (B.as_seq h0 r) (B.as_seq h0 p) (B.as_seq h0 l)) /\
   (~v.invoked ==> B.as_seq h1 ctx == B.as_seq h0 ctx)) =
 let h0 = get () in
 F.build r p l k e;
 let hb = get () in
 assert (B.as_seq h0 r == B.as_seq hb r /\ B.as_seq h0 p == B.as_seq hb p /\ B.as_seq h0 l == B.as_seq hb l);
 let ok = E.check k n r p l e in
 let answer = if ok then
   let status=E.invoke k n r p l ctx in
   {invoked=true;status=status}
 else {invoked=false;status=403ul} in
 let h2 = get () in
 assert (answer.invoked ==> E.authorized k n (B.as_seq h0 r) (B.as_seq h0 p) (B.as_seq h0 l));
 assert (~answer.invoked ==> B.as_seq h2 ctx == B.as_seq h0 ctx);
 answer
