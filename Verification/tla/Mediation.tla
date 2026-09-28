---------------------------- MODULE Mediation ----------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANT Mutation
Kinds == {"public", "login", "access", "update"}
Roles == {0, 1, 2}
Empty == [id |-> 0, kind |-> "public", role |-> 0, rate |-> 0,
          body |-> 0, policy |-> 0]
VARIABLES phase, req, ticket, accepted, effects, policy, nextId, altered
vars == <<phase, req, ticket, accepted, effects, policy, nextId, altered>>
Allowed(r) == r.rate < 50 /\
  CASE r.kind = "public" -> TRUE
    [] r.kind = "login" -> r.body = 1
    [] r.kind = "update" -> r.role = 2
    [] OTHER -> r.role = 2 \/ (r.role = 1 /\ r.policy = 1)
Init == /\ phase = "idle" /\ req = Empty /\ ticket = Empty
        /\ accepted = FALSE /\ effects = <<>> /\ policy = 0
        /\ nextId = 1 /\ altered = FALSE
Begin == /\ phase = "idle" /\ nextId <= 2
         /\ \E k \in Kinds, r \in Roles, rate \in {0,50}, b \in {0,1}:
               req' = [id |-> nextId, kind |-> k, role |-> r,
                       rate |-> rate, body |-> b, policy |-> policy]
         /\ phase' = "ready" /\ altered' = FALSE
         /\ IF Mutation = "stale" THEN UNCHANGED <<ticket, accepted>>
            ELSE /\ ticket' = Empty /\ accepted' = FALSE
         /\ UNCHANGED <<effects, policy, nextId>>
Check == /\ phase = "ready"
         /\ ticket' = req /\ accepted' = Allowed(req)
         /\ phase' = "checked"
         /\ UNCHANGED <<req, effects, policy, nextId, altered>>
Alter == /\ phase = "checked" /\ ~altered
         /\ Mutation \in {"wrong_request", "wrong_candidate"}
         /\ (Mutation = "wrong_candidate" => req.kind = "update")
         /\ req' = [req EXCEPT !.body = 1 - @]
         /\ altered' = TRUE
         /\ UNCHANGED <<phase, ticket, accepted, effects, policy, nextId>>
Dispatch == /\ (phase = "checked" /\ (accepted \/ Mutation = "ignore_deny"))
                \/ (phase = "ready" /\ Mutation = "bypass")
                \/ (phase = "ready" /\ Mutation = "stale" /\ accepted)
                \/ (phase = "done" /\ Mutation = "replay" /\ accepted /\ Len(effects)<3)
            /\ effects' = Append(effects,
                 [request |-> req, checked |-> ticket, ok |-> accepted])
            /\ policy' = IF req.kind = "update" THEN req.body ELSE policy
            /\ phase' = "done"
            /\ UNCHANGED <<req, ticket, accepted, nextId, altered>>
Reject == /\ phase \in {"ready", "checked"}
          /\ phase' = "done"
          /\ UNCHANGED <<req, ticket, accepted, effects, policy, nextId, altered>>
Finish == /\ phase = "done" /\ phase' = "idle" /\ nextId' = nextId+1
          /\ UNCHANGED <<req, ticket, accepted, effects, policy, altered>>
Next == Begin \/ Check \/ Alter \/ Dispatch \/ Reject \/ Finish
Spec == Init /\ [][Next]_vars
Mediated == \A i \in 1..Len(effects):
             /\ effects[i].ok
             /\ effects[i].checked = effects[i].request
             /\ Allowed(effects[i].request)
Once == \A i,j \in 1..Len(effects):
          effects[i].request.id = effects[j].request.id => i=j
PolicyCommit == \A i \in 1..Len(effects):
                  effects[i].request.kind = "update" => effects[i].request.role = 2
=============================================================================
