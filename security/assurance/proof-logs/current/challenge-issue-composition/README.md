# GET /auth/challenge: issue/consumer composition

## Claim

`Vela_session_policy_challenge_issue_composition` composes the extracted issue
driver with the shared one-shot take used by the three consumers
(`/auth/verify`, `/device/enroll`, `/web-session/:id/token`). A schedule is an
arbitrary finite interleaving of issue requests/events, consumer takes for one
of the three purposes, and failed takes. For every schedule:

```fstar
let w = run_world initial schedule in
all_keys_ok w.w_keys /\
all_issues_sound w.w_issues /\
ids_below w.w_keys w.w_next_key
```

`all_keys_ok` carries the headline facts:

- every issued key has exactly one purpose and at most one consuming request
  (`k_consumed` is an option, and a key cannot be present with a recorded
  consumption);
- an accepted take records its expected purpose, and that purpose equals the
  key's own purpose;
- a wrong-purpose take spends the key but never accepts it;
- a key is absent after any consumption and no second take can change it.

`ids_below` proves ids are allocated fresh: a new key is added with the current
allocator value and the allocator increments, so two issues never share a key.
The general issue step is proved in `world_step_inv`; it adds exactly one key
when the extracted transition emits `Issue`. Reachability witnesses show a
successful own-purpose take, a second take yielding nothing, a wrong-purpose
take that is spent, a failed take leaving the key for a later success, and
distinct allocator ids.

## Scope and the take decision

The composition calls the actual extracted `classify_consumption` on the key's
stored purpose tag (`purpose_stored_tag`). The production `consume_challenge`
uses the same decision after `get_del`; the byte conversion from `Vec<u8>` to
the bounded tag and the login consumer's full driver composition are checked in
the existing `challenge-take-adapter` / `login-*` evidence. This module models
the shared nonce boundary, not the consumers' later stages.

## Mutation

`mutation-1.diff` changes the modelled take to leave the key present after
consumption. `world_step_inv` / `all_keys_ok` fail (`mutation-1.log`). The
mutant is a copy under `/tmp/vela-f2-account-a-mut/`, never committed.

## Assumptions and non-claims

- `get_del` is linearizable and removes the value in the same atomic step; a
  failed `get_del` leaves it in place (modelled by `TakeFailed`).
- Consumer requests present one of the three purposes; their later device,
  verifier and token stages are separate drivers.
- Sled durability, TTL expiry, crash/retry and multi-node replication remain
  outside the model.
- The hax models and solver remain trusted.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-challenge-issue-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-challenge-issue-composition.sh
```

`composition-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
