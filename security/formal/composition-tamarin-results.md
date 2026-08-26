# M26 composition assurance record

Cross-milestone composition: the first theory where four individually
verified subsystems — M18 possession recovery, M19 share-key bindings,
M20 route gating, and the M23 rotation ladder — share one state machine.
Component proofs do not rule out interaction attacks; this model targets
the seams.

## Modeled interactions

The account's live epoch is a single linear token (`CurrentEpoch`) that
every subsystem consumes and re-emits:

- **Setup / re-mint** stages the blind possession commitment for the live
  epoch (`StageCommitment`).
- **Rotation** (M23 ladder) consumes the epoch token and advances it —
  implicitly destroying everything bound to the old epoch: outstanding
  possession challenges, grants, commitments, and web-session validity.
- **M18 recovery chain** — challenge → possession grant → enrollment — each
  step requires `CurrentEpoch(E)` to still be live, so every link in the
  chain is stranded by an intervening rotation.
- **M19 share-key registration** requires an onboarded device of the
  account; a recovered device onboards through its epoch-bound grant, never
  around it.
- **M20 web-session pass-through** requires the session's bound epoch to
  equal the live epoch at *every* vault action.

## Proven properties (8/8 verified)

Recovery-chain provenance:
- `possession_grant_requires_staged_commitment`
- `challenge_requires_staged_commitment`
- `enrollment_requires_possession_grant`

Rotation stranding (the composition payoff):
- `grants_cannot_outlive_their_rotation` — no possession grant is issued
  after its epoch's rotation consumed the epoch token.
- `enrollments_cannot_outlive_their_rotation` — same bound for recovered-
  device enrollment.
- `web_actions_cannot_outlive_their_rotation` — a live web session cannot
  perform a single vault action after rotation strands its bound epoch.

Share-key provenance:
- `share_key_registration_requires_onboarded_device` — every registration
  traces to an onboarded device of the account (setup or recovered
  enrollment); there is no path from "knows the commitment" to "registers a
  key" without the full recovery ladder.

Availability:
- `full_composition_reachable` — setup → commitment → possession grant →
  recovered enrollment → share-key registration → web-session grant →
  vault pass-through, all in one trace.

## Verification output

```text
m26_composition: 8 verified
m26 composition formal proof gate: 8 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-composition-proofs.sh
```
