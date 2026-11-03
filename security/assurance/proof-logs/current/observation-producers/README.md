# Observation producers consumed by the verified policy crates

Plan step **O1** (F-1 observation origins). Read-only inventory: this log
records, for every observation/fact/view struct that an extracted driver,
interpreter or executor in `serverVELA/vela-*-policy/src` consumes from the
handler side, which server code produces each field and whether an existing
proof covers that producer.

Scope: `serverVELA/vela-*-policy/src` types ending in `Facts`, `Observation`,
`View`, `Verdict`, `Row` or `Snapshot`, plus the `*_model.rs` input rows are
*excluded* (those are F* store-model mirrors, not handler observations).
Bare-`enum` observation types (for example `DeviceObservation`, `ProbeObservation`)
carry no fields; they are listed at the end of each area when their payload is a
decision input.

Method: every `pub struct` with those suffixes was extracted from the eight
policy crates, then `vela-server/src` was grepped for each struct literal /
decoder; each constructor, row decoder, classifier and call site was read and
the field expression or column index recorded. The companion
`observation-producers.json` carries the same rows for tooling.

Totals: **134 struct types, 565 fields, 96 fields whose producer is fully open, and 116 more whose mapping is proved but whose origin has an open part**.

Producer kinds: SQL row, store lookup, signature verifier, WebAuthn verifier,
token/session, clock, OS randomness, request body, constant.

Coverage labels used in the tables:

- `covered: <area> plans` — the statement/plan/classifier (and, in wave 2, the
  handler I/O outside the executor methods) is extracted and proved against the
  transactional store model with fault injection, and matched on the real
  store. Cite: 08 sections *Executor honesty* and *Handler I/O outside ...*.
- `covered: constructor mapping` — the observation-to-fact mapping is a checked
  pure constructor (docs 13, 14, 15). It does not prove where the observation
  came from; the origin is listed as its own producer.
- `open: ...` — no proof covers this producer. `open: request body` is the
  unverified parsing glue; `open: signature verdict` / `open: WebAuthn verdict`
  are verifier calls that 08 lists as inputs; `open: token/session` covers PASETO
  verification and the session extractor; `open: clock` and `open: OS randomness`
  are the clock and entropy sources (plan steps O11/T9).
- `constant/config` — a literal or configuration value; no proof obligation.

## Summary

| Area | Types | Fields | Fully open | Partly open |
|---|---|---|---|---|
| Cross-user sharing (send capsule, linked-item update/revoke, inbox delete, share-EK registration) | 27 | 103 | 20 | 13 |
| One-off share links (POST /send, GET /send/:id, DELETE /send/:id, owner listing, expiry sweep) | 3 | 16 | 12 | 0 |
| Session and web session (login, registration, revocation/logout, admission, deletion, challenge issue, web sessions) | 18 | 77 | 16 | 15 |
| Device enrollment, invitation packages, pairing rendezvous (vela-enrollment-policy) | 22 | 92 | 20 | 36 |
| Recovery (grant redemption, recovery share, possession proof, WebAuthn recovery) | 50 | 220 | 27 | 52 |
| Vault chunks, ORAM, sync, rotation and device capsules (vela-rekey-policy) | 14 | 57 | 1 | 0 |
| **Total** | **134** | **565** | **96** | **116** |

Per-type consumer functions are listed in the per-area tables below; the
`Consumer` column names the driver/interpreter/executor entry point, and the
`Producer (file:line)` column names the server code that fills the field.

## Cross-user sharing (send capsule, linked-item update/revoke, inbox delete, share-EK registration)

27 types, 103 fields, 20 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `SendRequestObservation` | `session_user_id_present` | token/session | share/mod.rs:364 `!session.user_id.is_nil()` (AuthSession extractor) | open: token/session origin (PASETO verification and extractor unverified) |
| `SendRequestObservation` | `decode_failed` | request body | share/mod.rs:350 `B64.decode(&body.capsule)` | open: request body (unverified parsing) |
| `SendRequestObservation` | `capsule_len` | request body | share/mod.rs:352 decoded body length | open: request body (unverified parsing) |
| `SendRequestObservation` _consumer_ | — | — | interpreter::start_send (share/mod.rs:363) | `vela-share-policy/src/driver.rs:90` |
| `SendAdmissionObservation` | `failed` | SQL row/classifier | store.rs:856 classify_recipient_probe over plan_recipient_probe (store.rs:772; SQL "SELECT share_ek FROM users" store.rs:1329); share/mod.rs:158 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` | `recipient_can_receive` | SQL row/classifier | same classifier (store.rs:856); share/mod.rs:166 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` | `inbox_count` | SQL aggregate | store.rs:884 classify_send_admission over COUNT(*) (plan store.rs:778; SQL store.rs:1334) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` | `pair_bytes` | SQL aggregate | SUM(LENGTH(capsule)) pair query (SQL store.rs:1338); store.rs:884 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` | `total_bytes` | SQL aggregate | SUM(LENGTH(capsule)) inbox query (SQL store.rs:1346); store.rs:884 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` | `quota_read` | classifier stage | store.rs:884 (AdmissionStage::Ready); share/mod.rs:210 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendAdmissionObservation` _consumer_ | — | — | ShareExecutor::admit_send -> driver SendAdmitted (share/mod.rs:154-215) | `vela-share-policy/src/driver.rs:103` |
| `LinkUpdateStartObservation` | `decode_failed` | request body | share/mod.rs:701 `B64.decode(&body.capsule)` | open: request body (unverified parsing) |
| `LinkUpdateStartObservation` | `capsule_len` | request body | share/mod.rs:703 decoded length | open: request body (unverified parsing) |
| `LinkUpdateStartObservation` _consumer_ | — | — | interpreter::start_link_update (share/mod.rs:709) | `vela-share-policy/src/driver.rs:121` |
| `EkRegistrationStartObservation` | `ek_decode_failed` | request body | share/mod.rs:1021 `B64.decode(&body.share_ek)` | open: request body (unverified parsing) |
| `EkRegistrationStartObservation` | `ek_len` | request body | share/mod.rs:1023 decoded length | open: request body (unverified parsing) |
| `EkRegistrationStartObservation` | `signed_at_not_canonical` | request body | share/mod.rs:1031-1035 `body.signed_at` suffix/length test | open: request body (unverified parsing) |
| `EkRegistrationStartObservation` | `signed_at_unparseable` | request body | share/mod.rs:1038 RFC3339 parse of `body.signed_at` | open: request body (unverified parsing) |
| `EkRegistrationStartObservation` | `signed_at_future` | request body + clock | share/mod.rs:1040-1043 `Utc::now()` vs parsed `signed_at` | open: clock read (TTL/scheduler choice) |
| `EkRegistrationStartObservation` _consumer_ | — | — | interpreter::start_ek_registration (share/mod.rs:1046) | `vela-share-policy/src/driver.rs:144` |
| `EkDeviceObservation` | `registration.ek_len` | request body | ShareEkIo.ek_bytes (share/mod.rs:910,1023,1048) | open: request body (unverified parsing) |
| `EkDeviceObservation` | `registration.signature_verified` | signature verifier | share/mod.rs:965 `verify_hybrid_signature(vk,...,"share-key binding signature invalid")` | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `EkDeviceObservation` | `registration.device_row_present` | SQL row | plan_device_read (store.rs:181; SQL "SELECT d.hybrid_vk, d.revoked, u.share_ek_since, d.user_id" store.rs:1525); classify_device store.rs:280 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkDeviceObservation` | `registration.device_user_matches` | SQL row + session | classify_device (store.rs:280) compares row user_id with caller = session.user_id (share/mod.rs:911) | covered: share executor plans (08 Executor honesty: sharing; share-executors) ; caller id open: token/session origin (PASETO verification and extractor unverified) |
| `EkDeviceObservation` | `registration.device_active` | SQL row | devices.revoked of the same row; classify_device store.rs:280 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkDeviceObservation` | `registration.signed_at_is_fresher` | SQL row + request body | pure `vela_share_policy::timestamp_is_fresher(canonical_signed_at, share_ek_since)` share/mod.rs:972-975 | covered: share executor plans (08 Executor honesty: sharing; share-executors) for the stored cell; canonical value open: request body (unverified parsing) |
| `EkDeviceObservation` | `registration.binding_exists` | SQL row | `share_ek_since` presence in DeviceRowView (share/sql.rs:126-141) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkDeviceObservation` | `stored_identity_vk_decode_failed` | row decode | share/mod.rs:938-947 `crate::db::decode_b64(&hybrid_vk)` | open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `EkDeviceObservation` | `signature_decode_failed` | request body decode | share/mod.rs:950-959 `B64.decode(&self.signature)` | open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `EkDeviceObservation` _consumer_ | — | — | ShareExecutor::observe_device (share/mod.rs:907) | `vela-share-policy/src/driver.rs:131` |
| `EkRegistrationObservation` | `ek_len` | request body | share/mod.rs:1019 (EkDeviceObservation.registration.ek_len) | open: request body (unverified parsing) |
| `EkRegistrationObservation` | `signature_verified` | signature verifier | share/mod.rs:965 | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `EkRegistrationObservation` | `device_row_present` | SQL row | classify_device store.rs:280 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRegistrationObservation` | `device_user_matches` | SQL row + session | classify_device store.rs:280; caller share/mod.rs:911 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRegistrationObservation` | `device_active` | SQL row | classify_device store.rs:280 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRegistrationObservation` | `signed_at_is_fresher` | SQL row + body | share/mod.rs:972-975 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRegistrationObservation` | `binding_exists` | SQL row | share/sql.rs:134 `share_ek_since` | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRegistrationObservation` _consumer_ | — | — | ek_registration_facts -> plan_ek_registration (driver step EkObserved) | `vela-share-policy/src/lib.rs:34` |
| `RowsObservation` | `rows` | SQL affected-row count | store.rs:221 classify_rows over run_writes (share/mod.rs:675,760,988; 554) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RowsObservation` _consumer_ | — | — | driver Mutated event (update/revoke/EK/inbox delete) | `vela-share-policy/src/driver.rs:155` |
| `CleanupObservation` | `storage_failed` | SQL affected rows/classifier | store.rs:233 classify_cleanup over plan_linked_inbox_cleanup (store.rs:171; SQL 1507); share/mod.rs:770 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `CleanupObservation` _consumer_ | — | — | driver Cleaned event (revoke cleanup) | `vela-share-policy/src/driver.rs:173` |
| `LinkMutationObservation` | `item_present` | SQL row | store.rs:252 classify_link over plan_link_read (store.rs:151; SQL "SELECT sender_user_id, revoked FROM shared_items" store.rs:1127); share/mod.rs:828 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `LinkMutationObservation` | `caller_matches_sender` | SQL row + session | classify_link compares row sender with session.user_id (share/mod.rs:838) | covered: share executor plans (08 Executor honesty: sharing; share-executors) ; caller id open: token/session origin (PASETO verification and extractor unverified) |
| `LinkMutationObservation` | `item_not_revoked` | SQL row | `revoked` column; classify_link store.rs:252 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `LinkMutationObservation` _consumer_ | — | — | link_mutation_facts -> plan_link_mutation (ShareExecutor::observe_link) | `vela-share-policy/src/lib.rs:278` |
| `SendObservation` | `session_user_id_present` | derived | driver.rs:663 from SendRequestObservation.session_user_id_present | covered: share executor plans (08 Executor honesty: sharing; share-executors) (driver); origin open: token/session origin (PASETO verification and extractor unverified) |
| `SendObservation` | `recipient_has_share_ek` | constant | driver.rs:664 literal `true`, reached only after SendAdmissionObservation.recipient_can_receive passed (driver.rs:647) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendObservation` | `capsule_len` | derived | driver.rs:665 from SendRequestObservation.capsule_len | open: request body (unverified parsing) |
| `SendObservation` | `existing_inbox_bytes` | derived | driver.rs:666 from SendAdmissionObservation.total_bytes | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendObservation` _consumer_ | — | — | send_facts -> plan_send (driver.rs:662) | `vela-share-policy/src/lib.rs:205` |
| `SendCapsuleFacts` | `sender_authenticated` | derived | send_facts lib.rs:236-243 (from SendObservation) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendCapsuleFacts` | `recipient_registered` | derived | send_facts lib.rs:236-243 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendCapsuleFacts` | `capsule_size_valid` | derived | send_facts lib.rs:236-243 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendCapsuleFacts` | `inbox_has_capacity` | derived | send_facts lib.rs:236-243 (i128-bounded sum) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendCapsuleFacts` _consumer_ | — | — | send_is_authorized / plan_send | `vela-share-policy/src/lib.rs:217` |
| `EkRegistrationFacts` | `ek_size_valid` | derived | ek_registration_facts lib.rs:99-114 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` | `signature_verified` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` | `device_owned_by_caller` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` | `device_active` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` | `signed_at_is_fresher` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` | `seq` | derived (1 or 2) | same, from binding_exists | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `EkRegistrationFacts` _consumer_ | — | — | ek_registration_is_authorized / plan_ek_registration | `vela-share-policy/src/lib.rs:55` |
| `LinkMutationFacts` | `caller_is_sender` | derived | link_mutation_facts lib.rs:315-330 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `LinkMutationFacts` | `item_exists` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `LinkMutationFacts` | `not_already_revoked` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `LinkMutationFacts` _consumer_ | — | — | link_mutation_is_authorized / plan_link_mutation | `vela-share-policy/src/lib.rs:288` |
| `LinkRowView` | `sender` | SQL row column 0 | share/sql.rs:122-125 `SELECT sender_user_id` (SQL store.rs:1127) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `LinkRowView` | `revoked` | SQL row column 1 | share/sql.rs:123 `revoked` | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `LinkRowView` _consumer_ | — | — | classify_link (store.rs:252) | `vela-share-policy/src/store.rs:93` |
| `DeviceRowView` | `hybrid_vk` | SQL row column 0 | share/sql.rs:131-141 (SQL store.rs:1525) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `DeviceRowView` | `revoked` | SQL row column 1 | share/sql.rs:133-137 (integer or text "1") | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `DeviceRowView` | `share_ek_since` | SQL row column 2 | share/sql.rs:138 (users.share_ek_since) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `DeviceRowView` | `user_id` | SQL row column 3 | share/sql.rs:139 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `DeviceRowView` _consumer_ | — | — | classify_device (store.rs:280) | `vela-share-policy/src/store.rs:102` |
| `DeviceVerdicts` | `signature_verified` | signature verifier | share/mod.rs:965 | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `DeviceVerdicts` | `stored_vk_decode_failed` | row decode | share/mod.rs:931-942 | open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `DeviceVerdicts` | `signature_decode_failed` | body decode | share/mod.rs:944-953 | open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `DeviceVerdicts` | `signed_at_is_fresher` | row + body | share/mod.rs:972-975 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `DeviceVerdicts` _consumer_ | — | — | classify_device input | `vela-share-policy/src/store.rs:113` |
| `EkRowView` | `share_ek` | SQL row column 0 | share/sql.rs:185-190 `SELECT share_ek, share_ek_since FROM users` (SQL store.rs:1351) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRowView` | `share_ek_since` | SQL row column 1 | share/sql.rs:188 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `EkRowView` _consumer_ | — | — | classify_recipient_probe / classify_recipient_ek | `vela-share-policy/src/store.rs:683` |
| `CursorRowView` | `created_at` | SQL row column 0 | share/sql.rs:193-196 (SQL store.rs:1355) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `CursorRowView` _consumer_ | — | — | classify_inbox_cursor (store.rs:1014) | `vela-share-policy/src/store.rs:690` |
| `RecipientProbeObservation` | `can_receive` | SQL row/classifier | store.rs:856 classify_recipient_probe | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RecipientProbeObservation` | `failed` | read error/classifier | store.rs:856 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RecipientProbeObservation` _consumer_ | — | — | SendExecutor::admit_send | `vela-share-policy/src/store.rs:698` |
| `AdmissionObservation` | `stage` | classifier | store.rs:884 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `AdmissionObservation` | `inbox_count` | SQL aggregate | SQL store.rs:1334 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `AdmissionObservation` | `pair_bytes` | SQL aggregate | SQL store.rs:1338 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `AdmissionObservation` | `total_bytes` | SQL aggregate | SQL store.rs:1346 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `AdmissionObservation` _consumer_ | — | — | classify_send_admission -> SendAdmissionObservation | `vela-share-policy/src/store.rs:719` |
| `RecipientEkObservation` | `share_ek` | SQL row | store.rs:982 over EkRowView | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RecipientEkObservation` | `signed_at` | SQL row | store.rs:982 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RecipientEkObservation` | `failed` | read/classifier | store.rs:982 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RecipientEkObservation` _consumer_ | — | — | classify_recipient_ek (store.rs:982) | `vela-share-policy/src/store.rs:729` |
| `CursorObservation` | `created_at` | SQL row | store.rs:1014 over CursorRowView | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `CursorObservation` | `absent` | classifier | store.rs:1014 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `CursorObservation` | `failed` | read/classifier | store.rs:1014 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `CursorObservation` _consumer_ | — | — | get_inbox cursor | `vela-share-policy/src/store.rs:738` |
| `PageObservation` | `keep` | row count/limit | store.rs:1036 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `PageObservation` | `has_more` | row count/limit | store.rs:1036 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `PageObservation` | `failed` | read error | store.rs:1036 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `PageObservation` _consumer_ | — | — | classify_listing (store.rs:1036) | `vela-share-policy/src/store.rs:747` |
| `SweepObservation` | `purged` | SQL affected rows | store.rs:1059 over plan_expired_inbox_cleanup/plan_expired_sends_cleanup (store.rs:822,827) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SweepObservation` | `failed` | SQL outcome | store.rs:1059 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SweepObservation` _consumer_ | — | — | classify_sweep (store.rs:1059); inbox/expiry cleanup tasks | `vela-share-policy/src/store.rs:755` |
| `RateLimitObservation` | `count` | store counter | store.rs:1085 over plan_rate_limit (store.rs:832) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RateLimitObservation` | `allowed` | store counter | store.rs:1085 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RateLimitObservation` | `failed` | store outcome | store.rs:1085 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `RateLimitObservation` _consumer_ | — | — | plan_rate_limit classifier (store.rs:1085) | `vela-share-policy/src/store.rs:763` |
| `SendFetchObservation` | `read` | classifier | store.rs:562 over SendRowView | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `missing_cell` | classifier | store.rs:562 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `ciphertext` | SQL row | store.rs:562; send/sql.rs:90 column 0 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `has_passphrase` | SQL row | send/sql.rs:92 column 1 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `kdf_salt` | SQL row | send/sql.rs:93 column 2 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `view_once` | SQL row | send/sql.rs:94 column 3 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `max_views` | SQL row | send/sql.rs:95 column 4 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `view_count` | SQL row | send/sql.rs:96 column 5 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` | `expires_at` | SQL row (timestamp parse) | send/sql.rs:97 column 6 (`row.timestamp`) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendFetchObservation` _consumer_ | — | — | classify_send_read (store.rs:562) -> send driver | `vela-share-policy/src/store.rs:389` |
| `SendRowView` | `ciphertext` | SQL row column 0 | send/sql.rs:90-98 (SQL store.rs:1279) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `has_passphrase` | SQL row column 1 | send/sql.rs:92 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `kdf_salt` | SQL row column 2 | send/sql.rs:93 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `view_once` | SQL row column 3 | send/sql.rs:94 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `max_views` | SQL row column 4 | send/sql.rs:95 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `view_count` | SQL row column 5 | send/sql.rs:96 | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` | `expires_at` | SQL row column 6 | send/sql.rs:97 (RFC3339 parse) | covered: share executor plans (08 Executor honesty: sharing; share-executors) |
| `SendRowView` _consumer_ | — | — | classify_send_read | `vela-share-policy/src/store.rs:368` |

## One-off share links (POST /send, GET /send/:id, DELETE /send/:id, owner listing, expiry sweep)

3 types, 16 fields, 12 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `CreateObservation` | `owner_present` | token/session | send.rs:201 `!session.user_id.is_nil()` (DeviceSession extractor) | open: token/session origin (PASETO verification and extractor unverified) |
| `CreateObservation` | `ciphertext_decode_failed` | request body | send.rs:174 `B64.decode(&body.ciphertext)` | open: request body (unverified parsing) |
| `CreateObservation` | `ciphertext_len` | request body | send.rs:174 decoded length | open: request body (unverified parsing) |
| `CreateObservation` | `has_passphrase` | request body | send.rs:204 `body.has_passphrase` | open: request body (unverified parsing) |
| `CreateObservation` | `kdf_salt_present` | request body | send.rs:180-187 salt match arm | open: request body (unverified parsing) |
| `CreateObservation` | `kdf_salt_decode_failed` | request body | send.rs:180-187 `B64.decode(salt)` | open: request body (unverified parsing) |
| `CreateObservation` | `kdf_salt_len` | request body | send.rs:181 decoded salt length | open: request body (unverified parsing) |
| `CreateObservation` | `has_ttl` | request body | send.rs:206 `body.ttl_secs.is_some()` | open: request body (unverified parsing) |
| `CreateObservation` | `ttl_secs` | request body | send.rs:207 `body.ttl_secs.unwrap_or(0)` | open: request body (unverified parsing) |
| `CreateObservation` | `has_max_views` | request body | send.rs:208 `body.max_views.is_some()` | open: request body (unverified parsing) |
| `CreateObservation` | `max_views` | request body | send.rs:209 `body.max_views.unwrap_or(0)` | open: request body (unverified parsing) |
| `CreateObservation` | `view_once` | request body | send.rs:210 `body.view_once` | open: request body (unverified parsing) |
| `CreateObservation` _consumer_ | — | — | send_interpreter::start_create (send.rs:199) | `vela-share-policy/src/send_driver.rs:71` |
| `RowsObservation` | `rows` | SQL affected rows | store.rs:480 classify_send_create / store.rs:538 classify_send_delete | covered: send-link plans (08 Executor honesty: one-off share links; send-executors) |
| `RowsObservation` | `failed` | SQL outcome | same | covered: send-link plans (08 Executor honesty: one-off share links; send-executors) |
| `RowsObservation` _consumer_ | — | — | SendExecutor insert/delete (send.rs:102,158,346,359,491,507) | `vela-share-policy/src/send_driver.rs:126` |
| `RemoveObservation` | `removed` | SQL affected rows | store.rs:516 classify_send_remove over plan_send_remove (store.rs:467; SQL 1284) | covered: send-link plans (08 Executor honesty: one-off share links; send-executors) |
| `RemoveObservation` | `failed` | SQL outcome | store.rs:516 | covered: send-link plans (08 Executor honesty: one-off share links; send-executors) |
| `RemoveObservation` _consumer_ | — | — | SendExecutor::remove_fetched (send.rs:332) | `vela-share-policy/src/send_driver.rs:119` |

## Session and web session (login, registration, revocation/logout, admission, deletion, challenge issue, web sessions)

18 types, 77 fields, 16 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `FailureRecordObservation` | `fallback_counter_ok` | store counter | store.rs:1057 classify_failure_counter over plan_failure_counter (store.rs:579); verify.rs:196-209 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `FailureRecordObservation` _consumer_ | — | — | on_failure_recorded (login driver) | `vela-session-policy/src/login_driver.rs:105` |
| `RegistrationRequestObservation` | `has_account_limit` | config | account/mod.rs:398 `state.config.max_accounts.is_some()` | constant/config (inspection only) |
| `RegistrationRequestObservation` | `account_limit` | config | account/mod.rs:399-402 `config.max_accounts` clamped to i64 | constant/config (inspection only) |
| `RegistrationRequestObservation` _consumer_ | — | — | interpreter::start_registration (account/mod.rs:397) | `vela-session-policy/src/registration_driver.rs:42` |
| `ActorObservation` | `authenticated` | token/session (constant at call site) | device/revoke.rs:208 literal `true`; justified by DeviceSession extractor | open: token/session origin (PASETO verification and extractor unverified) |
| `ActorObservation` | `device_active` | token/session (constant at call site) | device/revoke.rs:209 literal `true`; middleware durable check (middleware.rs:159-176) | open: token/session origin (PASETO verification and extractor unverified) |
| `ActorObservation` _consumer_ | — | — | revocation_interpreter! (device/revoke.rs:207) | `vela-session-policy/src/revocation_driver.rs:38` |
| `TargetObservation` | `same_account` | SQL row + session | vela_session_policy::store::classify_target over TargetRowView (session_store.rs:538); row user_id vs session.user_id | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) ; caller id open: token/session origin (PASETO verification and extractor unverified) |
| `TargetObservation` | `already_revoked` | SQL row | TargetRowView.revoked (session_store.rs:539-542) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TargetObservation` _consumer_ | — | — | target classification in the revocation driver (built inside classify_target) | `vela-session-policy/src/revocation_driver.rs:45` |
| `AdmissionObservation` | `jti_revoked` | store lookup | middleware.rs:113 `store.exists("jti:revoked:<jti>")` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `AdmissionObservation` | `device_revoked` | store lookup | middleware.rs:114 `store.exists("device:revoked:<id>")` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `AdmissionObservation` | `account_present` | SQL row | middleware.rs:143 after `SELECT key_epoch FROM users WHERE id = ?` (middleware.rs:133) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `AdmissionObservation` | `device_row_active` | SQL row | middleware.rs:181 after `SELECT id FROM devices WHERE id=? AND user_id=? AND revoked=0` (middleware.rs:172) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `AdmissionObservation` | `device_scoped` | token/session claim | middleware.rs:121 `claims.scope == TokenScope::Device` (PASETO claims) | open: token/session origin (PASETO verification and extractor unverified) |
| `AdmissionObservation` _consumer_ | — | — | enforce_admission (middleware.rs:116,143,181) | `vela-session-policy/src/revocation_driver.rs:771` |
| `DeletionActorObservation` | `authenticated` | token/session (constant) | account/delete.rs:213 literal `true` after DeviceSession extraction | open: token/session origin (PASETO verification and extractor unverified) |
| `DeletionActorObservation` | `device_active` | token/session (constant) | account/delete.rs:214 literal `true` (middleware durable check) | open: token/session origin (PASETO verification and extractor unverified) |
| `DeletionActorObservation` | `scoped_to_session_account` | constant/code shape | account/delete.rs:215 literal `true`; single `session.user_id` scopes every effect | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `DeletionActorObservation` _consumer_ | — | — | deletion_interpreter! (account/delete.rs:212) | `vela-session-policy/src/deletion_driver.rs:37` |
| `GrantObservation` | `phase` | SQL row | web_session/mod.rs:755-760 from web_sessions.status (load_session) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `GrantObservation` | `mode` | request body | web_session/mod.rs:761 `self.body.mode == "rw"` | open: request body (unverified parsing) |
| `GrantObservation` | `approver_user` | SQL row | web_session/mod.rs:764 `existing.approver_user_id.map(as_u128)` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `GrantObservation` | `authenticated_user` | token/session | web_session/mod.rs:765 `self.session.user_id.as_u128()` | open: token/session origin (PASETO verification and extractor unverified) |
| `GrantObservation` | `nonce_length` | request body | web_session/mod.rs:766 `given_nonce.len()` from body.link_nonce (web_session/mod.rs:727-729) | open: request body (unverified parsing) |
| `GrantObservation` | `nonce_equal` | body + SQL row | web_session/mod.rs:731-739 `ct_eq(given_nonce, stored_nonce)` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) for stored cell; comparison glue open: request body (unverified parsing) |
| `GrantObservation` | `has_web_vk` | SQL row | web_session/mod.rs:767 `existing.web_vk.is_some()` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `GrantObservation` | `declared_epoch` | request body | web_session/mod.rs:768 `self.body.key_epoch` -> used as grant epoch (see finding O13c) | open: request body (unverified parsing) |
| `GrantObservation` _consumer_ | — | — | grant_facts -> plan_grant / plan_observed_grant (web_session grant) | `vela-session-policy/src/lib.rs:174` |
| `GrantFacts` | `phase` | derived | grant_facts lib.rs:205-217 | covered: constructor mapping (14); origin open where the source observation is open |
| `GrantFacts` | `mode` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `GrantFacts` | `approver_matches` | derived | same (None never matches) | covered: constructor mapping (14); origin open where the source observation is open |
| `GrantFacts` | `nonce_matches` | derived | same (32-byte length + equality) | covered: constructor mapping (14); origin open where the source observation is open |
| `GrantFacts` | `has_web_vk` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `GrantFacts` | `declared_epoch` | derived | same; origin is body | open: request body (unverified parsing) |
| `GrantFacts` _consumer_ | — | — | grant_is_authorized / plan_grant | `vela-session-policy/src/lib.rs:95` |
| `WebTokenObservation` | `phase` | SQL row | web_session/mod.rs:997-1005 via TokenSessionObservation.phase | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `mode` | SQL row | web_session/mod.rs:1006-1009 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `granted_user` | SQL row | web_session/mod.rs:1011 `session.user_id.map(as_u128)` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `approver_user` | SQL row | web_session/mod.rs:1012 `session.approver_user_id.map(as_u128)` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `nonce_present` | SQL row | web_session/mod.rs:1013 `session.link_nonce.is_some()` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `challenge_consumed` | store take | web_session/mod.rs:1030 `take_challenge(..., WebToken)` (plan_take_challenge store.rs:557) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `WebTokenObservation` | `signature_valid` | signature verifier | web_session/mod.rs:1049 `verify_auth_signature(web_vk, challenge, id, body.signature)` | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `WebTokenObservation` _consumer_ | — | — | web_token_facts -> plan_observed_web_token (built inside the token driver from TokenSessionObservation + challenge/signature observations) | `vela-session-policy/src/lib.rs:226` |
| `WebTokenFacts` | `phase` | derived | web_token_facts lib.rs:243-252 | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` | `mode` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` | `approver_bound` | derived | same (both ids present and equal) | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` | `nonce_bound` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` | `challenge_consumed` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` | `signature_valid` | derived | same | covered: constructor mapping (14); origin open where the source observation is open |
| `WebTokenFacts` _consumer_ | — | — | web_token_is_authorized / plan_observed_web_token | `vela-session-policy/src/lib.rs:161` |
| `TokenSessionObservation` | `phase` | SQL row | web_session/mod.rs:997 via status (web_session/mod.rs:961-966) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `mode` | SQL row | web_session/mod.rs:1006-1009 (mode column) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `granted_user` | SQL row | web_session/mod.rs:1011 (user_id column) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `approver_user` | SQL row | web_session/mod.rs:1012 (approver_user_id column) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `nonce_present` | SQL row | web_session/mod.rs:1013 (link_nonce column) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `web_vk_present` | SQL row | web_session/mod.rs:1014 (web_vk column) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `key_epoch` | SQL row | web_session/mod.rs:1015 (key_epoch column, `unwrap_or(1)`) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` | `now` | clock | web_session/mod.rs:996 `Utc::now().timestamp()` | open: clock read (TTL/scheduler choice) |
| `TokenSessionObservation` | `expires_at` | SQL row | web_session/mod.rs:1016 `session.expires_at.map(timestamp)` | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `TokenSessionObservation` _consumer_ | — | — | TokenIo::token_load_session (web_session/mod.rs:997) | `vela-session-policy/src/websession_driver.rs:742` |
| `GrantActorObservation` | `authenticated` | token/session (constant) | web_session/mod.rs:844 literal `true` | open: token/session origin (PASETO verification and extractor unverified) |
| `GrantActorObservation` | `device_active` | token/session (constant) | web_session/mod.rs:845 literal `true`; middleware durable check | open: token/session origin (PASETO verification and extractor unverified) |
| `GrantActorObservation` _consumer_ | — | — | websession_grant_interpreter! (web_session/mod.rs:843) | `vela-session-policy/src/websession_driver.rs:329` |
| `DeleteActorObservation` | `authenticated` | token/session (constant) | web_session/mod.rs:1444 literal `true` | open: token/session origin (PASETO verification and extractor unverified) |
| `DeleteActorObservation` | `user` | token/session | web_session/mod.rs:1445 `actor_user = session.user_id.as_u128()` (web_session/mod.rs:1425) | open: token/session origin (PASETO verification and extractor unverified) |
| `DeleteActorObservation` _consumer_ | — | — | websession_delete_interpreter! (web_session/mod.rs:1443) | `vela-session-policy/src/websession_driver.rs:1600` |
| `DeleteSessionFacts` | `session_user` | SQL row | web_session/mod.rs:1363 from load_session row user_id | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `DeleteSessionFacts` | `approver_user` | SQL row | web_session/mod.rs:1364 from load_session row approver_user_id | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `DeleteSessionFacts` _consumer_ | — | — | delete driver ownership check | `vela-session-policy/src/websession_driver.rs:1608` |
| `TargetRowView` | `user_id` | row (decoded DeviceRow) | device/revoke.rs:106 `parse_device_row_turso` then session_store.rs:538-543 target_row_view | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) ; DeviceRow decode open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `TargetRowView` | `revoked` | row (decoded DeviceRow) | device/revoke.rs:106 then session_store.rs:539-542 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) ; DeviceRow decode open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `TargetRowView` _consumer_ | — | — | classify_target (revocation driver) | `vela-session-policy/src/store.rs:299` |
| `SessionRowView` | `user_id` | SQL row column 0 | web_session/mod.rs:377-388 `SELECT ... FROM web_sessions WHERE id = ?` (store.rs:753) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `approver_user_id` | SQL row column 7 | web_session/mod.rs:384 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `poll_secret_hash` | SQL row column 8 | web_session/mod.rs:385 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `web_vk` | SQL row column 1 | web_session/mod.rs:379 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `link_nonce` | SQL row column 2 | web_session/mod.rs:380 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `mode` | SQL row column 3 | web_session/mod.rs:381 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `status` | SQL row column 4 | web_session/mod.rs:382 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `capsule` | SQL row column 5 | web_session/mod.rs:383 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `expires_at` | SQL row column 6 | web_session/mod.rs:386 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` | `key_epoch` | SQL row column 9 | web_session/mod.rs:387 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionRowView` _consumer_ | — | — | classify_session_lookup (store.rs:1239) / load_session | `vela-session-policy/src/store.rs:355` |
| `SessionListRowView` | `id` | SQL row column 0 | web_session/mod.rs:396-403 (plan_sessions_list store.rs:758) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionListRowView` | `mode` | SQL row column 1 | web_session/mod.rs:399 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionListRowView` | `status` | SQL row column 2 | web_session/mod.rs:400 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionListRowView` | `created_at` | SQL row column 3 | web_session/mod.rs:401 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionListRowView` | `expires_at` | SQL row column 4 | web_session/mod.rs:402 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionListRowView` _consumer_ | — | — | classify_sessions_list (store.rs:1249) | `vela-session-policy/src/store.rs:379` |
| `SessionKeysView` | `ephemeral_pk` | SQL row column 0 | web_session/mod.rs:594-598 (plan_session_keys store.rs:867) | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionKeysView` | `web_vk` | SQL row column 1 | web_session/mod.rs:596 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionKeysView` | `status` | SQL row column 2 | web_session/mod.rs:597 | covered: session plans (08 Executor honesty: session, login, registration and web sessions; session-executors) |
| `SessionKeysView` _consumer_ | — | — | classify_session_keys (store.rs:1355) | `vela-session-policy/src/store.rs:423` |

## Device enrollment, invitation packages, pairing rendezvous (vela-enrollment-policy)

22 types, 92 fields, 20 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `OpenObservation` | `scope_is_device` | token/session | rendezvous.rs:199 `matches!(session.scope, TokenScope::Device)` (PASETO claim) | open: token/session origin (PASETO verification and extractor unverified) |
| `OpenObservation` | `user_id_present` | token/session | rendezvous.rs:200 `!session.user_id.is_nil()` | open: token/session origin (PASETO verification and extractor unverified) |
| `OpenObservation` | `device_id_present` | token/session | rendezvous.rs:201 `!session.device_id.is_nil()` | open: token/session origin (PASETO verification and extractor unverified) |
| `OpenObservation` | `ttl_secs` | constant | rendezvous.rs:202 `GRANT_TTL_SECS` | constant/config (inspection only) |
| `OpenObservation` _consumer_ | — | — | open_facts -> plan_open (pairing_interpreter::start_open_grant, rendezvous.rs:198) | `vela-enrollment-policy/src/lib.rs:36` |
| `OpenFacts` | `device_scope` | derived | open_facts lib.rs:74-84 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `OpenFacts` | `user_bound` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `OpenFacts` | `opener_bound` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `OpenFacts` | `ttl_positive` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `OpenFacts` _consumer_ | — | — | open_is_authorized / plan_open | `vela-enrollment-policy/src/lib.rs:48` |
| `ClaimObservation` | `grant_live` | store exists | rendezvous.rs:381-385 plan_grant_exists + classify_grant_exists (exists(enroll_grant:<id>)) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimObservation` | `claim_exists` | store exists | rendezvous.rs:299 plan_claim_check + classify_claim_check:311 (exists(enroll_claim:<id>)) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimObservation` | `hybrid_ek_len` | request body | rendezvous.rs:285-292 `decode_base64_field(&self.body.hybrid_ek)` then ek.len() | open: request body (unverified parsing) |
| `ClaimObservation` | `hybrid_vk_len` | request body | rendezvous.rs:293-301 `decode_base64_field(&self.body.hybrid_vk)` then vk.len() | open: request body (unverified parsing) |
| `ClaimObservation` _consumer_ | — | — | claim_facts -> plan_claim (PairingExecutor::check_claim, rendezvous.rs:284) | `vela-enrollment-policy/src/lib.rs:106` |
| `ClaimFacts` | `phase` | derived | claim_facts lib.rs:150-170 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ClaimFacts` | `grant_live` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ClaimFacts` | `no_existing_claim` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ClaimFacts` | `public_keys_valid` | derived | same (1600/2624-byte constants) | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ClaimFacts` _consumer_ | — | — | claim_is_authorized / plan_claim | `vela-enrollment-policy/src/lib.rs:118` |
| `InspectObservation` | `claim_present` | store get | rendezvous.rs:434 load_claim -> plan_claim_read (get(enroll_claim:<id>)) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `InspectObservation` | `user_matches` | store get + session | rendezvous.rs:432 `authorize_grant` -> read_grant comparison (grant.user_id vs session.user_id) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) ; session open: token/session origin (PASETO verification and extractor unverified) |
| `InspectObservation` | `opener_matches` | store get + session | same (grant.device_id vs session.device_id) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) ; session open: token/session origin (PASETO verification and extractor unverified) |
| `InspectObservation` _consumer_ | — | — | inspect_facts -> authorize_inspection (get_claim, rendezvous.rs:446) | `vela-enrollment-policy/src/lib.rs:185` |
| `InspectFacts` | `phase` | derived | inspect_facts lib.rs:230-243 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `InspectFacts` | `user_matches` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `InspectFacts` | `opener_matches` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `InspectFacts` | `claim_present` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `InspectFacts` _consumer_ | — | — | inspection_is_authorized / authorize_inspection | `vela-enrollment-policy/src/lib.rs:195` |
| `CompletionObservation` | `claim_present` | derived (internal) | completion_facts lib.rs:365-400; no direct server literal | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `user_matches` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `opener_matches` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `opener_active` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `signature_verified` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `claim_key_source` | derived (internal) | same; `StoredClaim` is a structural constant at the call site | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `account_epoch` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` | `declared_epoch` | derived (internal) | same; body when used | open: request body (unverified parsing) |
| `CompletionObservation` | `rotation_in_progress` | derived (internal) | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionObservation` _consumer_ | — | — | completion_facts -> plan_completion (internal: no server construction; the shipped path uses CompletionPreflightObservation) | `vela-enrollment-policy/src/lib.rs:271` |
| `CompletionFacts` | `phase` | derived | completion_facts lib.rs:365-400 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `user_matches` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `opener_matches` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `opener_active` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `claim_present` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `displayed_claim_is_stored_claim` | derived | same (claim_key_source) | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `signature_covers_stored_claim` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` | `account_epoch_active` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `CompletionFacts` _consumer_ | — | — | completion_is_authorized / plan_completion | `vela-enrollment-policy/src/lib.rs:293` |
| `ResultObservation` | `source` | derived (internal) | result_facts lib.rs:470-490; store reads classify_result_read | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ResultObservation` | `claimed_key_len` | derived (internal) | same; stored claim/result decode | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ResultObservation` | `signature_verified` | derived (internal) | same; collector verifier (rendezvous.rs:1270 verify_result_signature) | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `ResultObservation` _consumer_ | — | — | result_facts -> plan_result (internal: built by the result driver from ResultReadObservation) | `vela-enrollment-policy/src/lib.rs:412` |
| `ResultFacts` | `phase` | derived | result_facts lib.rs:470-490 | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ResultFacts` | `claimed_key_present` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ResultFacts` | `claimed_key_proof_valid` | derived | same | covered: constructor mapping (08 enrollment ceremony); origin open where the source observation is open |
| `ResultFacts` _consumer_ | — | — | result_is_authorized / plan_result | `vela-enrollment-policy/src/lib.rs:421` |
| `PackageStoreObservation` | `token_valid` | request body | invitation.rs:106 `validate_token(&body.token)` (format check, invitation.rs:218) | open: request body (unverified parsing) |
| `PackageStoreObservation` | `ciphertext_len_valid` | request body | invitation.rs:107-108 `body.ciphertext` length bounds | open: request body (unverified parsing) |
| `PackageStoreObservation` _consumer_ | — | — | start_store_package (invitation.rs:105) | `vela-enrollment-policy/src/pairing_driver.rs:50` |
| `PackageTokenObservation` | `token_valid` | request body/header | invitation.rs:187 `validate_token(&token)`; token from `x-enrollment-token` or path (invitation.rs:180-185) | open: request body (unverified parsing) |
| `PackageTokenObservation` _consumer_ | — | — | start_redeem_package (invitation.rs:186) | `vela-enrollment-policy/src/pairing_driver.rs:58` |
| `CompletionPreflightObservation` | `claim` | store get + JSON decode | rendezvous.rs:588,620-676 get(enroll_claim:<id>) via plan_completion_preflight; ClaimRowView from serde_json | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionPreflightObservation` | `capsule_valid` | request body | rendezvous.rs:678-681 `decode_any(&self.body.rms_capsule)` | open: request body (unverified parsing) |
| `CompletionPreflightObservation` | `signature_field_valid` | request body | rendezvous.rs:681 `decode_exact(&self.body.signature, HYBRID_SIG_LEN)` | open: request body (unverified parsing) |
| `CompletionPreflightObservation` | `opener` | SQL row | rendezvous.rs:683-718 devices row (hybrid_vk, revoked) read by plan_completion_preflight | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionPreflightObservation` | `signature` | signature verifier | rendezvous.rs:732-750 verify_enrollment_signature (primary_vk, hybrid_ek/vk, capsule, signature) | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `CompletionPreflightObservation` | `account_epoch` | SQL row | rendezvous.rs:546-556 AccountRowView.key_epoch (check_account, plan_account_read) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionPreflightObservation` | `declared_epoch` | request body | rendezvous.rs:769 `self.body.key_epoch` | open: request body (unverified parsing) |
| `CompletionPreflightObservation` | `rotation_in_progress` | SQL row | rendezvous.rs:551 AccountRowView.rekey_state.is_some() | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionPreflightObservation` | `account_epoch_active` | rekey policy over SQL row | rendezvous.rs:573-582 `authorize_active_mutation(observed_state, permit)`; observed_state epoch/phase from the row | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionPreflightObservation` _consumer_ | — | — | classify_completion_preflight (rendezvous.rs:585-780) | `vela-enrollment-policy/src/pairing_driver.rs:141` |
| `CompletionAccountObservation` | `account_query_ok` | SQL row | rendezvous.rs:541-552 plan_account_read result | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionAccountObservation` | `declared_epoch_positive` | request body | rendezvous.rs:584 `self.body.key_epoch >= 1` | open: request body (unverified parsing) |
| `CompletionAccountObservation` | `rekey_permitted` | rekey policy over SQL row | rendezvous.rs:557-582 plan_active_mutation/authorize_active_mutation | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionAccountObservation` _consumer_ | — | — | check_account (rendezvous.rs:540) | `vela-enrollment-policy/src/pairing_driver.rs:913` |
| `GrantRecordView` | `user_id` | store get JSON | rendezvous.rs:1577-1581 decoded Grant from get(enroll_grant:<id>) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `GrantRecordView` | `device_id` | store get JSON | same | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `GrantRecordView` _consumer_ | — | — | classify_grant_read / plan_ceremony_restore | `vela-enrollment-policy/src/executor.rs:163` |
| `ClaimRecordView` | `hybrid_ek` | store get JSON | rendezvous.rs:642-647 decoded Claim (enroll_claim:<id>) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRecordView` | `hybrid_vk` | store get JSON | rendezvous.rs:643 | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRecordView` | `device_name` | store get JSON | rendezvous.rs:644 | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRecordView` | `device_type` | store get JSON | rendezvous.rs:645 | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRecordView` _consumer_ | — | — | plan_ceremony_restore / completion | `vela-enrollment-policy/src/executor.rs:170` |
| `ClaimRowView` | `hybrid_ek` | store get JSON | rendezvous.rs:636-641 (and 977,1333,1668) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRowView` | `hybrid_vk` | store get JSON | same | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRowView` | `device_name` | store get JSON | same | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRowView` | `device_type` | store get JSON | same | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ClaimRowView` _consumer_ | — | — | classify_completion_preflight / classify_claim_inspection | `vela-enrollment-policy/src/executor.rs:233` |
| `ResultRowView` | `device_id` | store get JSON | rendezvous.rs:1281-1284 decoded EnrollmentResult from get(enroll_result:<id>) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ResultRowView` | `hybrid_vk` | store get JSON | same | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `ResultRowView` _consumer_ | — | — | classify_result_read | `vela-enrollment-policy/src/executor.rs:242` |
| `AccountRowView` | `key_epoch` | SQL row column 0 | rendezvous.rs:546-549 `SELECT key_epoch, rekey_state FROM users` | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `AccountRowView` | `rekey_state` | SQL row column 1 | rendezvous.rs:549 | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `AccountRowView` _consumer_ | — | — | classify_account | `vela-enrollment-policy/src/executor.rs:250` |
| `CompletionVerdicts` | `claim_keys_usable` | store get + decoders | rendezvous.rs:606-680 stored claim base64 decodes | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionVerdicts` | `capsule_valid` | request body | rendezvous.rs:678 `decode_any(&self.body.rms_capsule)` | open: request body (unverified parsing) |
| `CompletionVerdicts` | `signature_field_valid` | request body | rendezvous.rs:681 `decode_exact(&self.body.signature, HYBRID_SIG_LEN)` | open: request body (unverified parsing) |
| `CompletionVerdicts` | `opener_key_decodes` | SQL row + decode | rendezvous.rs:683-718 opener hybrid_vk base64 decode | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionVerdicts` | `signature_verified` | signature verifier | rendezvous.rs:732-750 verify_enrollment_signature | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `CompletionVerdicts` | `account_epoch` | SQL row | rendezvous.rs:548-556 AccountRowView.key_epoch | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionVerdicts` | `declared_epoch` | request body | rendezvous.rs:769 self.body.key_epoch | open: request body (unverified parsing) |
| `CompletionVerdicts` | `rotation_in_progress` | SQL row | rendezvous.rs:551 AccountRowView.rekey_state | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionVerdicts` | `account_epoch_active` | rekey policy over SQL row | rendezvous.rs:573-582 authorize_active_mutation | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CompletionVerdicts` _consumer_ | — | — | classify_completion_preflight input (rendezvous.rs:727-773) | `vela-enrollment-policy/src/executor.rs:299` |
| `CollectorVerdicts` | `key_decodes` | store get + decode | rendezvous.rs:1273 `crate::db::decode_b64(&result.hybrid_vk)` | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CollectorVerdicts` | `key_len` | store get + decode | rendezvous.rs:1277 `vk.len()` | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `CollectorVerdicts` | `signature_verified` | signature verifier | rendezvous.rs:1270-1276 verify_result_signature | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `CollectorVerdicts` _consumer_ | — | — | classify_result_read input (rendezvous.rs:1265-1285) | `vela-enrollment-policy/src/executor.rs:333` |
| `DeviceRowView` | `device_id` | SQL row / decoded DeviceRow | enroll.rs:146-155 `parse_device_row_turso` (plan_active_device_read); row decode is app glue; rendezvous.rs:687 (None here) | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `DeviceRowView` | `hybrid_vk` | SQL row | rendezvous.rs:690 `row.text(0)`; enroll.rs:151 `row.text(6)` | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `DeviceRowView` | `revoked` | SQL row | rendezvous.rs:695-699 integer/text "0" test; enroll.rs:152 constant 0 after the query | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `DeviceRowView` | `user_id` | SQL row / decoded row | enroll.rs:153 (DeviceRow decode open); rendezvous.rs:692 None | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) ; open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `DeviceRowView` | `enrollment_grant_id` | decoded row | rendezvous.rs:693 None; used by the result path at 1403 | covered: enrollment/pairing plans (08 Executor honesty: enrollment and pairing; enrollment-executors) |
| `DeviceRowView` _consumer_ | — | — | classify_completion_preflight / enroll device read | `vela-enrollment-policy/src/executor.rs:257` |

## Recovery (grant redemption, recovery share, possession proof, WebAuthn recovery)

50 types, 220 fields, 27 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `ConsumedGrantObservation` | `key_epoch` | store get_del + JSON decode | redemption_store.rs:203-212 classify_take over plan_take_grant (get_del); grant JSON decoded in recovery/recover.rs (open) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) ; JSON open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `ConsumedGrantObservation` | `possession` | store get_del + JSON decode | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ConsumedGrantObservation` | `matches_observed_grant` | store get_del vs preflight value | redemption_store.rs:203-212 compares decoded value with the preflight GrantView (enroll_device.rs:300) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ConsumedGrantObservation` _consumer_ | — | — | redemption driver Consumed event (redemption_store::classify_take) | `vela-recovery-policy/src/driver.rs:51` |
| `FinalPolicyObservation` | `enrollment` | derived | enroll_device.rs:328-341 from server-side grant/account observations | covered: constructor mapping (13/15); origin open where the source observation is open |
| `FinalPolicyObservation` | `rekey` | rekey policy over consumed grant epoch | enroll_device.rs:316-326 plan_active_mutation(consumed epoch, RecoveryGrant authority) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalPolicyObservation` _consumer_ | — | — | redemption driver FinalPolicy event (enroll_device.rs:327) | `vela-recovery-policy/src/driver.rs:79` |
| `PublicationStateFacts` | `account_epoch_active` | SQL row | share_store::classify_stage_account (share_store.rs:154) over StageAccountRowView | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` | `active_share_absent` | SQL row | share_store.rs:154 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` | `account_epoch` | SQL row | StageAccountRowView.stored_epoch (recovery/sql.rs:268) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` | `pending_epoch` | derived | share_store.rs:154 (staged epoch vs stored) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` | `pending_split_matches` | SQL row | share_store.rs:154 (recovery_split_id column) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` | `pending_share_present` | derived + row | share_store.rs:154 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PublicationStateFacts` _consumer_ | — | — | pending_publication_can_commit (internal to publication policy; handler passes row observations) | `vela-recovery-policy/src/lib.rs:170` |
| `InitiateObservation (src/lib:303)` | `account_present` | SQL row | webauthn_store::classify_auth_start (initiate.rs:162-171) over ShareRowView (recovery/sql.rs:636) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/lib:303)` | `share_present` | SQL row | webauthn_store::classify_auth_start over ShareRowView (recovery/sql.rs:636-646) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/lib:303)` | `credential_present` | SQL row + JSON decode | recovery/sql.rs:587-626 credential_row (CredentialRowView) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/lib:303)` | `attempt_id_fresh` | store exists | initiate.rs:193-205 probe_auth_slot (exists(auth_state:<user>:<attempt>)) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/lib:303)` | `ttl_secs` | constant | initiate.rs:207 `AUTH_STATE_TTL_SECS` | constant/config (inspection only) |
| `InitiateObservation (src/lib:303)` _consumer_ | — | — | initiate_facts -> plan_initiate (internal: built by webauthn_store::classify_auth_start from the start-observe reads) | `vela-recovery-policy/src/lib.rs:303` |
| `InitiateFacts` | `phase` | derived | initiate_facts lib.rs:350-375 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` | `account_exists` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` | `share_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` | `credential_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` | `attempt_id_fresh` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` | `ttl_positive` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `InitiateFacts` _consumer_ | — | — | initiate_is_authorized / plan_initiate | `vela-recovery-policy/src/lib.rs:317` |
| `RegistrationFacts` | `device_scope` | token/session | recovery/webauthn.rs registration driver `registration_facts` input (session.scope) | open: token/session origin (PASETO verification and extractor unverified) |
| `RegistrationFacts` | `account_matches` | token/session | same (session user vs requested user) | open: token/session origin (PASETO verification and extractor unverified) |
| `RegistrationFacts` | `challenge_pending` | store get_del | recovery/webauthn.rs:540-560 take_register_state | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RegistrationFacts` | `challenge_consumed` | store get_del | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RegistrationFacts` | `credential_valid` | WebAuthn verifier | recovery/webauthn.rs:578-590 finish_passkey_registration | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `RegistrationFacts` | `credential_unique` | SQL row | recovery/webauthn.rs:596+ registration_check_uniqueness (holder_view recovery/sql.rs:680-700) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RegistrationFacts` _consumer_ | — | — | registration_is_authorized / plan_registration (WebAuthn register finish) | `vela-recovery-policy/src/lib.rs:406` |
| `RecoverObservation` | `attempt_source` | store get_del | recover.rs:380-416 take_auth_state (classify_take_auth_state) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` | `user_matches` | store get_del + request | webauthn_store::classify_take_auth_state (user id in the envelope vs request) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` | `attempt_matches` | store get_del + request | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` | `credential_matches_current` | WebAuthn verifier + SQL row | recover.rs:436-446 assertion_result cred_id vs challenge credential id | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `RecoverObservation` | `assertion_valid` | WebAuthn verifier | recover.rs:430-448 finish_passkey_authentication | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `RecoverObservation` | `user_verified` | WebAuthn verifier | recover.rs:439 auth_result.user_verified() | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `RecoverObservation` | `share_present` | SQL row | recover.rs:528-540 finish_account_row_view (share column, recovery/sql.rs:651) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` | `account_epoch_active` | SQL row | recover.rs:528-540 rekey_state column | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` | `stored_epoch` | SQL row | recover.rs:528-540 key_epoch column | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RecoverObservation` _consumer_ | — | — | recover_facts -> plan_recover (internal: WebAuthn recover driver builds it from take/assertion/account observations) | `vela-recovery-policy/src/lib.rs:470` |
| `RecoverFacts` | `phase` | derived | recover_facts lib.rs:540-590 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `user_matches` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `attempt_matches` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `challenge_consumed` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `credential_matches_current` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `assertion_valid` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `user_verified` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `share_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `account_epoch_active` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` | `epoch` | derived | same (observed_recovery_epoch normalization, lib.rs:22-26 of 13) | covered: constructor mapping (13/15); origin open where the source observation is open |
| `RecoverFacts` _consumer_ | — | — | recover_is_authorized / plan_recover | `vela-recovery-policy/src/lib.rs:492` |
| `ProofInitiateObservation` | `account_present` | SQL row | possess.rs:208-218 plan_initiate_account -> InitiateRowView (recovery/sql.rs:329) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofInitiateObservation` | `share_present` | SQL row | InitiateRowView.share_present (recovery/sql.rs:329) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofInitiateObservation` | `commitment_len` | SQL row + base64 decode | initiate_row decoded `recovery_auth_hash` (recovery/sql.rs:300-335) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofInitiateObservation` | `rotation_active` | SQL row | InitiateRowView.rotation_active (rekey_state) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofInitiateObservation` | `attempt_id_fresh` | store exists | possess.rs:224-236 probe_proof_slot (exists(proof_state:<user>:<attempt>)) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofInitiateObservation` | `ttl_secs` | constant | possess.rs:239 `PROOF_STATE_TTL_SECS` | constant/config (inspection only) |
| `ProofInitiateObservation` _consumer_ | — | — | proof_initiate_facts -> plan_proof_initiation (possession InitiateProofIo::observe, possess.rs:207) | `vela-recovery-policy/src/lib.rs:641` |
| `ProofInitiateFacts` | `phase` | derived | proof_initiate_facts lib.rs:700-750 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` | `account_exists` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` | `share_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` | `possession_hash_present` | derived | same (commitment_len > 0) | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` | `attempt_id_fresh` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` | `ttl_positive` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `ProofInitiateFacts` _consumer_ | — | — | proof_initiation_is_authorized / plan_proof_initiation | `vela-recovery-policy/src/lib.rs:659` |
| `PossessionRecoverObservation` | `attempt_source` | store get_del | possess.rs:455-483 take_proof_attempt (classify_attempt, possession_store.rs:211) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `account_present` | SQL row | possession_store.rs:228 classify_proof_account (ProofAccountRowView) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `user_matches` | store envelope + request | possession_store.rs:211 classify_attempt | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `attempt_matches` | store envelope + request | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `proof_verified` | signature verifier | possess.rs:528-536 verify_possession_proof (hybrid verifier) | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `PossessionRecoverObservation` | `account_epoch_active` | SQL row | ProofAccountRowView.rotation_active (recovery/sql.rs:361) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `commitment_len` | SQL row decode | ProofAccountRowView.commitment (recovery/sql.rs:361) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `commitment_epoch` | store envelope | PossessionProofState.key_epoch decoded at possess.rs:471-476 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` | `stored_epoch` | SQL row | ProofAccountRowView.stored_epoch | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `PossessionRecoverObservation` _consumer_ | — | — | possession_recover_facts -> plan_possession_recover (driven by ProofObservation/ProofAccountObservation in possession driver) | `vela-recovery-policy/src/lib.rs:757` |
| `PossessionRecoverFacts` | `phase` | derived | possession_recover_facts lib.rs:800-860 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `account_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `user_matches` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `attempt_matches` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `challenge_consumed` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `proof_verified` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `account_epoch_active` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `commitment_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `commitment_epoch_matches` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` | `epoch` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `PossessionRecoverFacts` _consumer_ | — | — | possession_recover_is_authorized | `vela-recovery-policy/src/lib.rs:738` |
| `CredentialUpdateObservation` | `assertion_valid` | WebAuthn verifier | recover.rs:436 `assertion_valid: true` on finish_passkey_authentication success | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `CredentialUpdateObservation` | `credential_matches_current` | WebAuthn verifier + stored id | recover.rs:437-438 base64 cred_id vs auth_state.credential_id | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `CredentialUpdateObservation` | `needs_update` | WebAuthn verifier | recover.rs:440 auth_result.needs_update() | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `CredentialUpdateObservation` _consumer_ | — | — | credential_update_facts -> plan_credential_update (recover.rs:436) | `vela-recovery-policy/src/lib.rs:906` |
| `CredentialUpdateFacts` | `assertion_valid` | derived | credential_update_facts lib.rs:928-936 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `CredentialUpdateFacts` | `credential_matches_current` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `CredentialUpdateFacts` | `needs_update` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `CredentialUpdateFacts` _consumer_ | — | — | credential_update_is_authorized / plan_credential_update | `vela-recovery-policy/src/lib.rs:916` |
| `EnrollmentGrantFacts` | `epoch` | store get + JSON decode | enroll_device.rs:133 `grant.key_epoch` from observe_enroll_grant (recover.rs:672-690) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentGrantFacts` | `possession` | store get + JSON decode | enroll_device.rs:134 `grant.possession` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentGrantFacts` _consumer_ | — | — | plan_enrollment_preflight (enroll_device.rs:132) | `vela-recovery-policy/src/lib.rs:981` |
| `EnrollmentAccountFacts` | `stored_epoch` | SQL row | enroll_device.rs:464 from EnrollmentAccountRowView.stored_epoch (recovery/sql.rs:258) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountFacts` | `epoch_active` | SQL row | enroll_device.rs:465 rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountFacts` | `credential_id_matches` | SQL row + stored grant | enroll_device.rs:466 comparison of row credential id with the grant | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountFacts` | `commitment_len` | SQL row + decode | enroll_device.rs:467 EnrollmentAccountRowView.commitment_len | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountFacts` _consumer_ | — | — | plan_enrollment_preflight (enroll_device.rs:464,506) | `vela-recovery-policy/src/lib.rs:991` |
| `EnrollmentPreflightObservation` | `grant` | store get + JSON decode | enroll_device.rs:112-117 observe_enroll_grant | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentPreflightObservation` | `account` | SQL row (conditional) | enroll_device.rs:122-128 enrollment_account_preflight -> EnrollmentAccountRowView | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentPreflightObservation` _consumer_ | — | — | plan_enrollment_preflight (enroll_device.rs:139) | `vela-recovery-policy/src/lib.rs:1015` |
| `EnrollmentFacts` | `phase` | derived | enrollment_facts lib.rs:1830-1900 | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `account_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `user_matches` | derived | same (= grant_present; store-key binding, 15 `Unproved correspondence`) | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `grant_live` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `grant_consumed` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `credential_matches_current` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `possession_grant` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `possession_hash_present` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `public_keys_valid` | derived | same (1600/2624 decoded lengths) | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `account_epoch_active` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `grant_epoch` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` | `account_epoch` | derived | same | covered: constructor mapping (13/15); origin open where the source observation is open |
| `EnrollmentFacts` _consumer_ | — | — | enrollment_facts / plan_enrollment (driver final policy) | `vela-recovery-policy/src/lib.rs:1729` |
| `EnrollmentObservation` | `grant_present` | store get + JSON decode | enroll_device.rs:112-117 observe_enroll_grant (non-consuming get) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `grant_consumed` | store get_del | enroll_device.rs:300 classify_take over get_del(enroll_grant) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `consumed_matches_observed` | store get_del vs preflight | redemption_store.rs:203-212 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `account_present` | SQL row | enroll_device.rs:464 EnrollmentAccountRowView | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `grant_possession` | store get + JSON decode | enroll_device.rs:134 / 328 `consumed.possession` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `grant_epoch` | store get + JSON decode | enroll_device.rs:324 `consumed.key_epoch` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `stored_epoch` | SQL row | enroll_device.rs:337 `self.account.stored_epoch` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `account_epoch_active` | SQL row | enroll_device.rs:338 `self.account.epoch_active` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `credential_id_matches` | SQL row + stored grant | enroll_device.rs:339 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `commitment_len` | SQL row + decode | enroll_device.rs:340 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentObservation` | `hybrid_ek_len` | request body | enroll_device.rs:341 `self.hybrid_ek.len()` (validated 1600 at enroll_device.rs:90) | open: request body (unverified parsing) |
| `EnrollmentObservation` | `hybrid_vk_len` | request body | enroll_device.rs:342 `self.hybrid_vk.len()` (validated 2624 at enroll_device.rs:99) | open: request body (unverified parsing) |
| `EnrollmentObservation` _consumer_ | — | — | enrollment_facts (enroll_device.rs:328, device/enroll.rs:205) | `vela-recovery-policy/src/lib.rs:1756` |
| `InitiateObservation (src/possession_driver:66)` | `account_present` | SQL row | possession_store.rs:164 classify_initiate over InitiateRowView (recovery/sql.rs:329) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/possession_driver:66)` | `share_present` | SQL row | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/possession_driver:66)` | `commitment` | SQL row decode | InitiateRowView.commitment (recovery/sql.rs:300-335) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/possession_driver:66)` | `rotation_active` | SQL row | InitiateRowView.rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/possession_driver:66)` | `attempt_id_fresh` | store exists | possess.rs:224-236 probe_proof_slot | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateObservation (src/possession_driver:66)` | `ttl_secs` | constant | possess.rs:239 PROOF_STATE_TTL_SECS | constant/config (inspection only) |
| `InitiateObservation (src/possession_driver:66)` _consumer_ | — | — | begin_initiation (possession driver) | `vela-recovery-policy/src/possession_driver.rs:66` |
| `ProofAccountObservation` | `account_present` | SQL row | possession_store.rs:228 classify_proof_account (recovery/sql.rs:361) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountObservation` | `account_epoch_active` | SQL row | ProofAccountRowView.rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountObservation` | `commitment` | SQL row decode | ProofAccountRowView.commitment | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountObservation` | `stored_epoch` | SQL row | ProofAccountRowView.stored_epoch | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountObservation` _consumer_ | — | — | possession driver after attempt consumption (possess.rs:515) | `vela-recovery-policy/src/possession_driver.rs:397` |
| `ProofObservation` | `verified` | signature verifier | possess.rs:529-537 `verify_possession_proof(allow_legacy_v1, commitment, attempt, presented)` | open: signature verdict is an input (08 Handler I/O outside the other executors) |
| `ProofObservation` _consumer_ | — | — | possession driver verify step (possess.rs:529) | `vela-recovery-policy/src/possession_driver.rs:408` |
| `ProofAttemptView` | `user` | store key / request | possess.rs:271-274 from `self.user_id` (request body user_id, possess.rs:151) | open: request body (unverified parsing) |
| `ProofAttemptView` | `attempt` | store key / request | possess.rs:272 from `self.recovery_id` (fresh v4, possess.rs:152) | open: OS randomness (plan step O11 / T9) |
| `ProofAttemptView` | `key_epoch` | SQL row | possess.rs:273 `self.key_epoch`, set by initiate_epoch (possession_store.rs:191) from InitiateRowView | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAttemptView` _consumer_ | — | — | plan_store_challenge / classify_attempt (store envelope) | `vela-recovery-policy/src/possession_store.rs:63` |
| `EnrollmentGrantView` | `key_epoch` | driver permit | possess.rs:555 `permit.epoch()` (possession driver decision over SQL row) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentGrantView` _consumer_ | — | — | plan_issue_grant | `vela-recovery-policy/src/possession_store.rs:71` |
| `InitiateRowView` | `share_present` | SQL row column 0 | recovery/sql.rs:329-336 (`recovery_share`) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateRowView` | `commitment` | SQL row column 1 + base64 | recovery/sql.rs:300-325 commitment_cell | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateRowView` | `key_epoch` | SQL row column 2 | recovery/sql.rs:331 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateRowView` | `rotation_active` | SQL row column 3 | recovery/sql.rs:332 (`rekey_state`) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `InitiateRowView` _consumer_ | — | — | classify_initiate / initiate_epoch | `vela-recovery-policy/src/possession_store.rs:78` |
| `ProofAccountRowView` | `commitment` | SQL row column 0 + base64 | recovery/sql.rs:361-368 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountRowView` | `stored_epoch` | SQL row column 1 | recovery/sql.rs:363 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountRowView` | `rotation_active` | SQL row column 2 | recovery/sql.rs:364 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ProofAccountRowView` _consumer_ | — | — | classify_proof_account | `vela-recovery-policy/src/possession_store.rs:90` |
| `ShareActorObservation` | `authenticated` | token/session (constant) | recovery/mod.rs:67 literal `true` | open: token/session origin (PASETO verification and extractor unverified) |
| `ShareActorObservation` | `device_active` | token/session (constant) | recovery/mod.rs:68 literal `true` | open: token/session origin (PASETO verification and extractor unverified) |
| `ShareActorObservation` | `scoped_to_session_account` | constant/code shape | recovery/mod.rs:69 literal `true`; single session.user_id | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareActorObservation` _consumer_ | — | — | recovery_share_interpreter! (recovery/mod.rs:268,404,533,649) | `vela-recovery-policy/src/recovery_share_driver.rs:54` |
| `ShareRequestObservation` | `operation` | constant per handler | recovery/mod.rs:269,405,534,650 (Stage/Finalize/Delete/Read) | constant/config (inspection only) |
| `ShareRequestObservation` | `actor` | derived | recovery/mod.rs:66-71 actor() | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRequestObservation` | `declared_epoch` | request body/header | recovery/mod.rs:271 `body.key_epoch`; :407 body; :535 X-Vela-Epoch header (recovery/mod.rs:637-644); :651 constant 0 for Read | open: request body (unverified parsing) |
| `ShareRequestObservation` | `split_id_present` | constant `true` | recovery/mod.rs:272,406,536,652 | constant/config (inspection only) |
| `ShareRequestObservation` | `share_present` | constant `true` / decoded body | recovery/mod.rs:273,407,537,653 (Stage: `!share_bytes.is_empty()` at :274) | open: request body (unverified parsing) |
| `ShareRequestObservation` | `device_authority` | constant `true` after policy check | recovery/mod.rs:275,409,539,655; `recovery_mutation_permit` (recovery/mod.rs:42-55) is fed the same request epoch | open: request body (unverified parsing) |
| `ShareRequestObservation` | `split` | body split id / 0 | recovery/mod.rs:276,408 `split_token(body.split_id)`; :540,656 constant 0 | open: request body (unverified parsing) |
| `ShareRequestObservation` _consumer_ | — | — | recovery_share_interpreter! (put/finalize/delete/get) | `vela-recovery-policy/src/recovery_share_driver.rs:70` |
| `StageAccountObservation` | `account_present` | SQL row | share_store.rs:154 over StageAccountRowView (recovery/sql.rs:268) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountObservation` | `stored_epoch` | SQL row | StageAccountRowView.stored_epoch | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountObservation` | `rotation_active` | SQL row | StageAccountRowView.rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountObservation` | `active_share_matches` | SQL row vs request copy | share_store.rs:154 compares stored share text with `stored_share` (body-derived) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) ; value open: request body (unverified parsing) |
| `StageAccountObservation` | `active_split_matches` | SQL row vs request copy | share_store.rs:154 compares stored split id with request split | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) ; value open: request body (unverified parsing) |
| `StageAccountObservation` _consumer_ | — | — | classify_stage_account (share_store.rs:154) | `vela-recovery-policy/src/recovery_share_driver.rs:98` |
| `FinalizeAccountObservation` | `account_present` | SQL row | share_store.rs:198 over FinalizeAccountRowView (recovery/sql.rs:278) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountObservation` | `stored_epoch` | SQL row | FinalizeAccountRowView.stored_epoch | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountObservation` | `rotation_active` | SQL row | FinalizeAccountRowView.rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountObservation` | `active_split_matches` | SQL row vs request copy | share_store.rs:198 vs request split id | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountObservation` _consumer_ | — | — | classify_finalize_account (share_store.rs:198) | `vela-recovery-policy/src/recovery_share_driver.rs:121` |
| `ReadObservation` | `account_present` | SQL row | share_store.rs:238 over ShareRowView (recovery/sql.rs:287) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ReadObservation` | `share_present` | SQL row | ShareRowView.share | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ReadObservation` _consumer_ | — | — | classify_read_share (share_store.rs:238) | `vela-recovery-policy/src/recovery_share_driver.rs:141` |
| `GrantView` | `key_epoch` | store value JSON | recover.rs:682-688 decoded RecoveryEnrollGrant (get_del); JSON decode open (15) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) ; JSON open: row/body decoding outside the store model (store.rs DeviceVerdicts note) |
| `GrantView` | `credential_id` | store value JSON | recover.rs:684; JSON decode open | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `GrantView` | `possession` | store value JSON | recover.rs:685; JSON decode open | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `GrantView` _consumer_ | — | — | classify_take / plan_take_grant | `vela-recovery-policy/src/redemption_store.rs:41` |
| `AuthorityRowView` | `credential_id` | SQL row column 0 | recovery/sql.rs:228-231 `SelectAuthority` (recovery_webauthn_cred_id) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthorityRowView` | `auth_hash` | SQL row column 1 | recovery/sql.rs:229 (empty filtered, matching the insert guard) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthorityRowView` _consumer_ | — | — | classify_grant_peek / redemption preflight | `vela-recovery-policy/src/redemption_store.rs:110` |
| `EnrollmentAccountRowView` | `stored_epoch` | SQL row column 0 | recovery/sql.rs:258-266 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountRowView` | `rotation_active` | SQL row column 1 | recovery/sql.rs:262 (`rekey_state`) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountRowView` | `credential_id` | SQL row column 2 | recovery/sql.rs:264 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountRowView` | `commitment_len` | SQL row column 3 + base64 | recovery/sql.rs:246-256 (decoded only when epoch/rotation gate open) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountRowView` _consumer_ | — | — | EnrollmentAccountView adapter / enrollment_account_preflight | `vela-recovery-policy/src/redemption_store.rs:119` |
| `EnrollmentAccountView` | `stored_epoch` | derived (copy) | enroll_device.rs:464 (EnrollmentAccountRowView.stored_epoch) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountView` | `epoch_active` | derived (copy) | enroll_device.rs:465 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountView` | `credential_id_matches` | derived | enroll_device.rs:466 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountView` | `commitment_len` | derived (copy) | enroll_device.rs:467 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `EnrollmentAccountView` _consumer_ | — | — | four-field structural adapter -> EnrollmentAccountFacts (enroll_device.rs:464-470) | `vela-recovery-policy/src/redemption_store.rs:282` |
| `StageAccountRowView` | `stored_epoch` | SQL row column 0 | recovery/sql.rs:268-275 `SelectStageAccount` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountRowView` | `rotation_active` | SQL row column 1 | recovery/sql.rs:270 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountRowView` | `active_share` | SQL row column 2 | recovery/sql.rs:271 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountRowView` | `active_split` | SQL row column 3 | recovery/sql.rs:272 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `StageAccountRowView` _consumer_ | — | — | classify_stage_account | `vela-recovery-policy/src/share_store.rs:55` |
| `FinalizeAccountRowView` | `stored_epoch` | SQL row column 0 | recovery/sql.rs:278-284 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountRowView` | `rotation_active` | SQL row column 1 | recovery/sql.rs:280 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountRowView` | `active_split` | SQL row column 2 | recovery/sql.rs:281 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinalizeAccountRowView` _consumer_ | — | — | classify_finalize_account | `vela-recovery-policy/src/share_store.rs:65` |
| `ShareRowView (src/share_store:75)` | `share` | SQL row column 0 | recovery/sql.rs:287-294 `SelectShare` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRowView (src/share_store:75)` | `split_id` | SQL row column 1 | recovery/sql.rs:289 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRowView (src/share_store:75)` | `epoch` | SQL row column 2 | recovery/sql.rs:290 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRowView (src/share_store:75)` _consumer_ | — | — | classify_read_share | `vela-recovery-policy/src/share_store.rs:75` |
| `RegistrationStartObservation` | `account_present` | SQL row | recovery/webauthn.rs:214-230 credential_row (recovery/sql.rs:589) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RegistrationStartObservation` | `credential` | SQL row + JSON decode | recovery/webauthn.rs:214-230 credential_row | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `RegistrationStartObservation` _consumer_ | — | — | WebAuthn registration-start driver | `vela-recovery-policy/src/webauthn_driver.rs:114` |
| `RegistrationVerificationObservation` | `credential_valid` | WebAuthn verifier | recovery/webauthn.rs:565-590 `finish_passkey_registration` | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `RegistrationVerificationObservation` _consumer_ | — | — | finish_passkey_registration observation (recovery/webauthn.rs:578) | `vela-recovery-policy/src/webauthn_driver.rs:456` |
| `AuthStartObservation` | `account_present` | SQL row | initiate.rs:162-171 webauthn_share_row_view (recovery/sql.rs:636) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStartObservation` | `share_present` | SQL row | initiate.rs:162-171 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStartObservation` | `credential` | SQL row + JSON decode | initiate.rs:172-186 credential_row (recovery/sql.rs:589) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStartObservation` | `attempt_id_fresh` | store exists | initiate.rs:193-205 probe_auth_slot | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStartObservation` | `ttl_secs` | constant | initiate.rs:208 AUTH_STATE_TTL_SECS | constant/config (inspection only) |
| `AuthStartObservation` _consumer_ | — | — | auth_start_observe (initiate.rs:161) | `vela-recovery-policy/src/webauthn_driver.rs:961` |
| `AuthFinishContextObservation` | `account_present` | SQL row | recover.rs:340-352 webauthn_share_row_view | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthFinishContextObservation` | `share_present` | SQL row | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthFinishContextObservation` | `credential` | SQL row + JSON decode | recover.rs:353-367 credential_row | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthFinishContextObservation` | `attempt_id_present` | request body | recover.rs:369 `self.recovery_id.is_some()` (body attempt id) | open: request body (unverified parsing) |
| `AuthFinishContextObservation` _consumer_ | — | — | auth_finish_context (recover.rs:339) | `vela-recovery-policy/src/webauthn_driver.rs:1321` |
| `AssertionObservation` | `assertion_valid` | WebAuthn verifier | recover.rs:436 `finish_passkey_authentication` result | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `AssertionObservation` | `user_verified` | WebAuthn verifier | recover.rs:439 `auth_result.user_verified()` | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `AssertionObservation` | `credential_matches` | WebAuthn verifier + stored id | recover.rs:437-438 `B64.encode(auth_result.cred_id()) == auth_state.credential_id` | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `AssertionObservation` | `needs_update` | WebAuthn verifier | recover.rs:440 `auth_result.needs_update()` | open: WebAuthn verdict is an input (recovery-executors: assumptions) |
| `AssertionObservation` _consumer_ | — | — | auth_finish_verify (recover.rs:425) | `vela-recovery-policy/src/webauthn_driver.rs:1348` |
| `AuthAccountObservation` | `account_present` | SQL row | webauthn_store::classify_finish_account over FinishAccountRowView (recovery/sql.rs:651) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthAccountObservation` | `account_epoch_active` | SQL row | FinishAccountRowView.rotation_active | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthAccountObservation` | `share_present` | SQL row | FinishAccountRowView.share | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthAccountObservation` | `stored_credential_matches` | SQL row vs challenge | classify_finish_account compares stored credential id | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthAccountObservation` | `stored_epoch` | SQL row | FinishAccountRowView.stored_epoch | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthAccountObservation` _consumer_ | — | — | auth_finish_account (recover.rs:519) | `vela-recovery-policy/src/webauthn_driver.rs:1368` |
| `AuthStateView` | `user` | store envelope JSON | initiate.rs:391-396 decode_auth_attempt | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStateView` | `attempt` | store envelope JSON | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStateView` | `credential_id` | store envelope JSON | same | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `AuthStateView` _consumer_ | — | — | classify_take_auth_state | `vela-recovery-policy/src/webauthn_store.rs:104` |
| `CredentialGrantView` | `key_epoch` | driver permit | recover.rs:580 `permit_epoch` (WebAuthn finish driver decision over SQL row) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `CredentialGrantView` | `credential_id` | SQL row + challenge | recover.rs:581 challenge-bound credential id | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `CredentialGrantView` | `possession` | constant | recover.rs:583 literal `false` for a WebAuthn grant | constant/config (inspection only) |
| `CredentialGrantView` _consumer_ | — | — | plan_store_credential_grant | `vela-recovery-policy/src/webauthn_store.rs:112` |
| `ShareRowView (src/webauthn_store:121)` | `account_present` | SQL row | recovery/sql.rs:636-646 (`SELECT recovery_share FROM users`) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRowView (src/webauthn_store:121)` | `share_present` | SQL row | recovery/sql.rs:689 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `ShareRowView (src/webauthn_store:121)` _consumer_ | — | — | classify_auth_start / classify_finish_context | `vela-recovery-policy/src/webauthn_store.rs:121` |
| `CredentialRowView` | `account_present` | SQL row | recovery/sql.rs:587-626 credential_row | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `CredentialRowView` | `credential` | SQL row + JSON decode | recovery/sql.rs:600-625 StoredCredentialObservation (Missing/Present/Corrupt) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `CredentialRowView` _consumer_ | — | — | classify_auth_start / finish context | `vela-recovery-policy/src/webauthn_store.rs:129` |
| `FinishAccountRowView` | `share` | SQL row column 0 | recovery/sql.rs:651-659 `SelectFinishAccount` | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinishAccountRowView` | `stored_epoch` | SQL row column 1 | recovery/sql.rs:653 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinishAccountRowView` | `rotation_active` | SQL row column 2 | recovery/sql.rs:654 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinishAccountRowView` | `stored_credential_id` | SQL row column 3 | recovery/sql.rs:655 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinishAccountRowView` | `split_id` | SQL row column 4 | recovery/sql.rs:656 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `FinishAccountRowView` _consumer_ | — | — | classify_finish_account | `vela-recovery-policy/src/webauthn_store.rs:136` |
| `LegacyCredentialRowView` | `user` | SQL row column 0 | recovery/sql.rs:664-675 legacy_credential_rows (backfill scan) | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `LegacyCredentialRowView` | `credential` | SQL row column 1 | recovery/sql.rs:668 | covered: recovery plans (08 Executor honesty: recovery; recovery-executors) |
| `LegacyCredentialRowView` _consumer_ | — | — | startup credential backfill | `vela-recovery-policy/src/webauthn_store.rs:203` |

## Vault chunks, ORAM, sync, rotation and device capsules (vela-rekey-policy)

14 types, 57 fields, 1 open.

| Type | Field | Producer kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| `ChunkRowView` | `chunk_id` | SQL row column 0 | vault/sql.rs:245-253 `SelectChunkRow` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `user_id` | SQL row column 1 | vault/sql.rs:248 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `version` | SQL row column 2 | vault/sql.rs:249 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `lamport_clock` | SQL row column 3 | vault/sql.rs:250 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `last_writer` | SQL row column 4 | vault/sql.rs:251 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `ciphertext` | SQL row column 5 | vault/sql.rs:251 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` | `epoch` | SQL row column 6 | vault/sql.rs:252 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ChunkRowView` _consumer_ | — | — | classify_chunk_read / plan_read_chunk (vault/chunk.rs:70) | `vela-rekey-policy/src/executor.rs:248` |
| `InventoryRowView` | `chunk_id` | SQL row column 0 | vault/sql.rs:271-276 `SelectInventory` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `InventoryRowView` | `version` | SQL row column 1 | vault/sql.rs:273 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `InventoryRowView` | `lamport_clock` | SQL row column 2 | vault/sql.rs:274 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `InventoryRowView` _consumer_ | — | — | rotation completeness probes / inventory row set | `vela-rekey-policy/src/executor.rs:260` |
| `PendingRowView` | `epoch` | SQL row column 0 | vault/sql.rs:263-267 `SelectPendingCapsule` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `PendingRowView` _consumer_ | — | — | capsule acknowledgement / pending epoch | `vela-rekey-policy/src/executor.rs:268` |
| `ExistsView` | `found` | SQL row existence | vault/sql.rs:256-259 `exists_view(rows)` (bool, folded into the ORAM observation) | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ExistsView` _consumer_ | — | — | ORAM bucket probe (classifier built inside the executor plan) | `vela-rekey-policy/src/executor.rs:274` |
| `KeyStateView` | `key_epoch` | SQL row column 0 | vault/sql.rs:283-293 `SelectKeyState` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `rekey_state` | SQL row column 1 | vault/sql.rs:285 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `rekey_started_at` | SQL row column 2 | vault/sql.rs:286 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `rekey_starter` | SQL row column 3 | vault/sql.rs:287 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `rekey_id` | SQL row column 4 | vault/sql.rs:288 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `last_rekey_id` | SQL row column 5 | vault/sql.rs:289 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` | `last_rekey_epoch` | SQL row column 6 | vault/sql.rs:290 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `KeyStateView` _consumer_ | — | — | load_key_state (vault/rekey.rs:100-125) | `vela-rekey-policy/src/executor.rs:280` |
| `OramRowView` | `version` | SQL row column 0 | vault/sql.rs:307-313 `SelectOramRow` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `OramRowView` | `lamport_clock` | SQL row column 1 | vault/sql.rs:309 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `OramRowView` | `last_writer` | SQL row column 2 | vault/sql.rs:310 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `OramRowView` | `ciphertext` | SQL row column 3 | vault/sql.rs:311 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `OramRowView` _consumer_ | — | — | ORAM path read/write | `vela-rekey-policy/src/executor.rs:315` |
| `SyncRowView` | `chunk_id` | SQL row column 0 | vault/sql.rs:318-325 `SelectSyncManifest` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `SyncRowView` | `version` | SQL row column 1 | vault/sql.rs:320 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `SyncRowView` | `lamport_clock` | SQL row column 2 | vault/sql.rs:321 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `SyncRowView` | `last_writer` | SQL row column 3 | vault/sql.rs:322 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `SyncRowView` _consumer_ | — | — | sync manifest listing | `vela-rekey-policy/src/executor.rs:333` |
| `CapsuleView` | `capsule` | SQL row column 0 | vault/sql.rs:329-335 `SelectCapsule` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CapsuleView` | `capsule_epoch` | SQL row column 1 | vault/sql.rs:331 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CapsuleView` | `rotation_id` | SQL row column 2 | vault/sql.rs:332 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CapsuleView` _consumer_ | — | — | get_capsule (capsule delivery) | `vela-rekey-policy/src/executor.rs:363` |
| `DeviceListRowView` | `id` | SQL row column 0 | vault/sql.rs:339-356 `SelectDeviceList` | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `user_id` | SQL row column 1 | vault/sql.rs:341 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `device_name` | SQL row column 2 | vault/sql.rs:342 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `device_type` | SQL row column 3 | vault/sql.rs:343 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `last_active` | SQL row column 4 | vault/sql.rs:344 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `hybrid_ek` | SQL row column 5 | vault/sql.rs:345 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `hybrid_vk` | SQL row column 6 | vault/sql.rs:346 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `enrolled_by` | SQL row column 7 | vault/sql.rs:347 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `rms_capsule` | SQL row column 8 | vault/sql.rs:348 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `revoked` | SQL row column 9 | vault/sql.rs:349 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `revoked_at` | SQL row column 10 | vault/sql.rs:350 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `revoked_by` | SQL row column 11 | vault/sql.rs:351 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `created_at` | SQL row column 12 | vault/sql.rs:352 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` | `rekey_capable` | SQL row column 13 | vault/sql.rs:353 | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `DeviceListRowView` _consumer_ | — | — | device listing (`list_devices` is outside the vault executor proof set, 08) | `vela-rekey-policy/src/executor.rs:387` |
| `StartFacts` | `no_oram` | derived (internal) | rekey_driver start path; ORAM probe observation | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `StartFacts` | `all_devices_rekey_capable` | derived (internal) | device-list observation | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `StartFacts` | `all_devices_acknowledged` | derived (internal) | capsule acknowledgements | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `StartFacts` _consumer_ | — | — | start_is_authorized / plan_start (only constructed inside the crate/tests; no server literal) | `vela-rekey-policy/src/lib.rs:132` |
| `CommitFacts` | `authority` | derived (internal) | attempt authority from the key-state row | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitFacts` | `chunk_shadows_complete` | derived (internal) | chunk-shadow completeness probe | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitFacts` | `device_capsules_complete` | derived (internal) | device-capsule completeness probe | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitFacts` _consumer_ | — | — | commit_is_authorized / plan_commit (internal; no server literal) | `vela-rekey-policy/src/lib.rs:257` |
| `TimeoutFacts` | `expired` | SQL row + clock | vault/rekey.rs:147-152 parses `rekey_started_at` and compares with `Utc::now()` | open: clock read (TTL/scheduler choice) |
| `TimeoutFacts` | `rotation_id_present` | SQL row | vault/rekey.rs:153 `ks.rotation_id.is_some()` (KeyStateView.rekey_id) | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `TimeoutFacts` _consumer_ | — | — | plan_timeout (vault/rekey.rs:155) | `vela-rekey-policy/src/lib.rs:346` |
| `CommitReplayFacts` | `target_epoch` | derived (internal) | commit request epoch | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitReplayFacts` | `recorded_epoch` | derived (internal) | `last_rekey_epoch` row cell | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitReplayFacts` | `rotation_id_present` | derived (internal) | `rekey_id` row cell | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitReplayFacts` | `rotation_id_matches` | derived (internal) | request rotation id vs row cell | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `CommitReplayFacts` _consumer_ | — | — | authorize_commit_replay (internal; no server literal) | `vela-rekey-policy/src/lib.rs:395` |
| `ReadEpochObservation` | `epoch` | SQL row | vault/chunk.rs:47-56 `crate::vault::rekey::read_epoch` (`SELECT key_epoch FROM users WHERE id = ?`) | covered: vault/rotation plans (08 Executor honesty: vault, rotation and device capsules; vault-executors) |
| `ReadEpochObservation` _consumer_ | — | — | upload/read driver ReadEpoch effect (vault/chunk.rs:53) | `vela-rekey-policy/src/vault_upload_driver.rs:843` |

## Enum-valued observations (no per-field payload)

These are consumed exactly like the structs above, but carry no fields; the
producer is the whole value. Same coverage labels apply.

| Area | Type | Kind | Producer (file:line) | Covered by / open |
|---|---|---|---|---|
| sharing | `SendResultObservation` | send transaction outcome | run_writes/commit classifier (share/mod.rs:216-280) | covered: share plans |
| sharing | `ShareEvent / ShareStage` | driver event/phase | built by the proved interpreter loop | covered: share interpreter |
| send-links | `ConsumeObservation` | atomic view-consume UPDATE | store.rs:502 classify_send_consume (SQL store.rs:1273) | covered: send-link plans |
| send-links | `ReadObservation` | row SELECT after consume | store.rs:562 classify_send_read | covered: send-link plans |
| session | `ChallengeObservation` | challenge take | store.rs:1027 classify_login_challenge over plan_take_challenge (store.rs:557); challenge-take-adapter evidence | covered: session plans |
| session | `DeviceObservation` | device row | store.rs:1046 classify_login_device | covered: session plans |
| session | `VerifierObservation` | signature verifier | auth/verify.rs:160-190 verify_auth_signature | open: verifier verdict |
| session | `TokenIssueObservation` | PASETO issuance | verify.rs:271-289 / account/mod.rs:319-331 | open: token |
| session | `TokenTrackObservation` | JTI store write | store.rs:1075 classify_track_jti | covered: session plans |
| session | `BackoffResetObservation` | backoff reset store | verify.rs:226-268 plan_reset_login_streak | covered: session plans |
| session | `LimitObservation` | rate limiter | store.rs:1335 classify_keys_limit etc. | covered: session plans |
| session | `SessionLookup / SessionsList / SessionKeysLookup` | SQL row read | store.rs:1239,1249,1355 | covered: session plans |
| enrollment | `StoreObservation / TakeObservation / DeviceInsertObservation` | pairing store/SQL outcomes | classifiers in vela-enrollment-policy/src/pairing_driver.rs / executor.rs | covered: enrollment plans |
| enrollment | `DeviceObservation (enroll)` | active device row | device/enroll.rs:143-165 plan_active_device_read | covered: enrollment plans |
| recovery | `CommitmentObservation` | decoded commitment cell | recovery/sql.rs:298-325 commitment_cell | covered: recovery plans |
| recovery | `GrantTake / ProofAttemptTake / AuthStateTake` | atomic get_del envelopes | redemption_store.rs:203; possession_store.rs:211; webauthn_store.rs classify_take_auth_state | covered: recovery plans |
| recovery | `ShareDecodeObservation` | staged share base64 decode | recover.rs:545-556 + webauthn_store.rs:490 classify_share_release | covered: recovery plans |
| recovery | `RekeyObservation` | rekey permit at consumed epoch | enroll_device.rs:316-326 plan_active_mutation | covered: rekey policy + recovery plans |
| vault | `ProbeObservation / CapsuleObservation / ReadOutcome` | rotation probes and chunk reads | vault/sql.rs + vela-rekey-policy/src/executor.rs classifiers | covered: vault plans |
| vault | `KeyStateObservation` | key-state row | vault/rekey.rs:99-125 load_key_state | covered: vault plans |

## Findings

1. **O13c — web-session grant epoch is body-supplied** (`GrantObservation.declared_epoch`,
   `web_session/mod.rs:768`). The checked `plan_grant` only tests `>= INITIAL_EPOCH`
   (`vela-session-policy/src/lib.rs:99-121,205-217`); the binding to the live account
   epoch is the SQL CAS in `StoreStmt::GrantWebSession` (`store.rs:2461-2470`). A stale
   or forged value fails the CAS, but it is request-supplied context, not a proved
   observation. O13c should derive it from the row or prove the CAS as the binding.
2. **O13e — recovery-share epoch authority is self-asserted** (`body.key_epoch` at
   `recovery/mod.rs:271,407`; `X-Vela-Epoch` at `recovery/mod.rs:637`;
   `recovery_mutation_permit` at `recovery/mod.rs:42-55` passes it as both declared and
   authority epoch). `ShareRequestObservation.device_authority` is consequently a
   constant `true` (`recovery/mod.rs:275,409,539,655`); the only binding is the SQL
   predicate `key_epoch = ?` (`vela-recovery-policy/src/share_store.rs:264-277`).
3. **O13c — login identity comes from the request body** (`device_id_str =
   body.device_id`, `auth/verify.rs:321`; row lookup `auth/verify.rs:123`; verifier
   context `auth/verify.rs:175`). Expected for an unauthenticated endpoint, but the
   driver's device and verifier observations are decided over a body-chosen identity.
4. **O13a — share-EK freshness compares a body timestamp** (`signed_at`, canonicalised
   and skew-bounded at `share/mod.rs:1038-1046`, compared at `share/mod.rs:972-975`).
   The value is signed by the device (`share/mod.rs:942-944`), so it is authenticated,
   but it is not clock- or row-derived.
5. **O13d — pairing claim key material is body-supplied, length-checked only**
   (`ClaimObservation` from `rendezvous.rs:284-301`; policy at `lib.rs:106-118`). The
   completion path verifies the *stored* claim (`claim_key_source: StoredClaim`,
   `rendezvous.rs:620-676,732-750`), and the redemption path records request-body key
   lengths (`recovery/enroll_device.rs:341-342`) after exact 1600/2624 checks.
6. **O13c/d — middleware's first admission call uses placeholders**
   (`account_present: true`, `device_row_active: true`, `middleware.rs:116-124`); the
   real reads follow at `middleware.rs:143-149` and `181-188`.
7. **O13a-f — every actor observation is a constant `true`** at its call site
   (`device/revoke.rs:207-210`, `account/delete.rs:212-216`, `recovery/mod.rs:65-71`,
   `web_session/mod.rs:843-846,1443-1446`). Its truth rests on the `DeviceSession`/
   `AuthSession` extractor and PASETO verification, which remain open. This is the
   largest single open origin in the inventory.
8. **O11 — OS entropy is observed only as a length/boolean** (`getrandom` at
   `auth/challenge.rs:183`, `recovery/possess.rs:247`; `Uuid::new_v4` ids such as
   `share/mod.rs:355`, `recovery/enroll_device.rs:354`, `recovery/possess.rs:152`).
9. **O9 — clock reads enter observations directly** (`send.rs:191,291`, `share/mod.rs:356`,
   `web_session/mod.rs:769,996`, `vault/rekey.rs:147-152`). TTL expiry is a scheduler
   choice today; O9 must model it adversarially.
10. **O1 — `SendObservation.recipient_has_share_ek` is a literal `true`** in the driver
   (`vela-share-policy/src/driver.rs:664`) after the recipient probe passed
   (`driver.rs:647`, producer `share/mod.rs:157-166` / `store.rs:856`). Recorded so the
   fact is not over-credited as an independent observation.
11. **O12 — `EnrollmentAccountView` is a structural copy** into
   `EnrollmentAccountFacts` (`redemption_store.rs:282-287` -> `enroll_device.rs:464-470`);
   08 states it is conformance-checked, not extracted.
12. **O1 — `DeviceListRowView` has plan coverage but no policy consumer**
   (`vault/sql.rs:339-356`; 08 lists `list_devices` among the vault items not covered).

## What this inventory does not establish

- It is a source-reading inventory, not a refinement proof. Every `covered:`
  row cites an existing proof whose scope is exactly the statement/plan or
  constructor named; the store's linearizability and atomicity stay assumptions
  (08, *Executor honesty* assumptions).
- Column indices are the handler's decode positions; the SQL text is pinned in
  the plan shape lemmas, not re-derived here.
- Fields marked `open: request body` are parsed by serde/base64 in the handler
  and have no checked decoder-to-policy link. Some of those values are only
  used as bounded request parameters (TTL, view caps, capsule length), which is
  a different obligation from authenticated context (see O13 findings).
- I did not run any build, extraction or F* check; all evidence is quoted from
  the repository's existing proof logs at commit 94696ed plus this worktree.
