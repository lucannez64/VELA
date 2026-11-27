# Desktop feature map

What a desktop user can do, in their words, and what proves each feature
works in the real app. Use these IDs when asking for or reporting a change
("verify D3 on both front ends"). `scripts/check-feature-map.py` fails when a
proof named here no longer exists, so a renamed screenshot or test cannot
silently drop a feature's coverage.

Proof kinds:

- `uitest:<shot>`: `desktopVELA/scripts/uitest.sh` takes this screenshot
  (`$OUT/shots/<shot>.png`). Run it with the `desktop-uitest` skill and look
  at the image: a black frame means the app never rendered.
- `e2e:<test>`: a test in `desktopVELA/vela-e2e/tests/e2e.rs`, run with
  `cargo test -p vela-e2e --test e2e <test>` from `desktopVELA/`.
- `none`: no automated proof yet. Say so in the PR instead of claiming it
  was verified.

| ID | Feature | Proof |
|----|---------|-------|
| D1 | Create a vault: welcome screen, setup wizard, master password | `uitest:gpui-recovery`, `uitest:tauri-recovery` |
| D2 | Add a trusted contact for recovery: generate Share 3, copy it as a secret, acknowledge the handover | `uitest:gpui-share`, `uitest:tauri-share` |
| D3 | Unlock the vault with the master password | `uitest:gpui-settings-recovery`, `uitest:tauri-settings-recovery` (reached only after unlock) |
| D4 | See recovery method status in Settings, persisted across restart | `uitest:gpui-settings-recovery`, `uitest:tauri-settings-recovery` |
| D5 | Open Devices, Sharing and Audit log | `none` (the journey clicks through them but takes no screenshot) |
| D6 | Enroll an Android device with a one-time code and fingerprint check | `e2e:desktop_enrolls_android_over_v3_and_the_code_is_worth_nothing`, `e2e:a_second_device_cannot_claim_the_same_v3_code`, `e2e:a_wrong_fingerprint_pick_cannot_be_retried` |
| D7 | Sync an item between desktop and Android, both directions | `e2e:desktop_to_android_item_flow_and_back`, `e2e:concurrent_edit_last_write_wins_after_android_merge` |
| D8 | Unlock with biometrics | `none` (not reachable under headless X) |
| D9 | Use a FIDO2 security key | `none` (not reachable under headless X) |
| D10 | Back up the vault to a cloud remote (rclone) | `none` |
| D11 | Autofill in the browser through the extension | `none` (native messaging is not driven by the journey) |

When you add a screenshot to `uitest.sh` or a test to `e2e.rs` that covers a
feature, add it here. When you add a user-facing feature, add a row, with
`none` if nothing proves it yet.
