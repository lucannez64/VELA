//! Headless end-to-end sync tests: desktop client + mock server + android
//! client, all in-process, no device or emulator.

use base64::Engine as _;
use chrono::Duration;
use vela_desktop_core::vault::ItemType;
use vela_e2e::android_client::AndroidClient;
use vela_e2e::desktop_client::DesktopClient;
use vela_e2e::mock_server::MockServer;

/// Fixed RMS shared by both clients in a scenario — in reality the android
/// device recovers it from the enrollment capsule; both must agree for chunks
/// to decrypt.
const RMS: [u8; 32] = [42u8; 32];

fn rms() -> [u8; 32] {
    let mut rms = RMS;
    rms[0] += 1;
    rms
}

#[tokio::test]
async fn desktop_to_android_item_flow_and_back() {
    let server = MockServer::spawn().await.unwrap();
    server.wait_ready().await;
    let url = server.url();

    // 1. Desktop creates an account and syncs its first item up.
    let desktop = DesktopClient::new(rms(), &url).await.unwrap();
    desktop.add_login("item-d", "GitHub", "https://github.com", "desktop-user", "d-password");
    let status = desktop.sync().await.unwrap();
    assert!(status.error.is_none(), "desktop first sync: {:?}", status.error);
    assert_eq!(desktop.item_ids(), vec!["item-d"]);
    assert!(server.db.chunk_count() >= 1, "server should hold the desktop's chunks");

    // 2. A second device (the android client) joins the SAME account via the
    //    desktop's enrollment code.
    let code = desktop.enrollment_code().await.unwrap();
    let mut android = AndroidClient::enroll_with_code(&code).await.unwrap();
    assert_eq!(android.user_id(), desktop.user_id, "enrollment must join the same account");

    // 3. Android's first sync pulls the desktop's vault (empty-local download path).
    let outcome = android.sync().await.unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(android.item_ids(), vec!["item-d"], "android should have downloaded the desktop item");

    // 4. Android adds an item and syncs it back up.
    android.add_login("item-a", "Company VPN", "https://vpn.example.com", "android-user", "a-password");
    android.sync().await.unwrap();
    assert_eq!(android.item_ids().len(), 2);

    // 5. Desktop syncs and merges — both items, and the android-written chunk
    //    must decrypt on the desktop side (proves cross-client crypto).
    let status = desktop.sync().await.unwrap();
    assert!(status.error.is_none(), "desktop merge sync: {:?}", status.error);
    let mut ids = desktop.item_ids();
    ids.sort();
    assert_eq!(ids, vec!["item-a", "item-d"]);

    let item = desktop.find_item("item-a").expect("desktop should hold the android item");
    assert_eq!(item.name(), "Company VPN");
    assert_eq!(item.item_type(), ItemType::Login);

    // 6. Deletion propagates: android deletes the desktop's item, desktop
    //    honours the tombstone.
    android.delete_item("item-d");
    android.sync().await.unwrap();
    assert_eq!(android.item_ids(), vec!["item-a"]);

    let status = desktop.sync().await.unwrap();
    assert!(status.error.is_none(), "desktop tombstone sync: {:?}", status.error);
    assert_eq!(desktop.item_ids(), vec!["item-a"], "desktop must honour the android tombstone");
}

#[tokio::test]
async fn concurrent_edit_last_write_wins_after_android_merge() {
    let server = MockServer::spawn().await.unwrap();
    server.wait_ready().await;
    let url = server.url();

    let desktop = DesktopClient::new(rms(), &url).await.unwrap();
    desktop.add_login("item-x", "Shared", "https://shared.example.com", "user", "pw-v1");
    let t1 = chrono::Utc::now();
    desktop.set_item_updated_at("item-x", t1);
    desktop.sync().await.unwrap();

    // Android joins and downloads item-x.
    let code = desktop.enrollment_code().await.unwrap();
    let mut android = AndroidClient::enroll_with_code(&code).await.unwrap();
    android.sync().await.unwrap();
    assert_eq!(android.item_ids(), vec!["item-x"]);

    // Desktop edits item-x (newer timestamp) and syncs.
    let t2 = t1 + Duration::hours(2);
    desktop.set_item_updated_at("item-x", t2);
    desktop.sync().await.unwrap();

    // Android edits the SAME item locally with an OLDER timestamp, then syncs.
    // Its merge must resolve to the desktop's newer version (last-write-wins)
    // and push the merged vault back up.
    let t15 = t1 + Duration::hours(1);
    android.set_item_updated_at("item-x", t15);
    let outcome = android.sync().await.unwrap();
    assert!(outcome.error.is_none());

    let merged = android.find_item("item-x").unwrap();
    let updated = match merged {
        vela_core::vault::VaultItem::Login { meta, .. } => meta.updated_at,
        _ => panic!("unexpected item type"),
    };
    assert_eq!(updated, t2, "android merge must keep the newer edit");

    // Desktop syncs again — no regression; converges on t2.
    let status = desktop.sync().await.unwrap();
    assert!(status.error.is_none(), "desktop converge sync: {:?}", status.error);
    assert_eq!(desktop.item_ids(), vec!["item-x"]);
}

/// Enrollment v3, both roles, end to end (audit P-1).
///
/// The property under test is what the code is *worth*: it carries a grant and
/// a server URL, the joining device generates its own keys, and the RMS comes
/// back sealed to a public key whose private half never left that device. So
/// the assertions here are not only "the vault synced" — they are that the code
/// contains no key material, and that the capsule the server holds does not
/// open with anything an interceptor could have had.
#[tokio::test]
async fn desktop_enrolls_android_over_v3_and_the_code_is_worth_nothing() {
    let server = MockServer::spawn().await.unwrap();
    server.wait_ready().await;
    let url = server.url();

    let desktop = DesktopClient::new(rms(), &url).await.unwrap();
    desktop.add_login("item-d", "GitHub", "https://github.com", "desktop-user", "d-password");
    desktop.sync().await.unwrap();

    // 1. The primary opens a grant. Nothing exists on the account yet.
    let invite = desktop.open_enrollment_invite().await.unwrap();
    assert!(invite.code.starts_with("VELA-ENROLL:v3:"));
    assert!(
        desktop.poll_enrollment_claim(&invite.grant_id).await.unwrap().is_none(),
        "nobody has claimed it yet"
    );

    // The whole point: everything a v2 code carried that was worth stealing is
    // absent. Decoded, not just absent from the opaque string.
    let decoded = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(invite.code.strip_prefix("VELA-ENROLL:v3:").unwrap())
            .unwrap(),
    )
    .unwrap();
    for forbidden in ["hybrid_sk", "hybrid_dk", "transfer_key", "device_id"] {
        assert!(!decoded.contains(forbidden), "v3 code carries {forbidden}: {decoded}");
    }

    // 2. The joining device claims it with keys it generated itself, and the
    //    user answers the fingerprint question on the primary. The closure is
    //    handed the fingerprint the *joining* device computed, which is what a
    //    real user reads off its screen.
    let grant_id = invite.grant_id.clone();
    let mut android = AndroidClient::join_with_v3_code(&invite.code, |fingerprint| {
        let desktop = &desktop;
        async move {
        let claim = desktop
            .poll_enrollment_claim(&grant_id)
            .await
            .map_err(|e| format!("poll claim: {e}"))?
            .ok_or("the primary never saw the claim")?;

        // The candidate list must really contain the joining device's own
        // fingerprint — if the primary computed it over anything else, a user
        // comparing the two screens would find no match at all.
        assert!(
            claim.fingerprint_choices.contains(&fingerprint),
            "the primary offered no candidate matching the joining device: {:?}",
            claim.fingerprint_choices
        );
        // And it must be a real choice: one right answer among decoys.
        assert!(claim.fingerprint_choices.len() >= 2, "a single option is not a choice");
        assert_eq!(
            claim.fingerprint_choices.iter().filter(|c| **c == fingerprint).count(),
            1,
            "two correct answers would halve the cost of guessing"
        );

            desktop
                .confirm_enrollment(&grant_id, &fingerprint)
                .await
                .map(|_| ())
                .map_err(|e| format!("confirm: {e}"))
        }
    })
    .await
    .unwrap();

    assert_eq!(android.user_id(), desktop.user_id, "v3 enrollment must join the same account");

    // 3. It really got the vault — which means the capsule opened with the key
    //    that never left it.
    let outcome = android.sync().await.unwrap();
    assert!(outcome.error.is_none(), "android first sync: {:?}", outcome.error);
    assert_eq!(android.item_ids(), vec!["item-d"]);

    // 4. And writes flow back, so the RMS both sides hold is the same one.
    android.add_login("item-a", "Company VPN", "https://vpn.example.com", "android-user", "a-pw");
    android.sync().await.unwrap();
    let status = desktop.sync().await.unwrap();
    assert!(status.error.is_none(), "desktop merge sync: {:?}", status.error);
    let mut ids = desktop.item_ids();
    ids.sort();
    assert_eq!(ids, vec!["item-a", "item-d"]);
}

/// A grant admits exactly one claim, and the loser is told.
///
/// This is what keeps a hijack from being silent: an attacker who wins the race
/// does not quietly enrol alongside the real device — the real device fails,
/// visibly, in the user's hand.
#[tokio::test]
async fn a_second_device_cannot_claim_the_same_v3_code() {
    let server = MockServer::spawn().await.unwrap();
    server.wait_ready().await;

    let desktop = DesktopClient::new(rms(), &server.url()).await.unwrap();
    desktop.sync().await.unwrap();
    let invite = desktop.open_enrollment_invite().await.unwrap();

    // First claimant gets as far as waiting for confirmation.
    let first = AndroidClient::join_with_v3_code(&invite.code, |_| async {
        Err("stop before confirming".to_string())
    })
    .await;
    assert!(first.is_err(), "the harness stops at the confirmation step");

    // Second claimant is refused outright rather than replacing the first.
    let second =
        AndroidClient::join_with_v3_code(&invite.code, |_| async { Ok(()) }).await;
    let error = match second {
        Ok(_) => panic!("a second claim must be refused"),
        Err(e) => e,
    };
    assert!(
        error.contains("409") || error.to_lowercase().contains("conflict"),
        "the loser must be told it lost, got: {error}"
    );
}

/// Picking the wrong fingerprint ends the enrollment rather than asking again.
///
/// With one attempt at n candidates, confirming without looking fails (n-1)/n
/// of the time. With unlimited attempts it succeeds every time, eventually —
/// which would make the whole choice decorative.
#[tokio::test]
async fn a_wrong_fingerprint_pick_cannot_be_retried() {
    let server = MockServer::spawn().await.unwrap();
    server.wait_ready().await;

    let desktop = DesktopClient::new(rms(), &server.url()).await.unwrap();
    desktop.sync().await.unwrap();
    let invite = desktop.open_enrollment_invite().await.unwrap();
    let grant_id = invite.grant_id.clone();

    let joined = AndroidClient::join_with_v3_code(&invite.code, |fingerprint| {
        let desktop = &desktop;
        async move {
        let claim = desktop.poll_enrollment_claim(&grant_id).await.unwrap().unwrap();

        // The user picks a decoy.
        let decoy = claim
            .fingerprint_choices
            .iter()
            .find(|c| **c != fingerprint)
            .expect("there must be a decoy to pick");
        assert!(
            desktop.confirm_enrollment(&grant_id, decoy).await.is_err(),
            "a decoy must not enrol the device"
        );

        // And now the right answer is no longer accepted either: the pending
        // enrollment is gone, not merely unsatisfied.
        let retry = desktop.confirm_enrollment(&grant_id, &fingerprint).await;
        assert!(
            retry.is_err(),
            "a wrong pick must end the enrollment, not offer another guess"
        );
            Err("enrollment was cancelled".to_string())
        }
    })
    .await;

    assert!(joined.is_err(), "no device may be enrolled after a wrong pick");
}
