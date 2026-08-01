//! Headless end-to-end sync tests: desktop client + mock server + android
//! client, all in-process, no device or emulator.

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
