use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;
use vela_core::rich_items::*;

fn now() -> DateTime<Utc> {
    "2026-10-20T10:00:00Z".parse().unwrap()
}

fn field(kind: CustomFieldType, value: Value) -> CustomField {
    CustomField {
        id: Uuid::new_v4(),
        label: "Field".into(),
        kind,
        value: SensitiveValue(value),
        extra: BTreeMap::new(),
    }
}

#[test]
fn legacy_objects_decode_without_organization_or_richer_fields() {
    assert_eq!(
        serde_json::from_str::<OrganizationData>("{}").unwrap(),
        OrganizationData::default()
    );
    let item: ItemOrganization = serde_json::from_str("{}").unwrap();
    assert_eq!(item, ItemOrganization::default());
    assert_eq!(serde_json::to_value(item).unwrap(), json!({}));
    assert_eq!(
        serde_json::from_str::<LoginDetails>("{}").unwrap(),
        LoginDetails::default()
    );
    assert_eq!(
        serde_json::from_str::<IdentityDetails>("{}").unwrap(),
        IdentityDetails::default()
    );
}

#[test]
fn richer_fixture_round_trips_future_types_and_properties_without_logging_values() {
    let original: Value = serde_json::from_str(include_str!("fixtures/rich_fields.json")).unwrap();
    let item: ItemOrganization = serde_json::from_value(original.clone()).unwrap();
    assert_eq!(serde_json::to_value(&item).unwrap(), original);
    let debug = format!("{item:?}");
    for secret in [
        "fixture-secret-never-log",
        "future-secret-never-log",
        "opaque-secret-never-log",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(
        item.custom_fields[1].validate_for_write().unwrap_err().0,
        "Unsupported custom-field type is read-only"
    );
}

#[test]
fn field_type_and_size_validation_never_interpolates_values() {
    for kind in [CustomFieldType::Text, CustomFieldType::Concealed] {
        assert!(field(kind.clone(), json!("value"))
            .validate_for_write()
            .is_ok());
        assert!(field(kind.clone(), json!(false))
            .validate_for_write()
            .is_err());
        assert!(field(kind, json!("x".repeat(MAX_CUSTOM_VALUE_BYTES + 1)))
            .validate_for_write()
            .is_err());
    }
    assert!(field(CustomFieldType::Boolean, json!(true))
        .validate_for_write()
        .is_ok());
    let bad = field(CustomFieldType::Boolean, json!("do-not-log-this"));
    assert!(!bad
        .validate_for_write()
        .unwrap_err()
        .to_string()
        .contains("do-not-log-this"));
    let mut item = ItemOrganization::default();
    let f = field(CustomFieldType::Text, json!("v"));
    item.custom_fields = vec![f.clone(), f];
    assert!(item.validate_for_write().is_err());
    item.custom_fields.clear();
    item.tag_ids = vec![Uuid::nil()];
    assert!(item.validate_for_write().is_err());
}

#[test]
fn names_are_normalized_and_duplicates_use_unicode_case_folding() {
    let mut data = OrganizationData::default();
    let id = data
        .create_folder("  Cafe\u{301}  ", None, "desktop", now())
        .unwrap();
    assert_eq!(data.folder(id).unwrap().name, "Café");
    assert!(data.create_folder("CAFÉ", None, "desktop", now()).is_err());
    data.create_tag("Straße", "desktop", now()).unwrap();
    assert!(data.create_tag("STRASSE", "desktop", now()).is_err());
    assert!(normalized_name("\n\t").is_err());
    assert!(normalized_name("one\ntwo").is_err());
    assert!(normalized_name(&"é".repeat(MAX_NAME_CHARS)).is_ok());
    assert!(normalized_name(&"é".repeat(MAX_NAME_CHARS + 1)).is_err());
}

#[test]
fn folder_moves_preserve_ids_reject_cycles_and_keep_sibling_names_unique() {
    let mut data = OrganizationData::default();
    let a = data.create_folder("A", None, "desktop", now()).unwrap();
    let b = data.create_folder("B", Some(a), "desktop", now()).unwrap();
    let c = data.create_folder("A", Some(b), "desktop", now()).unwrap();
    let before = data.clone();
    assert!(data.move_folder(a, Some(c), "desktop", now()).is_err());
    assert_eq!(data, before);
    assert!(data.move_folder(c, None, "desktop", now()).is_err());
    data.rename_folder(c, "C", "desktop", now()).unwrap();
    data.move_folder(c, None, "desktop", now()).unwrap();
    assert_eq!(data.folder(c).unwrap().parent_id, None);
    assert_eq!(data.folder(c).unwrap().revision.counter, 3);
}

#[test]
fn nesting_limit_includes_the_whole_moved_subtree() {
    let mut data = OrganizationData::default();
    let mut parent = None;
    for depth in 0..MAX_FOLDER_DEPTH {
        parent = Some(
            data.create_folder(&format!("level {depth}"), parent, "desktop", now())
                .unwrap(),
        );
    }
    assert!(data
        .create_folder("too deep", parent, "desktop", now())
        .is_err());
    let root = data
        .create_folder("other root", None, "desktop", now())
        .unwrap();
    data.create_folder("child", Some(root), "desktop", now())
        .unwrap();
    let target = data.folders[MAX_FOLDER_DEPTH - 2].id;
    let before = data.clone();
    assert!(data
        .move_folder(root, Some(target), "desktop", now())
        .is_err());
    assert_eq!(data, before);
}

#[test]
fn deletion_promotes_children_and_repairs_only_assignments() {
    let mut data = OrganizationData::default();
    let root = data.create_folder("Root", None, "desktop", now()).unwrap();
    let parent = data
        .create_folder("Parent", Some(root), "desktop", now())
        .unwrap();
    let child = data
        .create_folder("Child", Some(parent), "desktop", now())
        .unwrap();
    let tag = data.create_tag("Tag", "desktop", now()).unwrap();
    let custom = field(CustomFieldType::Text, json!("credential-content"));
    let mut item = ItemOrganization {
        folder_id: Some(parent),
        tag_ids: vec![tag],
        custom_fields: vec![custom.clone()],
    };
    data.delete_folder(parent, "desktop", now()).unwrap();
    data.delete_tag(tag).unwrap();
    data.repair_assignment(&mut item);
    assert_eq!(data.folder(child).unwrap().parent_id, Some(root));
    assert!(item.folder_id.is_none());
    assert!(item.tag_ids.is_empty());
    assert_eq!(item.custom_fields, vec![custom]);
    assert_eq!(data.organization_tombstones.len(), 2);
}

#[test]
fn deleted_ids_cannot_be_resurrected_by_later_offline_edits() {
    let mut original = OrganizationData::default();
    let folder = original
        .create_folder("Original", None, "a", now())
        .unwrap();
    let tag = original.create_tag("Tag", "a", now()).unwrap();
    let mut deleted = original.clone();
    deleted.delete_folder(folder, "a", now()).unwrap();
    deleted.delete_tag(tag).unwrap();
    let mut offline = original.clone();
    for _ in 0..10 {
        offline
            .rename_folder(folder, "Offline rename", "b", now())
            .unwrap();
        offline.rename_tag(tag, "Offline tag", "b", now()).unwrap();
    }
    let merged = deleted.merged(&offline).unwrap();
    assert_eq!(merged, offline.merged(&deleted).unwrap());
    assert!(merged.folder(folder).is_none());
    assert!(merged.tag(tag).is_none());
    assert_eq!(merged.organization_tombstones.len(), 2);
    assert_eq!(merged, merged.merged(&original).unwrap());
}

#[test]
fn concurrent_renames_converge_regardless_of_clock_and_merge_order() {
    let mut base = OrganizationData::default();
    let id = base
        .create_folder("Original", None, "origin", now())
        .unwrap();
    let mut a = base.clone();
    let mut b = base.clone();
    a.rename_folder(id, "A", "a", now() + chrono::Duration::days(2))
        .unwrap();
    b.rename_folder(id, "B", "b", now() - chrono::Duration::days(2))
        .unwrap();
    let merged = a.merged(&b).unwrap();
    assert_eq!(merged.folder(id).unwrap().name, "B");
    assert_eq!(merged, b.merged(&a).unwrap());
    assert_eq!(merged, merged.merged(&merged).unwrap());
    assert_eq!(
        a.merged(&b).unwrap().merged(&base).unwrap(),
        a.merged(&b.merged(&base).unwrap()).unwrap()
    );
}

#[test]
fn concurrent_moves_display_an_acyclic_tree_without_mutating_the_records() {
    let mut base = OrganizationData::default();
    let a = base.create_folder("A", None, "origin", now()).unwrap();
    let b = base.create_folder("B", None, "origin", now()).unwrap();
    let mut left = base.clone();
    let mut right = base.clone();
    left.move_folder(a, Some(b), "left", now()).unwrap();
    right.move_folder(b, Some(a), "right", now()).unwrap();
    let merged = left.merged(&right).unwrap();
    let parents = merged.display_parents();
    assert_eq!(parents[&a.max(b)], None);
    assert_eq!(parents[&a.min(b)], Some(a.max(b)));
    assert_eq!(merged.folder(a).unwrap().parent_id, Some(b));
    assert_eq!(merged.folder(b).unwrap().parent_id, Some(a));
    assert_eq!(parents, right.merged(&left).unwrap().display_parents());
}

#[test]
fn revision_overflow_is_an_atomic_failure() {
    let mut data = OrganizationData::default();
    let parent = data
        .create_folder("Parent", None, "desktop", now())
        .unwrap();
    let child = data
        .create_folder("Child", Some(parent), "desktop", now())
        .unwrap();
    data.folders
        .iter_mut()
        .find(|f| f.id == child)
        .unwrap()
        .revision
        .counter = u64::MAX;
    let before = data.clone();
    assert!(data.delete_folder(parent, "desktop", now()).is_err());
    assert_eq!(data, before);
    assert!(data
        .rename_folder(child, "Rename", "desktop", now())
        .is_err());
    assert_eq!(data, before);
}

#[test]
fn equal_revision_with_different_payload_is_rejected_without_mutation() {
    let mut a = OrganizationData::default();
    a.create_tag("A", "desktop", now()).unwrap();
    let mut b = a.clone();
    b.tags[0].name = "Corrupt same revision".into();
    let before = a.clone();
    assert!(a.merged(&b).is_err());
    assert!(b.merged(&a).is_err());
    assert_eq!(a, before);
}

#[test]
fn alternate_urls_validate_storage_without_becoming_an_autofill_api() {
    for candidate in [
        "http://example.com",
        "https://user:secret@example.com",
        "javascript:alert(1)",
        "https://",
        " https://example.com",
    ] {
        let url = AdditionalUrl {
            id: Uuid::new_v4(),
            url: candidate.into(),
            match_mode: UrlMatch::Origin,
            extra: BTreeMap::new(),
        };
        assert!(url.validate_for_write().is_err());
    }
    let details: LoginDetails = serde_json::from_value(json!({"additionalUrls":[{
        "id": Uuid::new_v4(), "url":"https://example.com/path?token=do-not-log", "match":"exact"
    }]}))
    .unwrap();
    assert!(details.validate_for_write().is_ok());
    assert!(!format!("{details:?}").contains("do-not-log"));
    assert_eq!(
        serde_json::to_value(&details).unwrap()["additionalUrls"][0]["match"],
        "exact"
    );
}

#[test]
fn identity_details_preserve_future_data_and_do_not_require_a_specific_country() {
    let input = json!({"middleName":null,"preferredName":"Private name", "email": "private@example.com",
        "phone":null,"company":null,"jobTitle":null,
        "addresses":[{"id":Uuid::new_v4(), "line1":"Private street", "futureRegion":"Private region"}],
        "futureAttribute":{"value":"Private value"}});
    let details: IdentityDetails = serde_json::from_value(input.clone()).unwrap();
    assert!(details.validate_for_write().is_ok());
    let encoded = serde_json::to_value(&details).unwrap();
    assert_eq!(encoded["futureAttribute"], input["futureAttribute"]);
    assert_eq!(encoded["addresses"][0]["futureRegion"], "Private region");
    assert!(!format!("{details:?}").contains("Private"));
    assert!(!format!("{:?}", details.addresses).contains("Private"));
}

#[test]
fn organization_wire_fixture_is_canonical_and_retains_unknown_record_properties() {
    let mut input: Value =
        serde_json::from_str(include_str!("fixtures/organization.json")).unwrap();
    input["folders"][0]["futureProperty"] = json!({"private": "not-for-debug"});
    let organization: OrganizationData = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(serde_json::to_value(&organization).unwrap(), input);
    assert!(!format!("{organization:?}").contains("not-for-debug"));
    let item: ItemOrganization =
        serde_json::from_str(include_str!("fixtures/rich_fields.json")).unwrap();
    assert!(organization.folder(item.folder_id.unwrap()).is_some());
    assert!(organization.tag(item.tag_ids[0]).is_some());
}

#[test]
fn future_url_match_modes_survive_decoding_but_cannot_be_written_as_known_rules() {
    let input = json!({"id": Uuid::new_v4(), "url":"https://example.com", "match":"future-mode", "futureOption":true});
    let entry: AdditionalUrl = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(serde_json::to_value(&entry).unwrap(), input);
    assert!(entry.validate_for_write().is_err());
}

#[test]
fn conflicting_obsolete_records_are_rejected_independent_of_record_order() {
    let mut base = OrganizationData::default();
    let id = base.create_tag("Original", "a", now()).unwrap();
    let mut corrupt = base.clone();
    corrupt.tags[0].name = "Divergent same revision".into();
    let mut newer = base.clone();
    newer.rename_tag(id, "Newer", "b", now()).unwrap();
    let mut candidates = base.clone();
    candidates.tags.extend(corrupt.tags.clone());
    candidates.tags.extend(newer.tags.clone());
    assert!(candidates.merged(&OrganizationData::default()).is_err());
    candidates.tags.reverse();
    assert!(candidates.merged(&OrganizationData::default()).is_err());
}

#[test]
fn delete_folder_handles_merged_cycles_without_promoting_children_into_themselves() {
    let mut data = OrganizationData::default();
    let a = data.create_folder("A", None, "a", now()).unwrap();
    let b = data.create_folder("B", Some(a), "a", now()).unwrap();
    data.folders
        .iter_mut()
        .find(|f| f.id == a)
        .unwrap()
        .parent_id = Some(b);
    let deleted = a.max(b);
    let remaining = a.min(b);
    data.delete_folder(deleted, "a", now()).unwrap();
    assert_eq!(data.folder(remaining).unwrap().parent_id, None);
}

#[test]
fn invalid_revision_and_tombstone_ids_fail_closed_during_merge() {
    let mut data = OrganizationData::default();
    data.create_tag("Tag", "desktop", now()).unwrap();
    data.tags[0].revision.counter = 0;
    assert!(data.merged(&OrganizationData::default()).is_err());
    data.tags[0].revision.counter = 1;
    data.tags[0].revision.device_id.clear();
    assert!(data.merged(&OrganizationData::default()).is_err());
    data.tags[0].revision.device_id = "desktop".into();
    data.organization_tombstones.push(OrganizationTombstone {
        kind: OrganizationKind::Tag,
        id: Uuid::nil(),
    });
    assert!(data.merged(&OrganizationData::default()).is_err());
}
