//! Test migration
//!
//! Sets up a group using a *previous* version's API (0.7.4 or 0.8.1, selected by
//! the `storage_migration_0_7` / `storage_migration_0_8` feature), each member
//! backed by their own postcard-serialized storage. A member then migrates their
//! persisted state to the current version by exporting it with the previous
//! version's API into a `GroupMigrationBundle`, bridging that through `serde_json`,
//! and importing it with `GroupMigrationBundle::store` in the current format.
//!
//! Two things are verified:
//!
//! 1. *State* preservation — every field round-trips through the version bridge,
//!    and everything the migration writes survives a current-version storage
//!    round-trip (see [`migrate_and_check`]).
//! 2. *Operability* — a migrated group is driven through real operations with the
//!    current API (self-update, and processing an incoming commit from another
//!    migrated member) to prove it is cryptographically usable, not just
//!    structurally intact. This is possible because the current-version
//!    crypto/credential providers are pulled in under the `*_current` package
//!    aliases (see `compat_tests/Cargo.toml`), so both versions' stacks coexist
//!    in this one crate.
//!
//! The operability tests also exercise the migration of *application-managed*
//! material — data that is not group-scoped, so the library cannot enumerate it
//! per group and the application migrates it itself: signature key pairs, PSKs (TODO),
//! and published key packages. The group-owned application export tree (under
//! `extensions-draft`) is carried automatically by the migration, inside the
//! group state; a test confirms it stays functional afterwards.

#![cfg(any(feature = "storage_migration_0_8", feature = "storage_migration_0_7"))]

use openmls_compat_tests::test_storage_provider::{
    PostcardOpenMlsProvider, PostcardProvider, SerdeJsonProvider, StorageProviderState,
};

// The previous-version OpenMLS crate under test (and its matching credential,
// crypto, and traits crates), aliased so the test body is agnostic to the
// specific version being migrated from. Exactly one source version is active per
// build. Adding another source version is purely additive: introduce a new
// `cfg`-gated alias arm (and the corresponding dependency/feature wiring)
// alongside these.
#[cfg(feature = "compat_0_8_1")]
use openmls_0_8_1 as openmls_compat;
#[cfg(feature = "compat_0_8_1")]
use openmls_basic_credential_0_8 as openmls_basic_credential_compat;
#[cfg(feature = "compat_0_8_1")]
use openmls_libcrux_crypto_0_8 as openmls_libcrux_crypto_compat;
#[cfg(feature = "compat_0_8_1")]
use openmls_traits_0_5_0 as openmls_traits_compat;

#[cfg(feature = "compat_0_7_4")]
use openmls_0_7_4 as openmls_compat;
#[cfg(feature = "compat_0_7_4")]
use openmls_basic_credential_0_7 as openmls_basic_credential_compat;
#[cfg(feature = "compat_0_7_4")]
use openmls_libcrux_crypto_0_7 as openmls_libcrux_crypto_compat;
#[cfg(feature = "compat_0_7_4")]
use openmls_traits_0_4_1 as openmls_traits_compat;

use openmls_compat::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_traits_compat::signatures::Signer;

use openmls as openmls_current;

/// Create a basic credential together with a freshly generated signature key
/// pair, persisting the key pair in the provider's storage.
fn generate_credential(
    identity: &[u8],
    ciphersuite: Ciphersuite,
    provider: &PostcardOpenMlsProvider,
) -> (
    openmls_compat::prelude::CredentialWithKey,
    openmls_basic_credential_compat::SignatureKeyPair,
) {
    let credential = BasicCredential::new(identity.to_vec());
    let signature_keys =
        openmls_basic_credential_compat::SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .unwrap();
    signature_keys.store(provider.storage()).unwrap();

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

/// Build a key package bundle for the given credential.
fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    provider: &PostcardOpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}

/// Recursively compare two JSON values, recording the paths (and a truncated
/// summary of the values) where they differ. Keeps failure output readable
/// instead of dumping the entire group state.
fn diff_json(
    path: &str,
    a: &serde_json::Value,
    b: &serde_json::Value,
    out: &mut Vec<(String, String)>,
) {
    use serde_json::Value;

    fn summarize(v: &Value) -> String {
        let s = v.to_string();
        if s.len() > 80 {
            format!("{}… ({} chars)", &s[..80], s.len())
        } else {
            s
        }
    }

    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = format!("{path}.{key}");
                match (a.get(key), b.get(key)) {
                    (Some(av), Some(bv)) => diff_json(&child, av, bv, out),
                    (Some(av), None) => {
                        out.push((child, format!("only in `before` = {}", summarize(av))))
                    }
                    (None, Some(bv)) => {
                        out.push((child, format!("only in `after` = {}", summarize(bv))))
                    }
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), av, bv, out);
            }
        }
        _ => {
            if a != b {
                out.push((
                    path.to_string(),
                    format!("before = {}, after = {}", summarize(a), summarize(b)),
                ));
            }
        }
    }
}

/// Create an operational two-member (Alice + Bob) group: Alice creates it and
/// adds Bob, who joins from the welcome. Each member's state is persisted to its
/// own provider. Returns Alice's group handle and both members' signers.
fn setup_alice_bob_group(
    ciphersuite: Ciphersuite,
    group_id: &GroupId,
    alice_provider: &PostcardOpenMlsProvider,
    bob_provider: &PostcardOpenMlsProvider,
) -> (
    MlsGroup,
    openmls_basic_credential_compat::SignatureKeyPair,
    openmls_basic_credential_compat::SignatureKeyPair,
) {
    let (alice_credential, alice_signer) =
        generate_credential(b"Alice", ciphersuite, alice_provider);
    let (bob_credential, bob_signer) = generate_credential(b"Bob", ciphersuite, bob_provider);
    let bob_key_package =
        generate_key_package(ciphersuite, bob_credential, bob_provider, &bob_signer);

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &config,
        group_id.clone(),
        alice_credential,
    )
    .expect("error creating group");

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("error adding Bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging commit");

    // Bob joins from the welcome so he holds his own state.
    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("error serializing welcome");
    let welcome =
        openmls_compat::prelude::MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
            .expect("error deserializing welcome");
    let openmls_compat::prelude::MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("expected the message to be a welcome")
    };
    StagedWelcome::new_from_welcome(
        bob_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating staged welcome for Bob")
    .into_group(bob_provider)
    .expect("error joining group as Bob");

    (alice_group, alice_signer, bob_signer)
}

/// Migrate Alice's previous-version group (persisted in `alice_state`) to the
/// current version through `serde_json` and assert the migration preserved the
/// whole group. Returns the migrated bundle as a `serde_json` value for any
/// additional caller assertions.
fn migrate_and_check(
    alice_state: &StorageProviderState,
    group_id_bytes: &[u8],
) -> serde_json::Value {
    // 1. Export Alice's group from postcard storage using the previous version's API.
    let alice_storage = alice_state.as_postcard_provider();
    let group_id = GroupId::from_slice(group_id_bytes);
    let alice_group_old = MlsGroup::export_for_migration(&alice_storage, &group_id)
        .expect("error exporting old group")
        .expect("no group state persisted for Alice");

    // 2. Serialize the exported bundle to a self-describing `serde_json` value.
    let before = serde_json::to_value(&alice_group_old).expect("error serializing old group");

    // 3. Deserialize into the current version's `GroupMigrationBundle` (enabled by
    //    the `migration-import` feature on `openmls`).
    let migrated_group: openmls_current::storage::GroupMigrationBundle =
        serde_json::from_value(before.clone())
            .expect("error deserializing into the current GroupMigrationBundle");

    // 4. Persist the migrated group in the current storage format.
    let migrated_state = StorageProviderState::default();
    let migrated_storage = migrated_state.as_serde_json_provider();
    migrated_group
        .store(&migrated_storage)
        .expect("error storing migrated group");

    // === Verify the migration ===

    // Serializing the migrated (current) bundle and comparing it field-by-field
    // against the original previous-version bundle value proves the whole group
    // crossed the version bridge. Object key order is irrelevant to the comparison,
    // so any dropped, renamed, or defaulted field shows up as a diff.
    //
    // The only expected differences are intentional schema changes between the
    // two versions, none of which lose information. These fields can appear at
    // several paths (e.g. `MessageSecrets` also lives inside a staged commit), so
    // they are matched wherever they occur:
    //   - `max_past_epochs` was renamed to `past_epoch_deletion_policy`; the
    //     current type reads the old name via `#[serde(alias)]` and both encode
    //     the same value, so only the key name changes.
    //   - `added_at` is a new field on `MessageSecrets` with no previous-version
    //     counterpart; it defaults to `null` after migration.
    //   - `safe_aad` (only when the migration target has `extensions-draft`) is new
    //     in the current version and absent from every source version's serialization
    //     (including a source built with its own `extensions-draft`); it defaults to
    //     an empty value after migration, so it only appears on the `after` side.
    //   - `application_export_tree` (only when migrating *into* `extensions-draft`
    //     from a source *without* it — the feature-flag-toggle case) has no source
    //     counterpart and defaults to `null` after migration. When both sides have
    //     the feature it round-trips normally and does not diff.
    //   - `SenderRatchet` (only under `virtual-clients-draft`) changes variant: the
    //     previous version encodes an `EncryptionRatchet`, which the current version
    //     decodes losslessly into a `DualUse` ratchet (see "decode SenderRatchet
    //     without breaking"). So the old side shows the `EncryptionRatchet` key and
    //     the new side the `DualUse` key, for the same ratchet.
    //   - `new_own_leaf_index` and `vc_emulation_epoch_id` (only under
    //     `virtual-clients-draft`) are new fields on the pending/staged commit state
    //     with no previous-version counterpart; they default to `null` after
    //     migration, so they only appear on the `after` side.
    fn is_expected_schema_diff(path: &str) -> bool {
        path.ends_with(".max_past_epochs")
            || path.ends_with(".past_epoch_deletion_policy")
            || path.ends_with(".added_at")
            || (cfg!(feature = "extensions-draft-current")
                && (path.ends_with(".safe_aad") || path.ends_with(".application_export_tree")))
            || (cfg!(feature = "virtual-clients-draft")
                && (path.ends_with(".EncryptionRatchet")
                    || path.ends_with(".DualUse")
                    || path.ends_with(".new_own_leaf_index")
                    || path.ends_with(".vc_emulation_epoch_id")))
    }

    let after = serde_json::to_value(&migrated_group).expect("error serializing migrated group");
    let mut diffs = Vec::new();
    diff_json("$", &before, &after, &mut diffs);
    let unexpected: Vec<_> = diffs
        .iter()
        .filter(|(path, _)| !is_expected_schema_diff(path))
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected differences after migration:\n{}",
        unexpected
            .iter()
            .map(|(path, detail)| format!("  {path}: {detail}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The migrated state can also be loaded with the current API from the current
    // storage format. This is a pure current-version round-trip (no schema change),
    // so it must reproduce the migrated group exactly. In particular, everything
    // the bundle persisted (including any queued proposals and a pending commit)
    // must survive the storage round-trip.
    //
    // `MlsGroup::load` returns just the group, so it is compared against the
    // bundle's `group` field (the bundle also carries the group's encryption key
    // pairs, which are side tables, not part of the loaded `MlsGroup`).
    let new_group_id = openmls_current::prelude::GroupId::from_slice(group_id_bytes);
    let reloaded = openmls_current::prelude::MlsGroup::load(&migrated_storage, &new_group_id)
        .expect("error loading migrated group")
        .expect("no migrated group state persisted");

    let reloaded_value = serde_json::to_value(&reloaded).expect("error serializing reloaded group");
    assert_eq!(
        after["group"], reloaded_value,
        "storage round-trip changed the group"
    );

    after
}

// ANCHOR: migration
/// Migrate a single group from the previous OpenMLS version to the current one.
///
/// `old_provider` implements the *previous* version's storage traits and already
/// holds the group; `new_provider` implements the *current* version's storage
/// traits and receives the migrated group. Both refer to the same `group_id`.
///
/// This requires the `migration-export` feature on the previous version's
/// `openmls` crate and the `migration-import` feature on the current one.
fn migrate_group(
    old_provider: &PostcardProvider<'_>,
    new_provider: &SerdeJsonProvider<'_>,
    group_id: &openmls_compat::prelude::GroupId,
) {
    // 1. Export the group and all the group-associated data it owns, using the
    //    *previous* version's API.
    let bundle = openmls_compat::prelude::MlsGroup::export_for_migration(old_provider, group_id)
        .expect("error reading the old storage")
        .expect("no group with this id in the old storage");

    // 2. Serialize the bundle to a self-describing format. Any `serde` format
    //    works; this example uses JSON.
    let serialized = serde_json::to_vec(&bundle).expect("error serializing the migration bundle");

    // 3. Deserialize into the *current* version's migration bundle.
    let bundle: openmls_current::storage::GroupMigrationBundle =
        serde_json::from_slice(&serialized).expect("error deserializing the migration bundle");

    // 4. Write the group and all its data to storage in the current version's
    //    format.
    bundle
        .store(new_provider)
        .expect("error storing the migrated group");
}
// ANCHOR_END: migration

#[test]
fn test_migration() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration test group");

    // Each member gets their own postcard-backed storage, wrapped in a full
    // previous-version provider (postcard storage + libcrux crypto/rand).
    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    let charlie_state = StorageProviderState::default();

    let alice_storage = alice_state.as_postcard_provider();
    let bob_storage = bob_state.as_postcard_provider();
    let charlie_storage = charlie_state.as_postcard_provider();

    let alice_provider = alice_storage.as_openmls_provider();
    let bob_provider = bob_storage.as_openmls_provider();
    let charlie_provider = charlie_storage.as_openmls_provider();

    // === Generate credentials ===
    let (alice_credential, alice_signer) =
        generate_credential(b"Alice", ciphersuite, &alice_provider);
    let (bob_credential, bob_signer) = generate_credential(b"Bob", ciphersuite, &bob_provider);
    let (charlie_credential, charlie_signer) =
        generate_credential(b"Charlie", ciphersuite, &charlie_provider);

    // Bob and Charlie publish key packages.
    let bob_key_package =
        generate_key_package(ciphersuite, bob_credential, &bob_provider, &bob_signer);
    let charlie_key_package = generate_key_package(
        ciphersuite,
        charlie_credential,
        &charlie_provider,
        &charlie_signer,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates the group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential,
    )
    .expect("error creating group");

    // === Alice adds Bob and Charlie ===
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[
                bob_key_package.key_package().clone(),
                charlie_key_package.key_package().clone(),
            ],
        )
        .expect("error adding members");

    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("error merging commit");

    // Bob and Charlie join from the welcome so that they hold their own state.
    // Round-trip the welcome through its wire encoding, as a delivery service
    // would, to obtain an incoming message (the in-memory `MlsMessageOut` ->
    // `MlsMessageIn` conversion is gated behind `test-utils`).
    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("error serializing welcome");
    let welcome =
        openmls_compat::prelude::MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
            .expect("error deserializing welcome");
    let openmls_compat::prelude::MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("expected the message to be a welcome")
    };
    let ratchet_tree = alice_group.export_ratchet_tree();

    let _bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        mls_group_create_config.join_config(),
        welcome.clone(),
        Some(ratchet_tree.clone().into()),
    )
    .expect("error creating staged welcome for Bob")
    .into_group(&bob_provider)
    .expect("error joining group as Bob");

    let _charlie_group = StagedWelcome::new_from_welcome(
        &charlie_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(ratchet_tree.into()),
    )
    .expect("error creating staged welcome for Charlie")
    .into_group(&charlie_provider)
    .expect("error joining group as Charlie");

    // Sanity check: Alice's group has all three members.
    assert_eq!(alice_group.members().count(), 3);

    // === Migrate each member's state to the current version ===
    // Alice created the group (own leaf index 0); Bob and Charlie joined via
    // welcome (own leaf index != 0). All of them must migrate correctly.
    migrate_and_check(&alice_state, b"migration test group");
    migrate_and_check(&bob_state, b"migration test group");
    migrate_and_check(&charlie_state, b"migration test group");
}

/// Migration must preserve the retained message secrets of past epochs.
#[test]
fn test_migration_multiple_epochs() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration multi-epoch group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", ciphersuite, &alice_provider);
        let (bob_credential, bob_signer) = generate_credential(b"Bob", ciphersuite, &bob_provider);
        let bob_key_package =
            generate_key_package(ciphersuite, bob_credential, &bob_provider, &bob_signer);

        // Keep several past epochs, so their message secrets are retained in the
        // message secrets store and must be migrated too.
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .max_past_epochs(3)
            .build();

        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.clone(),
            alice_credential,
        )
        .expect("error creating group");
        alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_key_package.key_package().clone()],
            )
            .expect("error adding Bob");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("error merging commit");

        // Advance several epochs so past-epoch secrets accumulate.
        for _ in 0..4 {
            alice_group
                .self_update(
                    &alice_provider,
                    &alice_signer,
                    LeafNodeParameters::default(),
                )
                .expect("error self-updating");
            alice_group
                .merge_pending_commit(&alice_provider)
                .expect("error merging self-update");
        }

        assert_eq!(alice_group.epoch().as_u64(), 5);
    }

    migrate_and_check(&alice_state, b"migration multi-epoch group");
}

/// Migration must preserve proposals that are queued in the proposal store but
/// not yet committed.
#[test]
fn test_migration_with_proposals() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration proposals group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    let charlie_state = StorageProviderState::default();
    let dave_state = StorageProviderState::default();

    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let charlie_storage = charlie_state.as_postcard_provider();
        let dave_storage = dave_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let charlie_provider = charlie_storage.as_openmls_provider();
        let dave_provider = dave_storage.as_openmls_provider();

        let (mut alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);

        // Queue two Add proposals (Charlie and Dave) in Alice's proposal store,
        // without committing them.
        for (identity, provider) in [
            (&b"Charlie"[..], &charlie_provider),
            (&b"Dave"[..], &dave_provider),
        ] {
            let (credential, signer) = generate_credential(identity, ciphersuite, provider);
            let key_package = generate_key_package(ciphersuite, credential, provider, &signer);
            alice_group
                .propose_add_member(&alice_provider, &alice_signer, key_package.key_package())
                .expect("error proposing add");
        }

        // The scenario under test: proposals queued, no pending commit.
        assert_eq!(alice_group.pending_proposals().count(), 2);
        assert!(alice_group.pending_commit().is_none());
    }

    migrate_and_check(&alice_state, b"migration proposals group");
}

/// Migration must preserve the *order* of entries in the accumulate-style tables
/// (own leaf nodes and the proposal queue), not just their contents. Two update
/// proposals populate both tables with two entries each; `migrate_and_check`
/// compares them index-by-index, across the serde bridge and (since `store`
/// clears then re-appends these tables) the store round-trip.
#[test]
fn test_migration_preserves_accumulative_order() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration order group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (mut alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);

        // Two self-update proposals: each queues a proposal *and* appends an own
        // leaf node, so both accumulate tables end up with two ordered entries.
        for _ in 0..2 {
            alice_group
                .propose_self_update(
                    &alice_provider,
                    &alice_signer,
                    LeafNodeParameters::default(),
                )
                .expect("error proposing self-update");
        }
        assert_eq!(alice_group.pending_proposals().count(), 2);
    }

    let after = migrate_and_check(&alice_state, b"migration order group");
    // Confirm the scenario actually exercised multi-entry accumulate tables (so
    // the order-sensitive comparison in `migrate_and_check` is meaningful).
    assert_eq!(
        after["group"]["own_leaf_nodes"]
            .as_array()
            .map(|nodes| nodes.len()),
        Some(2),
        "expected two own leaf nodes to exercise ordering",
    );
}

/// Migration must preserve a pending (staged, not yet merged) commit.
#[test]
fn test_migration_with_pending_commit() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration pending commit group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (mut alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);

        // Create a pending commit (a self-update) without merging it.
        alice_group
            .self_update(
                &alice_provider,
                &alice_signer,
                LeafNodeParameters::default(),
            )
            .expect("error creating self-update commit");

        // The scenario under test: a pending commit, no queued proposals.
        assert!(alice_group.pending_commit().is_some());
        assert_eq!(alice_group.pending_proposals().count(), 0);
    }

    migrate_and_check(&alice_state, b"migration pending commit group");
}

/// Migration must preserve a large group: a deep ratchet tree with many members
/// (and correspondingly many nodes and epoch encryption key pairs). The full
/// round-trip diff in `migrate_and_check` catches any dropped node or key pair.
#[test]
fn test_migration_large_group() {
    // Number of members added after Alice, chosen large enough to build a
    // deep, multi-level ratchet tree.
    const ADDED_MEMBERS: usize = 100;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration large group");

    let alice_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", ciphersuite, &alice_provider);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();
        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.clone(),
            alice_credential,
        )
        .expect("creating group");

        // Build the members' key packages (one shared provider is fine — they only
        // need to be valid to add) and add them all in one commit.
        let addee_state = StorageProviderState::default();
        let addee_storage = addee_state.as_postcard_provider();
        let addee_provider = addee_storage.as_openmls_provider();
        let key_packages: Vec<_> = (0..ADDED_MEMBERS)
            .map(|i| {
                let (credential, signer) = generate_credential(
                    format!("member{i}").as_bytes(),
                    ciphersuite,
                    &addee_provider,
                );
                generate_key_package(ciphersuite, credential, &addee_provider, &signer)
                    .key_package()
                    .clone()
            })
            .collect();
        alice_group
            .add_members(&alice_provider, &alice_signer, &key_packages)
            .expect("adding members");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merging the add commit");
        assert_eq!(alice_group.members().count(), ADDED_MEMBERS + 1);
    }

    migrate_and_check(&alice_state, b"migration large group");
}

/// Migration must preserve a pending (staged, not merged) commit whose content is
/// a *non-self-update* proposal — here an `AppEphemeral` proposal added via the
/// commit builder. AppEphemeral is an `extensions-draft` feature introduced in
/// 0.8.0, so this is gated on the 0.8.1 source with the draft on both sides.
#[cfg(all(feature = "compat_0_8_1", feature = "extensions-draft"))]
#[test]
fn test_migration_pending_app_ephemeral_commit() {
    const COMPONENT_ID: u16 = 1;
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration app ephemeral group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        // Members must advertise the AppEphemeral proposal type for the commit to
        // validate.
        let capabilities =
            Capabilities::new(None, None, None, Some(&[ProposalType::AppEphemeral]), None);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .capabilities(capabilities.clone())
            .build();

        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", ciphersuite, &alice_provider);
        let (bob_credential, bob_signer) = generate_credential(b"Bob", ciphersuite, &bob_provider);
        let bob_key_package = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
            .expect("building Bob's key package");

        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.clone(),
            alice_credential,
        )
        .expect("creating group");
        alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_key_package.key_package().clone()],
            )
            .expect("adding Bob");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merging the add commit");

        // Stage (do not merge) a commit carrying an AppEphemeral proposal.
        alice_group
            .commit_builder()
            .add_proposals(vec![Proposal::AppEphemeral(Box::new(
                AppEphemeralProposal::new(COMPONENT_ID, b"migration app-ephemeral data".to_vec()),
            ))])
            .load_psks(alice_provider.storage())
            .expect("loading psks")
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_| true,
            )
            .expect("building the commit")
            .stage_commit(&alice_provider)
            .expect("staging the commit");

        // The scenario under test: a pending commit (not a self-update).
        assert!(alice_group.pending_commit().is_some());
    }

    let after = migrate_and_check(&alice_state, b"migration app ephemeral group");
    // Confirm the staged AppEphemeral proposal actually crossed the bridge.
    assert!(
        after.to_string().contains("AppEphemeral"),
        "the pending AppEphemeral proposal should be present in the migrated state"
    );
}

/// Exercises the `migrate_group` example used in the book, so it stays valid.
#[test]
fn test_migration_book_example() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration book example group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Set up a group in the previous version's storage.
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);
    }

    // Migrate Alice's group into a current-version storage provider.
    let old_provider = alice_state.as_postcard_provider();
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    migrate_group(&old_provider, &new_provider, &group_id);

    // The migrated group can now be loaded with the current API.
    let new_group_id =
        openmls_current::prelude::GroupId::from_slice(b"migration book example group");
    let migrated = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("error loading migrated group")
        .expect("no migrated group state persisted");
    assert_eq!(migrated.members().count(), 2);
}

/// Post-migration operability: after migrating, the group must be usable with the
/// *current* API — here Alice performs a self-update and merges it.
#[test]
fn test_migration_then_operate() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration operate group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Set up a group in the previous version's storage.
    let alice_signer = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);
        alice_signer
    };

    // Migrate Alice into a current-version store.
    let old_provider = alice_state.as_postcard_provider();
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    migrate_group(&old_provider, &new_provider, &group_id);
    // The signer is application-managed; migrate it into the new store too.
    let signer = migrate_signature_key_pair(&alice_signer, &new_provider);

    // Drive a real operation on the migrated group with the current API.
    let current_provider = new_provider.as_openmls_provider();
    let new_group_id = openmls_current::prelude::GroupId::from_slice(b"migration operate group");
    let mut alice = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("error loading migrated group")
        .expect("no migrated group state persisted");

    alice
        .self_update(
            &current_provider,
            &signer,
            openmls_current::prelude::LeafNodeParameters::default(),
        )
        .expect("error self-updating migrated group");
    alice
        .merge_pending_commit(&current_provider)
        .expect("error merging self-update on migrated group");

    assert_eq!(alice.epoch().as_u64(), 2);
    assert_eq!(alice.members().count(), 2);
}

/// Post-migration operability across members: a migrated member can process an
/// incoming commit created at the migrated epoch. Unlike a self-update (which
/// re-keys), this exercises the migrated epoch encryption key pairs — the
/// group-associated data the bundle migration carries beyond the group struct.
#[test]
fn test_migration_then_process_incoming_commit() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration process group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Two-member group in the previous version (Bob joins from the welcome so he
    // holds his own state).
    let bob_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (_alice_group, _alice_signer, bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);

        bob_signer
    };

    // Migrate both members into their own current-version stores.
    let alice_new = StorageProviderState::default();
    {
        let old_provider = alice_state.as_postcard_provider();
        let new_provider = alice_new.as_serde_json_provider();
        migrate_group(&old_provider, &new_provider, &group_id);
    }
    let bob_new = StorageProviderState::default();
    {
        let old_provider = bob_state.as_postcard_provider();
        let new_provider = bob_new.as_serde_json_provider();
        migrate_group(&old_provider, &new_provider, &group_id);
    }

    // Operate with the current API.
    let alice_np = alice_new.as_serde_json_provider();
    let alice_provider = alice_np.as_openmls_provider();
    let bob_np = bob_new.as_serde_json_provider();
    let bob_provider = bob_np.as_openmls_provider();
    // Bob's signer is application-managed; migrate it into his new store.
    let bob_signer = migrate_signature_key_pair(&bob_signer_old, &bob_np);

    let new_group_id = openmls_current::prelude::GroupId::from_slice(b"migration process group");
    let mut alice = openmls_current::prelude::MlsGroup::load(&alice_np, &new_group_id)
        .expect("error loading Alice")
        .expect("no migrated group for Alice");
    let mut bob = openmls_current::prelude::MlsGroup::load(&bob_np, &new_group_id)
        .expect("error loading Bob")
        .expect("no migrated group for Bob");

    // Bob commits a self-update at the migrated epoch and sends it to Alice.
    let commit = bob
        .self_update(
            &bob_provider,
            &bob_signer,
            openmls_current::prelude::LeafNodeParameters::default(),
        )
        .expect("error creating Bob's commit")
        .into_commit();
    bob.merge_pending_commit(&bob_provider)
        .expect("error merging Bob's commit");

    // Alice processes Bob's commit — this decrypts against her migrated epoch
    // encryption key pairs, so it only succeeds if they crossed the migration.
    let commit_bytes = commit
        .tls_serialize_detached()
        .expect("error serializing commit");
    let commit_in =
        openmls_current::prelude::MlsMessageIn::tls_deserialize(&mut commit_bytes.as_slice())
            .expect("error deserializing commit");
    let protocol_message = commit_in
        .try_into_protocol_message()
        .expect("commit is a protocol message");
    let processed = alice
        .process_message(&alice_provider, protocol_message)
        .expect("error processing Bob's commit on the migrated group");
    match processed.into_content() {
        openmls_current::prelude::ProcessedMessageContent::StagedCommitMessage(staged) => {
            alice
                .merge_staged_commit(&alice_provider, *staged)
                .expect("error merging Bob's commit");
        }
        _ => panic!("expected a staged commit"),
    }

    assert_eq!(alice.epoch().as_u64(), 2);
    assert_eq!(alice.members().count(), 2);
}

/// Migrating into a store that already holds the group under the same key
/// encoding — an in-place migration, or simply a re-run — must *replace* the
/// group's state, not accumulate duplicates in the append-style tables (own leaf
/// nodes and the proposal queue). This migrates the same group twice into one
/// store and checks neither table grew.
#[test]
fn test_migration_replaces_existing_group() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration idempotent group");

    // Set up a previous-version group with a pending self-update *proposal*, which
    // populates both accumulate tables: it queues a proposal and appends an own
    // leaf node.
    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (mut alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);
        alice_group
            .propose_self_update(
                &alice_provider,
                &alice_signer,
                LeafNodeParameters::default(),
            )
            .expect("proposing a self-update");
        assert_eq!(alice_group.pending_proposals().count(), 1);
    }

    // Export the group with the previous version and bridge it into the current
    // `GroupMigrationBundle`.
    let bundle: openmls_current::storage::GroupMigrationBundle = {
        let old_provider = alice_state.as_postcard_provider();
        let exported =
            openmls_compat::prelude::MlsGroup::export_for_migration(&old_provider, &group_id)
                .expect("exporting the group")
                .expect("no group with this id in the old storage");
        let serialized = serde_json::to_vec(&exported).expect("serializing the bundle");
        serde_json::from_slice(&serialized).expect("deserializing the bundle")
    };

    // Store the bundle into one target serde_json store twice. What creates the
    // duplication risk is two writes landing on the same storage keys; both writes
    // here go to the same serde_json store, so they key the group identically —
    // modelling an in-place migration or a re-run.
    //
    // The target must be self-describing: the current `MlsGroupJoinConfig`
    // deserializes `past_epoch_deletion_policy` via an `#[serde(untagged)]` enum
    // (to accept older encodings), which needs `deserialize_any` and so cannot be
    // loaded from postcard (it fails with `WontImplement`). Current-version group
    // state therefore cannot round-trip through postcard at all.
    let target_state = StorageProviderState::default();
    {
        let target_storage = target_state.as_serde_json_provider();
        for _ in 0..2 {
            bundle
                .store(&target_storage)
                .expect("storing the migration bundle");
        }
    }

    // The twice-stored group must match a single store: each accumulate table
    // holds one entry, not two.
    let target_storage = target_state.as_serde_json_provider();
    let new_group_id = openmls_current::prelude::GroupId::from_slice(b"migration idempotent group");
    let reloaded = openmls_current::prelude::MlsGroup::load(&target_storage, &new_group_id)
        .expect("loading the migrated group")
        .expect("no migrated group state persisted");

    assert_eq!(
        reloaded.pending_proposals().count(),
        1,
        "the proposal queue was duplicated across a second migration"
    );
    let value = serde_json::to_value(&reloaded).expect("serializing the migrated group");
    assert_eq!(
        value["own_leaf_nodes"].as_array().map(|nodes| nodes.len()),
        Some(1),
        "own_leaf_nodes was duplicated across a second migration"
    );
    assert_eq!(reloaded.members().count(), 2);
}

// =============================================================================
// Application-managed material
//
// Signature key pairs, PSKs, and published key packages are not group-scoped, so
// the library cannot enumerate them per group; the application tracks their ids
// and migrates them itself with the same read -> serde bridge -> write pattern as
// the group. The tests below show this is possible with only existing public
// APIs, and drive each migrated item through a real current-version operation.
// =============================================================================

/// Create a current-version basic credential together with a freshly generated
/// current-version signature key pair, persisting the key pair in `provider`'s
/// storage. The current-version counterpart of [`generate_credential`].
fn current_credential(
    identity: &[u8],
    ciphersuite: openmls_current::prelude::Ciphersuite,
    provider: &impl openmls_traits::OpenMlsProvider,
) -> (
    openmls_current::prelude::CredentialWithKey,
    openmls_basic_credential_current::SignatureKeyPair,
) {
    let credential = openmls_current::prelude::BasicCredential::new(identity.to_vec());
    let signature_keys =
        openmls_basic_credential_current::SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .unwrap();
    signature_keys.store(provider.storage()).unwrap();

    (
        openmls_current::prelude::CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

// ANCHOR: migrate_signature_key_pair
/// Migrate one application-managed signature key pair by bridging it through
/// serde: serialize the previous version's `SignatureKeyPair`, deserialize it as
/// the current version's type, and store it in the current provider.
fn migrate_signature_key_pair(
    old_signer: &openmls_basic_credential_compat::SignatureKeyPair,
    new_storage: &SerdeJsonProvider<'_>,
) -> openmls_basic_credential_current::SignatureKeyPair {
    let signer: openmls_basic_credential_current::SignatureKeyPair =
        serde_json::from_slice(&serde_json::to_vec(old_signer).expect("serialize signer"))
            .expect("deserialize signer into the current version");
    signer
        .store(new_storage)
        .expect("store the migrated signer");
    signer
}
// ANCHOR_END: migrate_signature_key_pair

// ANCHOR: migrate_key_package
/// Migrate one key package. The application supplies the hash reference
/// it tracks (OpenMLS keys stored key packages by it). We read the stored
/// `KeyPackageBundle` with the previous version's storage API, bridge it through
/// serde, and write it to the current store under its current-version hash
/// reference. Returns the bridged bundle so the caller can use its `KeyPackage`.
///
/// The two `StorageProvider` traits (previous and current version) are brought
/// into scope in separate blocks: the backing `PostcardProvider` implements both,
/// so keeping only one in scope per call avoids an ambiguous method resolution.
fn migrate_key_package(
    old_storage: &PostcardProvider<'_>,
    old_hash_ref: &openmls_compat::prelude::KeyPackageRef,
    new_provider: &impl openmls_traits::OpenMlsProvider,
) -> openmls_current::prelude::KeyPackageBundle {
    // 1. Read the stored bundle (public key package + private init and encryption
    //    keys) with the previous version's storage API.
    let old_bundle: KeyPackageBundle = {
        use openmls_traits_compat::storage::StorageProvider as _;
        old_storage
            .key_package(old_hash_ref)
            .expect("read the old key package")
            .expect("no key package stored under this hash ref")
    };

    // 2. Bridge it through serde into the current version's type.
    let bundle: openmls_current::prelude::KeyPackageBundle =
        serde_json::from_slice(&serde_json::to_vec(&old_bundle).expect("serialize key package"))
            .expect("deserialize key package into the current version");

    // 3. Write it to the current store, keyed by its current-version hash ref.
    let new_hash_ref = bundle
        .key_package()
        .hash_ref(new_provider.crypto())
        .expect("compute the current key package hash ref");
    {
        use openmls_traits::storage::StorageProvider as _;
        new_provider
            .storage()
            .write_key_package(&new_hash_ref, &bundle)
            .expect("write the migrated key package");
    }

    bundle
}
// ANCHOR_END: migrate_key_package

/// Migrating a published key package with [`migrate_key_package`], then proving it
/// is usable: a fresh current-version group adds the migrated key package and its
/// owner joins from the welcome using the migrated bundle.
#[test]
fn test_migration_key_package() {
    let old_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let current_ciphersuite =
        openmls_current::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Bob publishes a key package into the previous version's store.
    let bob_old_state = StorageProviderState::default();
    let bob_old_storage = bob_old_state.as_postcard_provider();
    let bob_old_provider = bob_old_storage.as_openmls_provider();
    let (bob_credential, bob_signer) =
        generate_credential(b"Bob", old_ciphersuite, &bob_old_provider);
    let bob_key_package = generate_key_package(
        old_ciphersuite,
        bob_credential,
        &bob_old_provider,
        &bob_signer,
    );

    // The application tracks the key package's hash reference (OpenMLS keys stored
    // key packages by it), so it can address the stored bundle for migration.
    let old_crypto = openmls_libcrux_crypto_compat::CryptoProvider::new().unwrap();
    let old_hash_ref = bob_key_package
        .key_package()
        .hash_ref(&old_crypto)
        .expect("computing the old key package hash ref");

    // Migrate the published key package into a current-version store.
    let bob_new_state = StorageProviderState::default();
    let bob_new_storage = bob_new_state.as_serde_json_provider();
    let bob_new_provider = bob_new_storage.as_openmls_provider();
    let current_bundle = migrate_key_package(&bob_old_storage, &old_hash_ref, &bob_new_provider);

    // === Prove the migrated key package is usable with the current API ===
    // A fresh current-version group (Alice) adds Bob via his migrated key package,
    // and Bob joins from the welcome using his migrated bundle.
    let alice_state = StorageProviderState::default();
    let alice_storage = alice_state.as_serde_json_provider();
    let alice_provider = alice_storage.as_openmls_provider();
    let (alice_credential, alice_signer) =
        current_credential(b"Alice", current_ciphersuite, &alice_provider);

    let config = openmls_current::prelude::MlsGroupCreateConfig::builder()
        .ciphersuite(current_ciphersuite)
        .build();
    let mut alice_group = openmls_current::prelude::MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &config,
        openmls_current::prelude::GroupId::from_slice(b"migration key package group"),
        alice_credential,
    )
    .expect("creating the current-version group");

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[current_bundle.key_package().clone()],
        )
        .expect("adding Bob via his migrated key package");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merging Alice's add commit");

    // Bob joins from the welcome. `StagedWelcome` looks up his migrated bundle in
    // the current store by hash ref, so the join only succeeds if it was migrated.
    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("serializing the welcome");
    let welcome =
        openmls_current::prelude::MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
            .expect("deserializing the welcome");
    let openmls_current::prelude::MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("expected the message to be a welcome")
    };
    let bob_group = openmls_current::prelude::StagedWelcome::new_from_welcome(
        &bob_new_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("creating Bob's staged welcome from the migrated key package")
    .into_group(&bob_new_provider)
    .expect("Bob joining from the migrated key package");

    assert_eq!(bob_group.members().count(), 2);
}

/// The group-owned application export tree (`extensions-draft`) should be migrated.
/// This test confirms both that the application export tree's *state* crosses
/// (a component id consumed before migration cannot be exported again afterwards)
/// and that the tree stays *functional* (a fresh component id can be exported).
#[cfg(feature = "extensions-draft")]
#[test]
fn test_migration_application_export_tree() {
    let old_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration app export tree group");
    let consumed_component_id: u16 = 0x8000;

    // Create a group with the previous version and consume `consumed_component_id`
    // via `safe_export_secret`, which advances and persists the export tree.
    let alice_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", old_ciphersuite, &alice_provider);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(old_ciphersuite)
            .build();
        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.clone(),
            alice_credential,
        )
        .expect("creating the group");

        let old_crypto = openmls_libcrux_crypto_compat::CryptoProvider::new().unwrap();
        alice_group
            .safe_export_secret(&old_crypto, &alice_storage, consumed_component_id)
            .expect("exporting the consumed component secret before migration");
    }

    // Migrate the group; the application export tree is inside the group state.
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    {
        let old_provider = alice_state.as_postcard_provider();
        migrate_group(&old_provider, &new_provider, &group_id);
    }

    // Load the migrated group with the current API and check the tree.
    let new_group_id =
        openmls_current::prelude::GroupId::from_slice(b"migration app export tree group");
    let mut alice = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("loading the migrated group")
        .expect("no migrated group state persisted");
    let new_crypto = openmls_libcrux_crypto_current::CryptoProvider::new().unwrap();

    // (a) The consumed component id cannot be exported again — the tree's consumed
    //     state crossed the migration.
    alice
        .safe_export_secret(&new_crypto, &new_provider, consumed_component_id)
        .expect_err("re-exporting a consumed component id must fail after migration");

    // (b) A fresh component id can still be exported — the tree is functional.
    alice
        .safe_export_secret(&new_crypto, &new_provider, consumed_component_id + 1)
        .expect("exporting a fresh component id must succeed after migration");
}

/// Toggling `extensions-draft` *on* during migration: a source version WITHOUT
/// the feature migrates into a current version WITH it. The new extensions-draft
/// fields (`safe_aad`, `application_export_tree`) have no source counterpart, so
/// they must default on import — in particular, without `#[serde(default)]` on
/// `application_export_tree` the bundle would fail to deserialize (this test is
/// what makes that default necessary). After the first merged commit the
/// application export tree initializes and becomes usable.
///
/// Gated on the target having the feature while the source does not — the whole
/// point of splitting `extensions-draft` into `-current` / `-compat`.
#[cfg(all(
    feature = "extensions-draft-current",
    not(feature = "extensions-draft-compat")
))]
#[test]
fn test_migration_enabling_extensions_draft() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"migration enable ext-draft group");

    // Source group WITHOUT extensions-draft.
    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    let alice_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, alice_signer, _bob_signer) =
            setup_alice_bob_group(ciphersuite, &group_id, &alice_provider, &bob_provider);
        alice_signer
    };

    // Migrate into a current-version store that HAS extensions-draft. Deserializing
    // the bundle only succeeds because the new extensions-draft fields default.
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    {
        let old_provider = alice_state.as_postcard_provider();
        migrate_group(&old_provider, &new_provider, &group_id);
    }
    let signer = migrate_signature_key_pair(&alice_signer_old, &new_provider);

    // The migrated group loads cleanly with the current API.
    let current_provider = new_provider.as_openmls_provider();
    let new_group_id =
        openmls_current::prelude::GroupId::from_slice(b"migration enable ext-draft group");
    let mut alice = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("loading the migrated group")
        .expect("no migrated group state persisted");
    assert_eq!(alice.members().count(), 2);

    // The application export tree defaults to `None` on import and initializes on
    // the next merged commit; after that, `safe_export_secret` works — proving the
    // toggled-on feature is functional post-migration.
    alice
        .self_update(
            &current_provider,
            &signer,
            openmls_current::prelude::LeafNodeParameters::default(),
        )
        .expect("self-updating the migrated group");
    alice
        .merge_pending_commit(&current_provider)
        .expect("merging the self-update");
    let crypto = openmls_libcrux_crypto_current::CryptoProvider::new().unwrap();
    alice
        .safe_export_secret(&crypto, &new_provider, 0x8000)
        .expect("exporting a component secret after enabling extensions-draft");
}
