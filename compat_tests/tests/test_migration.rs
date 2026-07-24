//! Test migration
//!
//! Sets up a group using a *previous* version's API (0.7.4 or 0.8.1, selected by
//! the `storage_migration_0_7` / `storage_migration_0_8` feature), each member
//! backed by their own postcard-serialized storage. A member then migrates their
//! persisted state to the current version by exporting it with the previous
//! version's API into a `GroupMigrationBundle`, bridging that through `serde_json`,
//! and importing it with `GroupMigrationBundle::store` into a current-version,
//! self-describing store.
//!
//! Two things are verified:
//!
//! 1. *State* preservation — every field round-trips through the version bridge,
//!    and everything the migration writes survives a current-version storage
//!    round-trip, checked against each supported target format — `serde_json` and
//!    `ciborium` (see [`migrate_and_check`]).
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
//!
//! A migration can be run either all-at-once or *lazily*, per group on first access
//! (rather than migrating every group up front); [`test_migration_lazy_per_group`]
//! covers the lazy path, including the per-group "already migrated" marker.

#![cfg(any(feature = "storage_migration_0_8", feature = "storage_migration_0_7"))]

use openmls_compat_tests::test_storage_provider::{
    CiboriumOpenMlsProvider, CiboriumProvider, PostcardOpenMlsProvider, PostcardProvider,
    SerdeJsonOpenMlsProvider, SerdeJsonProvider, StorageProviderState,
};

// Imports for `compat_0_8_1` tests
#[cfg(feature = "compat_0_8_1")]
use openmls_0_8_1 as openmls_compat;
#[cfg(feature = "compat_0_8_1")]
use openmls_basic_credential_0_8 as openmls_basic_credential_compat;
#[cfg(feature = "compat_0_8_1")]
use openmls_traits_0_5_0 as openmls_traits_compat;

// Imports for `compat_0_7_4` tests
#[cfg(feature = "compat_0_7_4")]
use openmls_0_7_4 as openmls_compat;
#[cfg(feature = "compat_0_7_4")]
use openmls_basic_credential_0_7 as openmls_basic_credential_compat;
#[cfg(feature = "compat_0_7_4")]
use openmls_traits_0_4_1 as openmls_traits_compat;

// The test crypto provider implements the compat crypto trait
use openmls_compat_tests::test_crypto_provider as openmls_libcrux_crypto_compat;

use openmls_compat::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_current::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_traits_compat::signatures::Signer;

use openmls as openmls_current;

/// The ciphersuite used throughout these tests
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// GroupId wrapper to allow constructing a GroupId for
/// both `compat` and `current` versions of the library
struct TestGroupId(Vec<u8>);

impl TestGroupId {
    fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    fn compat(&self) -> openmls_compat::prelude::GroupId {
        openmls_compat::prelude::GroupId::from_slice(&self.0)
    }

    fn current(&self) -> openmls_current::prelude::GroupId {
        openmls_current::prelude::GroupId::from_slice(&self.0)
    }
}

/// Helper trait that can be implemented for multiple storage format targets.
trait StorageMigrationTarget {
    type Provider<'a>: openmls_current::storage::StorageProvider;
    type OpenMlsProvider<'a>: openmls_traits::OpenMlsProvider;
    fn provider(state: &StorageProviderState) -> Self::Provider<'_>;
    fn openmls_provider<'a, 'b>(provider: &'a Self::Provider<'b>) -> Self::OpenMlsProvider<'a>;
    /// Human-readable format name, for failure messages.
    const NAME: &'static str;
}

/// The `serde_json` (self-describing, human-readable) target.
struct SerdeJson;
impl StorageMigrationTarget for SerdeJson {
    type Provider<'a> = SerdeJsonProvider<'a>;
    type OpenMlsProvider<'a> = SerdeJsonOpenMlsProvider<'a>;
    fn provider(state: &StorageProviderState) -> SerdeJsonProvider<'_> {
        state.as_serde_json_provider()
    }
    fn openmls_provider<'a, 'b>(
        provider: &'a SerdeJsonProvider<'b>,
    ) -> SerdeJsonOpenMlsProvider<'a> {
        provider.as_openmls_provider()
    }
    const NAME: &'static str = "serde_json";
}

/// The `ciborium` (self-describing, binary CBOR) target.
struct Ciborium;
impl StorageMigrationTarget for Ciborium {
    type Provider<'a> = CiboriumProvider<'a>;
    type OpenMlsProvider<'a> = CiboriumOpenMlsProvider<'a>;
    fn provider(state: &StorageProviderState) -> CiboriumProvider<'_> {
        state.as_ciborium_provider()
    }
    fn openmls_provider<'a, 'b>(provider: &'a CiboriumProvider<'b>) -> CiboriumOpenMlsProvider<'a> {
        provider.as_openmls_provider()
    }
    const NAME: &'static str = "ciborium";
}

/// Helper function to generate a new BasicCredential with a SignatureKeyPair
/// that is stored in the original store
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

/// Helper function to build a new KeyPackage using the original provider
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

/// Create an operational two-member (Alice + Bob) group:
///     - Alice creates a group and adds Bob
///     - Bob joins from the Welcome
/// Returns Alice's group handle and both members' signers.
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

    // Bob joins from the welcome
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

/// Check the schema changes between serializations,
/// ignoring fields that were added in later versions (or when enabling a feature)
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

/// Check that a migrated GroupMigration bundle matches the exported one,
/// field-by-field ignoring the expected differences.
fn assert_bundle_preserved(before: &serde_json::Value, after: &serde_json::Value) {
    let mut diffs = Vec::new();
    diff_json("$", before, after, &mut diffs);
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
}

/// Basic assertions to check a migrated group
fn migration_assertions(
    original: &openmls_compat::prelude::MlsGroup,
    migrated: &openmls_current::prelude::MlsGroup,
) {
    // chekc that the epoch matches
    assert_eq!(
        original.epoch().as_u64(),
        migrated.epoch().as_u64(),
        "epoch differs between the original and migrated group"
    );

    // check that the index and signature key matches for each member
    let original_members: Vec<(u32, Vec<u8>)> = original
        .members()
        .map(|m| (m.index.u32(), m.signature_key))
        .collect();
    let migrated_members: Vec<(u32, Vec<u8>)> = migrated
        .members()
        .map(|m| (m.index.u32(), m.signature_key))
        .collect();
    assert_eq!(
        original_members, migrated_members,
        "membership differs between the original and migrated group"
    );

    // check that the ratchet tree matches
    assert_eq!(
        original
            .export_ratchet_tree()
            .tls_serialize_detached()
            .expect("serializing the original ratchet tree"),
        migrated
            .export_ratchet_tree()
            .tls_serialize_detached()
            .expect("serializing the migrated ratchet tree"),
        "ratchet tree differs between the original and migrated group"
    );

    assert_eq!(
        original.epoch_authenticator().as_slice(),
        migrated.epoch_authenticator().as_slice(),
        "epoch authenticator differs between the original and migrated group"
    );

    // check that the queued proposals match
    let original_proposals: Vec<_> = original.pending_proposals().collect();
    let migrated_proposals: Vec<_> = migrated.pending_proposals().collect();
    assert_eq!(
        original_proposals.len(),
        migrated_proposals.len(),
        "number of queued proposals differs between the original and migrated group"
    );
    for (i, (original_proposal, migrated_proposal)) in original_proposals
        .iter()
        .zip(migrated_proposals.iter())
        .enumerate()
    {
        assert_eq!(
            serde_json::to_value(original_proposal).expect("serializing the original proposal"),
            serde_json::to_value(migrated_proposal).expect("serializing the migrated proposal"),
            "queued proposal at index {i} differs between the original and migrated group"
        );
    }
}

/// Migrate a group, perform checks, and return the migrated group
fn migrate_and_check<S: openmls_current::storage::StorageProvider>(
    alice_state: &StorageProviderState,
    group_id: &TestGroupId,
    target: &S,
    format: &str,
) -> openmls_current::prelude::MlsGroup {
    let alice_storage = alice_state.as_postcard_provider();
    let exported = MlsGroup::export_for_migration(&alice_storage, &group_id.compat())
        .expect("error exporting old group")
        .expect("no group state persisted for Alice");

    // bridge the group via serde_json
    let migrated_group: openmls_current::storage::GroupMigrationBundle =
        serde_json_bridge(&exported).expect("error bridging the migration bundle");

    // check the schema
    let before = serde_json::to_value(&exported).expect("error serializing old group");
    let after = serde_json::to_value(&migrated_group).expect("error serializing migrated group");
    assert_bundle_preserved(&before, &after);

    // store the migrated group into the target store
    migrated_group
        .store(target)
        .unwrap_or_else(|e| panic!("error storing migrated group into {format} store: {e:?}"));

    // load the group from the store for comparison
    let migrated = openmls_current::prelude::MlsGroup::load(target, &group_id.current())
        .unwrap_or_else(|e| panic!("error loading migrated group from {format} store: {e:?}"))
        .expect("no migrated group state persisted");

    // compare the group in the migrated, serialized bundle to the serialized group
    // that was loaded from the new store
    assert_eq!(
        after["group"],
        serde_json::to_value(&migrated).expect("error serializing reloaded group"),
        "{format} storage round-trip changed the group"
    );

    // load the original group for comparison
    let original = openmls_compat::prelude::MlsGroup::load(&alice_storage, &group_id.compat())
        .expect("error loading the original group")
        .expect("no original group state persisted");

    // perform basic migration checks
    migration_assertions(&original, &migrated);

    // return the migrated group for further checks
    migrated
}

/// For testing only, merge the pending commit on both the migrated and original group,
/// and compare them
fn merge_pending_commit_and_compare<'a, 'b: 'a, T: StorageMigrationTarget>(
    alice_state: &StorageProviderState,
    group_id: &TestGroupId,
    target: &'a T::Provider<'b>,
    mut migrated: openmls_current::prelude::MlsGroup,
) {
    let migrated_provider = T::openmls_provider(target);
    migrated
        .merge_pending_commit(&migrated_provider)
        .expect("merging the migrated pending commit");

    let alice_storage = alice_state.as_postcard_provider();
    let old_provider = alice_storage.as_openmls_provider();
    let mut original = openmls_compat::prelude::MlsGroup::load(&alice_storage, &group_id.compat())
        .expect("loading the original group")
        .expect("no original group state persisted");
    original
        .merge_pending_commit(&old_provider)
        .expect("merging the original pending commit");

    migration_assertions(&original, &migrated);
}

// ANCHOR: serde_json_bridge
/// Bridge a value across the serde_json version boundary: serialize `source` (a
/// previous-version type) to JSON, then deserialize it as the current-version type
/// `T`.
///
/// The intermediate JSON buffer holds the value's secret key material in plaintext.
/// Unlike the typed `source` and returned `T` — whose secret fields are
/// `SecretVLBytes` and are wiped on their own drop — a plain `Vec<u8>` is not
/// scrubbed when freed, so it is held in a `Zeroizing` buffer that is wiped when
/// this function returns, on the error path as well as on success.
///
/// Keep the bridge on this byte-buffer path (`to_vec` / `from_slice`)
/// rather than routing it through `serde_json::Value`.
fn serde_json_bridge<S: serde::Serialize, T: serde::de::DeserializeOwned>(
    source: &S,
) -> Result<T, serde_json::Error> {
    let serialized = zeroize::Zeroizing::new(serde_json::to_vec(source)?);
    serde_json::from_slice(&serialized)
}
// ANCHOR_END: serde_json_bridge

// ANCHOR: migration
/// Migrate a single group from the previous OpenMLS version to the current one.
///
/// `old_provider` implements the *previous* version's storage traits and already
/// holds the group; `new_provider` implements the *current* version's storage
/// traits and receives the migrated group. Both refer to the same `group_id`.
///
/// This requires the `migration-export` feature on the previous version's
/// `openmls` crate and the `migration-import` feature on the current one.
///
/// **NOTE**: The `migration-export` feature is not available on the current
/// `openmls` version, since there are no supported migration paths that would
/// utilize this feature yet, although it may be added later, if needed.
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

    // 2. Bridge the bundle through `serde_json` into the *current* version's
    //    migration bundle. The intermediate buffer is zeroized on drop (see
    //    `serde_json_bridge`).
    let bundle: openmls_current::storage::GroupMigrationBundle =
        serde_json_bridge(&bundle).expect("error bridging the migration bundle through serde_json");

    // 3. Write the group and all its data to storage in the current version's
    //    format.
    bundle
        .store(new_provider)
        .expect("error storing the migrated group");
}
// ANCHOR_END: migration

/// Migration must preserve the retained message secrets of past epochs.
fn test_migration_multiple_epochs_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration multi-epoch group");

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
            group_id.compat(),
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

    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
    assert_eq!(
        migrated.epoch().as_u64(),
        5,
        "migrated group is at the wrong epoch"
    );
    assert_eq!(migrated.members().count(), 2);
}

/// Checks that a migration preserves proposals
fn test_migration_with_proposals_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration proposals group");

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

        let (mut alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );

        // Alice proposes Adds without committing them
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

        assert_eq!(alice_group.pending_proposals().count(), 2);
        assert!(alice_group.pending_commit().is_none());
    }

    // perform the migration
    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);

    // migrate the group; this also checks that the proposals in the store match
    let migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
}

/// Tests that a migration preserves a pending commit.
fn test_migration_with_pending_commit_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration pending commit group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (mut alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );

        // create a (pending) commit including a SelfUpdate proposal
        alice_group
            .self_update(
                &alice_provider,
                &alice_signer,
                LeafNodeParameters::default(),
            )
            .expect("error creating self-update commit");

        assert!(alice_group.pending_commit().is_some());
        assert_eq!(alice_group.pending_proposals().count(), 0);
    }

    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);

    // check that a pending commit is still present
    assert!(migrated.pending_commit().is_some(),);
    assert_eq!(migrated.pending_proposals().count(), 0);

    // merge and the pending commit and compare state
    merge_pending_commit_and_compare::<T>(&alice_state, &group_id, &target, migrated);
}

/// Test that migration preserves a large group
fn test_migration_large_group_impl<T: StorageMigrationTarget>() {
    // Number of members added after Alice, chosen large enough to build a
    // deep, multi-level ratchet tree.
    const ADDED_MEMBERS: usize = 100;

    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration large group");

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
            group_id.compat(),
            alice_credential,
        )
        .expect("creating group");

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

    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
    assert_eq!(
        migrated.members().count(),
        ADDED_MEMBERS + 1,
        "the large group lost members in migration"
    );
}

/// Tests that migration preserves an AppEphemeral proposal
/// in a pending commit.
#[cfg(all(feature = "compat_0_8_1", feature = "extensions-draft"))]
fn test_migration_pending_app_ephemeral_commit_impl<T: StorageMigrationTarget>() {
    const COMPONENT_ID: u16 = 1;
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration app ephemeral group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        // Members must support the AppEphemeral proposal type for the commit to
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
            group_id.compat(),
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

        assert!(alice_group.pending_commit().is_some());
    }

    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
    assert!(migrated.pending_commit().is_some(),);
    // Confirm the staged AppEphemeral proposal actually crossed the bridge (checked
    // before merging, while the commit is still pending).
    let migrated_json = serde_json::to_value(&migrated).expect("error serializing migrated group");
    assert!(
        migrated_json.to_string().contains("AppEphemeral"),
        "the pending AppEphemeral proposal should be present in the migrated state"
    );

    // The migrated pending AppEphemeral commit is usable: merging it yields exactly
    // the group that merging the original's pending commit yields.
    merge_pending_commit_and_compare::<T>(&alice_state, &group_id, &target, migrated);
}

/// Exercises the `migrate_group` example used in the book, so it stays valid.
#[test]
fn test_migration_book_example() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration book example group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Set up a group in the previous version's storage.
    {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );
    }

    // Migrate Alice's group into a current-version storage provider.
    let old_provider = alice_state.as_postcard_provider();
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    migrate_group(&old_provider, &new_provider, &group_id.compat());

    // The migrated group can now be loaded with the current API.
    let new_group_id = group_id.current();
    let migrated = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("error loading migrated group")
        .expect("no migrated group state persisted");
    assert_eq!(migrated.members().count(), 2);
}

/// Post-migration operability: after migrating, the group must be usable with the
/// current API — here Alice performs a self-update and merges it.
#[test]
fn test_migration_then_operate() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration operate group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Set up a group in the previous version's storage.
    let alice_signer = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );
        alice_signer
    };

    // Migrate Alice into a current-version store.
    let old_provider = alice_state.as_postcard_provider();
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    migrate_group(&old_provider, &new_provider, &group_id.compat());
    // The signer is application-managed; migrate it into the new store too.
    let signer = migrate_signature_key_pair(&alice_signer, &new_provider);

    // Drive a real operation on the migrated group with the current API.
    let current_provider = new_provider.as_openmls_provider();
    let new_group_id = group_id.current();
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

/// The migration target need not be JSON. Here the current-version store is CBOR
/// (via `ciborium`), a self-describing *binary* format
fn test_migration_ciborium_target() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration ciborium group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Set up a group in the previous version's (postcard) storage.
    let alice_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );
        alice_signer
    };

    // Migrate Alice's group into a current-version *CBOR* store. The group is
    // exported with the previous version's API, bridged through `serde_json`, and
    // stored with `ciborium` — the bridge format and the target format need not
    // match.
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_ciborium_provider();
    {
        let old_provider = alice_state.as_postcard_provider();
        let bundle = openmls_compat::prelude::MlsGroup::export_for_migration(
            &old_provider,
            &group_id.compat(),
        )
        .expect("error reading the old storage")
        .expect("no group with this id in the old storage");
        let bundle: openmls_current::storage::GroupMigrationBundle =
            serde_json_bridge(&bundle).expect("error bridging the migration bundle");
        bundle
            .store(&new_provider)
            .expect("error storing the migrated group into the CBOR store");
    }

    // Application-managed signature key pair: bridge and store it into the CBOR
    // store too, so the migrated group can be operated.
    let signer: openmls_basic_credential_current::SignatureKeyPair =
        serde_json_bridge(&alice_signer_old).expect("bridge signer into the current version");
    signer
        .store(&new_provider)
        .expect("store the migrated signer in the CBOR store");

    // The migrated group loads from the CBOR store with the current API ...
    let current_provider = new_provider.as_openmls_provider();
    let new_group_id = group_id.current();
    let mut alice = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("error loading the migrated group from the CBOR store")
        .expect("no migrated group state persisted");
    assert_eq!(alice.members().count(), 2);

    // ... and is operable: a self-update round-trips through the CBOR store.
    alice
        .self_update(
            &current_provider,
            &signer,
            openmls_current::prelude::LeafNodeParameters::default(),
        )
        .expect("error self-updating the migrated group in the CBOR store");
    alice
        .merge_pending_commit(&current_provider)
        .expect("error merging the self-update in the CBOR store");

    assert_eq!(alice.epoch().as_u64(), 2);
    assert_eq!(alice.members().count(), 2);
}

// ANCHOR: lazy_load_or_migrate
/// Load a group from the current-version store, migrating it from the previous
/// version *on first access* if it has not been migrated yet.
///
/// This is the building block of a **lazy, per-group** migration: instead of
/// migrating every group up front (a startup stall), each group is migrated the
/// first time the application needs it, exactly once. A per-group marker — a row in
/// the application's own store, here `CiboriumProvider::mark_group_migrated` —
/// records that a group has been migrated so it is never migrated twice, and so an
/// already-migrated group is loaded directly from the current store.
fn lazy_load_or_migrate(
    old_provider: &PostcardProvider<'_>,
    new_provider: &CiboriumProvider<'_>,
    group_id_bytes: &[u8],
) -> openmls_current::prelude::MlsGroup {
    let new_group_id = openmls_current::prelude::GroupId::from_slice(group_id_bytes);

    // Migrate this group only if it has not been migrated into the new store yet.
    // The marker is keyed by the (current-version) group id, checked through the
    // same provider used to load it.
    if !new_provider.is_group_migrated(&new_group_id) {
        let old_group_id = openmls_compat::prelude::GroupId::from_slice(group_id_bytes);
        let bundle =
            openmls_compat::prelude::MlsGroup::export_for_migration(old_provider, &old_group_id)
                .expect("error reading the old storage")
                .expect("no group with this id in the old storage");
        let bundle: openmls_current::storage::GroupMigrationBundle =
            serde_json_bridge(&bundle).expect("error bridging the migration bundle");
        bundle
            .store(new_provider)
            .expect("error storing the migrated group");

        // Set the marker
        new_provider.mark_group_migrated(&new_group_id);
    }

    openmls_current::prelude::MlsGroup::load(new_provider, &new_group_id)
        .expect("error loading the migrated group")
        .expect("no migrated group state persisted")
}
// ANCHOR_END: lazy_load_or_migrate

/// Lazy, per-group migration into a CBOR (`ciborium`) current-version store: with
/// several groups persisted in the previous version, each is migrated only when
/// first accessed, exactly once, and the others stay untouched until accessed.
/// Also confirms a lazily-migrated group is operable (a self-update) and that a
/// re-access short-circuits on the marker without consulting the old store.
#[test]
fn test_migration_lazy_per_group() {
    let ciphersuite = CIPHERSUITE;
    const GROUP_A: &[u8] = b"lazy per-group A";
    const GROUP_B: &[u8] = b"lazy per-group B";

    // Two groups persisted in Alice's previous-version (postcard) store, each with
    // its own Alice signature key pair.
    let alice_state = StorageProviderState::default();
    let bob_a_state = StorageProviderState::default();
    let bob_b_state = StorageProviderState::default();
    let (alice_signer_a, alice_signer_b) = {
        let alice_storage = alice_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_a_storage = bob_a_state.as_postcard_provider();
        let bob_b_storage = bob_b_state.as_postcard_provider();
        let (_group_a, signer_a, _bob_a) = setup_alice_bob_group(
            ciphersuite,
            &GroupId::from_slice(GROUP_A),
            &alice_provider,
            &bob_a_storage.as_openmls_provider(),
        );
        let (_group_b, signer_b, _bob_b) = setup_alice_bob_group(
            ciphersuite,
            &GroupId::from_slice(GROUP_B),
            &alice_provider,
            &bob_b_storage.as_openmls_provider(),
        );
        (signer_a, signer_b)
    };

    // The current-version store: CBOR.
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_ciborium_provider();

    // Eagerly migrate the application-managed signature key pairs (small, not
    // group-scoped) so every migrated group is immediately operable. Keep the
    // current-version group-A signer to drive an operation below.
    let signer_a: openmls_basic_credential_current::SignatureKeyPair =
        serde_json_bridge(&alice_signer_a).expect("bridge Alice's group-A signer");
    signer_a.store(&new_provider).expect("store group-A signer");
    let signer_b: openmls_basic_credential_current::SignatureKeyPair =
        serde_json_bridge(&alice_signer_b).expect("bridge Alice's group-B signer");
    signer_b.store(&new_provider).expect("store group-B signer");

    let old_provider = alice_state.as_postcard_provider();

    // Current-version group ids, used to check the per-group markers.
    let group_a_id = openmls_current::prelude::GroupId::from_slice(GROUP_A);
    let group_b_id = openmls_current::prelude::GroupId::from_slice(GROUP_B);

    // Nothing has been migrated yet.
    assert!(!new_provider.is_group_migrated(&group_a_id));
    assert!(!new_provider.is_group_migrated(&group_b_id));

    // Accessing group A migrates *only* A — group B stays untouched. This is the
    // laziness: no startup pass migrated everything.
    let group_a = lazy_load_or_migrate(&old_provider, &new_provider, GROUP_A);
    assert_eq!(group_a.members().count(), 2);
    assert!(new_provider.is_group_migrated(&group_a_id));
    assert!(
        !new_provider.is_group_migrated(&group_b_id),
        "group B must not be migrated until it is first accessed"
    );

    // Accessing group B migrates it too.
    let group_b = lazy_load_or_migrate(&old_provider, &new_provider, GROUP_B);
    assert_eq!(group_b.members().count(), 2);
    assert!(new_provider.is_group_migrated(&group_b_id));

    // Re-accessing A short-circuits on the marker and must not consult the old
    // store: passing an *empty* old store proves the old data is not read again.
    let empty_old_state = StorageProviderState::default();
    let empty_old = empty_old_state.as_postcard_provider();
    let group_a_again = lazy_load_or_migrate(&empty_old, &new_provider, GROUP_A);
    assert_eq!(group_a_again.members().count(), 2);

    // The lazily-migrated group A is operable with its eagerly-migrated signer.
    let current_provider = new_provider.as_openmls_provider();
    let mut alice_a = lazy_load_or_migrate(&old_provider, &new_provider, GROUP_A);
    alice_a
        .self_update(
            &current_provider,
            &signer_a,
            openmls_current::prelude::LeafNodeParameters::default(),
        )
        .expect("error self-updating the lazily-migrated group");
    alice_a
        .merge_pending_commit(&current_provider)
        .expect("error merging the self-update");
    assert_eq!(alice_a.epoch().as_u64(), 2);
    assert_eq!(alice_a.members().count(), 2);
}

/// Test processing an incoming message after migrating a group.
#[test]
fn test_migration_then_process_incoming_commit() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration process group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Two-member group in the previous version (Bob joins from the welcome so he
    // holds his own state).
    let bob_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (_alice_group, _alice_signer, bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );

        bob_signer
    };

    // Migrate both members into their own current-version stores.
    let alice_new = StorageProviderState::default();
    {
        let old_provider = alice_state.as_postcard_provider();
        let new_provider = alice_new.as_serde_json_provider();
        migrate_group(&old_provider, &new_provider, &group_id.compat());
    }
    let bob_new = StorageProviderState::default();
    {
        let old_provider = bob_state.as_postcard_provider();
        let new_provider = bob_new.as_serde_json_provider();
        migrate_group(&old_provider, &new_provider, &group_id.compat());
    }

    // Operate with the current API.
    let alice_np = alice_new.as_serde_json_provider();
    let alice_provider = alice_np.as_openmls_provider();
    let bob_np = bob_new.as_serde_json_provider();
    let bob_provider = bob_np.as_openmls_provider();
    // Bob's signer is application-managed; migrate it into his new store.
    let bob_signer = migrate_signature_key_pair(&bob_signer_old, &bob_np);

    let new_group_id = group_id.current();
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

    // Alice processes Bob's commit
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

/// test that a migrated group can decrypt an application message
fn test_migration_then_decrypt_application_message_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration decrypt application message");
    const PLAINTEXT: &[u8] = b"hello across the migration boundary";

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    // Previous version: a two-member group where Bob sends an application message
    // (at the current epoch) that Alice has not yet processed.
    let message_wire = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, _alice_signer, bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );

        // Bob (loaded from his own persisted state) creates the application message.
        let mut bob_group =
            openmls_compat::prelude::MlsGroup::load(&bob_storage, &group_id.compat())
                .expect("loading Bob's group")
                .expect("no group state persisted for Bob");
        bob_group
            .create_message(&bob_provider, &bob_signer, PLAINTEXT)
            .expect("Bob creating an application message")
            .tls_serialize_detached()
            .expect("serializing the application message")
    };

    // Migrate Alice into the target store, then decrypt Bob's message with the
    // current API against her migrated `message_secrets`.
    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let mut alice = migrate_and_check(&alice_state, &group_id, &target, T::NAME);

    let provider = T::openmls_provider(&target);
    let message_in =
        openmls_current::prelude::MlsMessageIn::tls_deserialize(&mut message_wire.as_slice())
            .expect("deserializing the application message");
    let protocol_message = message_in
        .try_into_protocol_message()
        .expect("application message is a protocol message");
    let processed = alice
        .process_message(&provider, protocol_message)
        .expect("processing Bob's application message on the migrated group");
    match processed.into_content() {
        openmls_current::prelude::ProcessedMessageContent::ApplicationMessage(
            application_message,
        ) => {
            assert_eq!(
                application_message.into_bytes(),
                PLAINTEXT,
                "decrypted application message does not match the original plaintext"
            );
        }
        _ => panic!("expected an application message"),
    }
}

/// Migrating into a store that already holds the group under the same key
/// encoding — an in-place migration, or simply a re-run — must *replace* the
/// group's state, not accumulate duplicates in the append-style tables (own leaf
/// nodes and the proposal queue). This migrates the same group twice into one
/// store and checks neither table grew.
#[test]
fn test_migration_replaces_existing_group() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration idempotent group");

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
        let (mut alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );
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
        let exported = openmls_compat::prelude::MlsGroup::export_for_migration(
            &old_provider,
            &group_id.compat(),
        )
        .expect("exporting the group")
        .expect("no group with this id in the old storage");
        serde_json_bridge(&exported).expect("bridging the bundle")
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
    let new_group_id = group_id.current();
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

/// Helper function to create a BasicCredential, using a SignatureKeyPair
/// stored in the storage provider
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
/// `serde_json`: serialize the previous version's `SignatureKeyPair`, deserialize
/// it as the current version's type, and store it in the current provider.
fn migrate_signature_key_pair(
    old_signer: &openmls_basic_credential_compat::SignatureKeyPair,
    new_storage: &SerdeJsonProvider<'_>,
) -> openmls_basic_credential_current::SignatureKeyPair {
    let signer: openmls_basic_credential_current::SignatureKeyPair =
        serde_json_bridge(old_signer).expect("bridge signer into the current version");
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
/// `serde_json`, and write it to the current store under its current-version hash
/// reference. Returns that current-version hash reference so the application can
/// track it and load the migrated key package back from the new store.
///
/// The two `StorageProvider` traits (previous and current version) are brought
/// into scope in separate blocks: the backing `PostcardProvider` implements both,
/// so keeping only one in scope per call avoids an ambiguous method resolution.
fn migrate_key_package<NewProvider: openmls_traits::OpenMlsProvider>(
    old_storage: &PostcardProvider<'_>,
    old_hash_ref: &openmls_compat::prelude::KeyPackageRef,
    new_provider: &NewProvider,
) -> openmls_current::prelude::KeyPackageRef {
    // 1. Read the stored bundle (public key package + private init and encryption
    //    keys) with the previous version's storage API.
    let old_bundle: KeyPackageBundle = {
        use openmls_traits_compat::storage::StorageProvider as _;
        old_storage
            .key_package(old_hash_ref)
            .expect("read the old key package")
            .expect("no key package stored under this hash ref")
    };

    // 2. Bridge it through `serde_json` into the current version's type.
    let bundle: openmls_current::prelude::KeyPackageBundle =
        serde_json_bridge(&old_bundle).expect("bridge key package into the current version");

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

    new_hash_ref
}
// ANCHOR_END: migrate_key_package

/// Migrating a published key package with [`migrate_key_package`], then proving it
/// is usable: a fresh current-version group adds the migrated key package and its
/// owner joins from the welcome using the migrated bundle.
#[test]
fn test_migration_key_package() {
    const CIPHERSUITE: Ciphersuite =
        openmls_compat::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let current_ciphersuite =
        openmls_current::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    // Bob publishes a key package into the previous version's store.
    let bob_old_state = StorageProviderState::default();
    let bob_old_storage = bob_old_state.as_postcard_provider();
    let bob_old_provider = bob_old_storage.as_openmls_provider();
    let (bob_credential, bob_signer) = generate_credential(b"Bob", CIPHERSUITE, &bob_old_provider);
    let bob_key_package =
        generate_key_package(CIPHERSUITE, bob_credential, &bob_old_provider, &bob_signer);

    // The application tracks the key package's hash reference (OpenMLS keys stored
    // key packages by it), so it can address the stored bundle for migration.
    let old_crypto = openmls_libcrux_crypto_compat::CryptoProvider::new().unwrap();
    let old_hash_ref = bob_key_package
        .key_package()
        .hash_ref(&old_crypto)
        .expect("computing the old key package hash ref");

    // Migrate the published key package into a current-version store, then load the
    // migrated bundle back from that store by the returned hash reference.
    let bob_new_state = StorageProviderState::default();
    let bob_new_storage = bob_new_state.as_serde_json_provider();
    let bob_new_provider = bob_new_storage.as_openmls_provider();
    let new_hash_ref = migrate_key_package(&bob_old_storage, &old_hash_ref, &bob_new_provider);
    let current_bundle: openmls_current::prelude::KeyPackageBundle = {
        use openmls_traits::storage::StorageProvider as _;
        bob_new_storage
            .key_package(&new_hash_ref)
            .expect("read the migrated key package")
            .expect("no migrated key package stored under this hash ref")
    };

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

    // Bob joins from the welcome. Staging the welcome looks up his key package in
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

/// Check migration of the application export tree
#[cfg(feature = "extensions-draft")]
#[test]
fn test_migration_application_export_tree() {
    let group_id = TestGroupId::new(b"migration app export tree group");
    let consumed_component_id: u16 = 0x8000;

    // Create a group with the previous version and consume `consumed_component_id`
    // via `safe_export_secret`
    let alice_state = StorageProviderState::default();
    {
        let alice_storage = alice_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", CIPHERSUITE, &alice_provider);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .build();
        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.compat(),
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
        migrate_group(&old_provider, &new_provider, &group_id.compat());
    }

    // Load the migrated group with the current API and check the tree.
    let new_group_id = group_id.current();
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

/// Tests enabling `extensions-draft` during migration
#[cfg(all(
    feature = "extensions-draft-current",
    not(feature = "extensions-draft-compat")
))]
#[test]
fn test_migration_enabling_extensions_draft() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration enable ext-draft group");

    // Source group without the `extensions-draft` feature enabled.
    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    let alice_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (_alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );
        alice_signer
    };

    // Migrate into a current-version store that has `extensions-draft` enabled
    let new_state = StorageProviderState::default();
    let new_provider = new_state.as_serde_json_provider();
    {
        let old_provider = alice_state.as_postcard_provider();
        migrate_group(&old_provider, &new_provider, &group_id.compat());
    }
    let signer = migrate_signature_key_pair(&alice_signer_old, &new_provider);

    // Load the migrated group with the current API.
    let current_provider = new_provider.as_openmls_provider();
    let new_group_id = group_id.current();
    let mut alice = openmls_current::prelude::MlsGroup::load(&new_provider, &new_group_id)
        .expect("loading the migrated group")
        .expect("no migrated group state persisted");
    assert_eq!(alice.members().count(), 2);

    // NOTE: `safe_export_secret()` fails immediately after mgration
    alice
        .safe_export_secret(&crypto, &new_provider, 0x8000)
        .expect_err("exporting a component secret after enabling extensions-draft");

    // create and merge a commit
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

    // `safe_export_secret()` succeeds
    alice
        .safe_export_secret(&crypto, &new_provider, 0x8000)
        .expect("exporting a component secret after enabling extensions-draft");
}

/// Test migration when creating a commit loads a pre-shared key from storage
fn test_migration_with_psk_proposal_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration psk proposal group");

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();
    let alice_signer_old = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();
        let (mut alice_group, alice_signer, _bob_signer) = setup_alice_bob_group(
            ciphersuite,
            &group_id.compat(),
            &alice_provider,
            &bob_provider,
        );

        // The application stores an external PSK in the old store.
        let psk_id = openmls_compat::schedule::PreSharedKeyId::external(
            b"migration-test-psk".to_vec(),
            vec![0u8; 32],
        );
        psk_id
            .store(&alice_provider, &[7u8; 32])
            .expect("storing the external PSK secret");
        alice_group
            .propose_external_psk(&alice_provider, &alice_signer, psk_id)
            .expect("queuing the PreSharedKey proposal");

        // The scenario under test: a queued PreSharedKey proposal, no pending commit.
        assert_eq!(alice_group.pending_proposals().count(), 1);
        assert!(alice_group.pending_commit().is_none());
        alice_signer
    };

    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let mut migrated = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
    assert_eq!(
        migrated.pending_proposals().count(),
        1,
        "the queued PreSharedKey proposal did not survive migration"
    );
    assert!(migrated.pending_commit().is_none());

    let signer: openmls_basic_credential_current::SignatureKeyPair =
        serde_json_bridge(&alice_signer_old)
            .expect("bridging Alice's signer to the current version");
    let provider = T::openmls_provider(&target);
    let error = migrated
        .commit_to_pending_proposals(&provider, &signer)
        .expect("PSK not found");
}

/// Check decryption of a past epoch message after migration
fn test_migration_then_decrypt_past_epoch_message_impl<T: StorageMigrationTarget>() {
    let ciphersuite = CIPHERSUITE;
    let group_id = TestGroupId::new(b"migration decrypt past-epoch message");
    const PLAINTEXT: &[u8] = b"a message from a past epoch";

    let alice_state = StorageProviderState::default();
    let bob_state = StorageProviderState::default();

    let message_wire = {
        let alice_storage = alice_state.as_postcard_provider();
        let bob_storage = bob_state.as_postcard_provider();
        let alice_provider = alice_storage.as_openmls_provider();
        let bob_provider = bob_storage.as_openmls_provider();

        let (alice_credential, alice_signer) =
            generate_credential(b"Alice", ciphersuite, &alice_provider);
        let (bob_credential, bob_signer) = generate_credential(b"Bob", ciphersuite, &bob_provider);
        let bob_key_package =
            generate_key_package(ciphersuite, bob_credential, &bob_provider, &bob_signer);

        // Alice configures the group to keep one past epoch
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .max_past_epochs(1)
            .build();
        let mut alice_group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_signer,
            &config,
            group_id.compat(),
            alice_credential,
        )
        .expect("creating the group");
        let (_commit, welcome, _group_info) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_key_package.key_package().clone()],
            )
            .expect("adding Bob");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merging the add commit");

        // Bob joins from the welcome.
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .expect("serializing the welcome");
        let welcome =
            openmls_compat::prelude::MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
                .expect("deserializing the welcome");
        let openmls_compat::prelude::MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("expected the message to be a welcome")
        };
        let mut bob_group = StagedWelcome::new_from_welcome(
            &bob_provider,
            config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("creating Bob's staged welcome")
        .into_group(&bob_provider)
        .expect("Bob joining the group");

        // Bob sends an application message at the current epoch (1).
        let message = bob_group
            .create_message(&bob_provider, &bob_signer, PLAINTEXT)
            .expect("Bob creating an application message")
            .tls_serialize_detached()
            .expect("serializing the application message");

        // Alice advances one epoch (self-update)
        alice_group
            .self_update(
                &alice_provider,
                &alice_signer,
                LeafNodeParameters::default(),
            )
            .expect("Alice self-updating");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merging the self-update");
        assert_eq!(alice_group.epoch().as_u64(), 2);

        message
    };

    // Migrate Alice into the target store, then decrypt Bob's past-epoch message
    // against her migrated (retained) `message_secrets`.
    let target_state = StorageProviderState::default();
    let target = T::provider(&target_state);
    let mut alice = migrate_and_check(&alice_state, &group_id, &target, T::NAME);
    assert_eq!(alice.epoch().as_u64(), 2);

    let provider = T::openmls_provider(&target);
    let message_in =
        openmls_current::prelude::MlsMessageIn::tls_deserialize(&mut message_wire.as_slice())
            .expect("deserializing the application message");
    let protocol_message = message_in
        .try_into_protocol_message()
        .expect("application message is a protocol message");
    let processed = alice
        .process_message(&provider, protocol_message)
        .expect("processing Bob's past-epoch application message on the migrated group");
    match processed.into_content() {
        openmls_current::prelude::ProcessedMessageContent::ApplicationMessage(
            application_message,
        ) => {
            assert_eq!(application_message.into_bytes(), PLAINTEXT,);
        }
        _ => panic!("expected an application message"),
    }
}

#[test]
fn test_migration_large_group_serde_json() {
    test_migration_large_group_impl::<SerdeJson>();
}

#[test]
fn test_migration_large_group_ciborium() {
    test_migration_large_group_impl::<Ciborium>();
}

#[test]
fn test_migration_with_pending_commit_serde_json() {
    test_migration_with_pending_commit_impl::<SerdeJson>();
}

#[test]
fn test_migration_with_pending_commit_ciborium() {
    test_migration_with_pending_commit_impl::<Ciborium>();
}

#[test]
fn test_migration_multiple_epochs_serde_json() {
    test_migration_multiple_epochs_impl::<SerdeJson>();
}

#[test]
fn test_migration_multiple_epochs_ciborium() {
    test_migration_multiple_epochs_impl::<Ciborium>();
}

#[test]
fn test_migration_with_proposals_serde_json() {
    test_migration_with_proposals_impl::<SerdeJson>();
}

#[test]
fn test_migration_with_proposals_ciborium() {
    test_migration_with_proposals_impl::<Ciborium>();
}

#[test]
#[ignore]
fn test_migration_with_psk_proposal_serde_json() {
    test_migration_with_psk_proposal_impl::<SerdeJson>();
}

#[test]
#[ignore]
fn test_migration_with_psk_proposal_ciborium() {
    test_migration_with_psk_proposal_impl::<Ciborium>();
}

#[cfg(all(feature = "compat_0_8_1", feature = "extensions-draft"))]
#[test]
fn test_migration_pending_app_ephemeral_commit_serde_json() {
    test_migration_pending_app_ephemeral_commit_impl::<SerdeJson>();
}

#[cfg(all(feature = "compat_0_8_1", feature = "extensions-draft"))]
#[test]
fn test_migration_pending_app_ephemeral_commit_ciborium() {
    test_migration_pending_app_ephemeral_commit_impl::<Ciborium>();
}

#[test]
fn test_migration_then_decrypt_application_message_serde_json() {
    test_migration_then_decrypt_application_message_impl::<SerdeJson>();
}

#[test]
fn test_migration_then_decrypt_application_message_ciborium() {
    test_migration_then_decrypt_application_message_impl::<Ciborium>();
}

#[test]
fn test_migration_then_decrypt_past_epoch_message_serde_json() {
    test_migration_then_decrypt_past_epoch_message_impl::<SerdeJson>();
}

#[test]
fn test_migration_then_decrypt_past_epoch_message_ciborium() {
    test_migration_then_decrypt_past_epoch_message_impl::<Ciborium>();
}
