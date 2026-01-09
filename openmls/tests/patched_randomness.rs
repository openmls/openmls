//! This integration module tests whether OpenMLS correctly uses
//! randomness provided by a custom randomness source implementing
//! the `OpenMlsRand` trait.

use std::time::{SystemTime, UNIX_EPOCH};

use openmls::{
    group::{GroupId, MlsGroup},
    prelude::{
        test_utils::new_credential, Ciphersuite, KeyPackageBuilder, LeafNodeParameters, Lifetime,
        OpenMlsRand,
    },
};
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;

#[derive(Clone)]
struct PatchedRandomness {
    next_encryption_key_seed: u8,
    next_path_secret: u8,
}

impl Default for PatchedRandomness {
    fn default() -> Self {
        Self {
            next_encryption_key_seed: 42,
            next_path_secret: 24,
        }
    }
}

impl PatchedRandomness {
    fn change_next_encryption_key_seed(&mut self) {
        self.next_encryption_key_seed += 1;
    }
    fn change_next_path_secret(&mut self) {
        self.next_path_secret += 1;
    }
}

impl OpenMlsRand for PatchedRandomness {
    type Error = std::convert::Infallible;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        Ok([0u8; N])
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0u8; len])
    }

    fn reuse_guard<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        Ok([1u8; N])
    }

    fn init_secret(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![2u8; len])
    }

    fn init_key_seed(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![3u8; len])
    }

    fn path_secret(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![self.next_path_secret; len])
    }

    fn encryption_key_seed(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![self.next_encryption_key_seed; len])
    }
}

#[derive(Default, Clone)]
struct PatchedOpenMlsProvider {
    storage: MemoryStorage,
    crypto: RustCrypto,
    rand: PatchedRandomness,
}

impl OpenMlsProvider for PatchedOpenMlsProvider {
    type CryptoProvider = RustCrypto;

    type RandProvider = PatchedRandomness;

    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

#[test]
fn patched_randomness() {
    let mut alice_provider = PatchedOpenMlsProvider::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    let (alice_credential_with_key, alice_signature_keys) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential_with_key, bob_signature_keys) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Alice creates a KeyPackageBundle with the patched randomness
    let alice_key_package_bundle = KeyPackageBuilder::new()
        .build(
            ciphersuite,
            &alice_provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .unwrap();
    // If we create the KeyPackageBundle again, the keys should be the same
    let alice_key_package_bundle_2 = KeyPackageBuilder::new()
        .build(
            ciphersuite,
            &alice_provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .unwrap();
    assert_eq!(
        alice_key_package_bundle.init_private_key(),
        alice_key_package_bundle_2.init_private_key()
    );
    assert_eq!(
        alice_key_package_bundle.key_package().hpke_init_key(),
        alice_key_package_bundle_2.key_package().hpke_init_key()
    );
    assert_eq!(
        alice_key_package_bundle.encryption_private_key(),
        alice_key_package_bundle_2.encryption_private_key()
    );
    assert_eq!(
        alice_key_package_bundle
            .key_package()
            .leaf_node()
            .encryption_key(),
        alice_key_package_bundle_2
            .key_package()
            .leaf_node()
            .encryption_key()
    );

    // Bob creates a KeyPackageBundle with normal randomness
    let bob_key_package_bundle = KeyPackageBuilder::new()
        .build(
            ciphersuite,
            &bob_provider,
            &bob_signature_keys,
            bob_credential_with_key.clone(),
        )
        .unwrap();

    // Alice creates a new group
    let group_id = GroupId::from_slice(&[0u8; 16]);
    let not_before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let not_after = not_before + 60 * 60 * 24; // 1 day validity
    let mut alice_group = MlsGroup::builder()
        .lifetime(Lifetime::init(not_before, not_after))
        .with_group_id(group_id.clone())
        .ciphersuite(ciphersuite)
        .build(
            &alice_provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .unwrap();

    let alice_encryption_key = alice_group.own_leaf().unwrap().encryption_key();
    // If we create the group again, the encryption key should be the same
    let alice_group_2 = MlsGroup::builder()
        .lifetime(Lifetime::init(not_before, not_after))
        .with_group_id(group_id.clone())
        .ciphersuite(ciphersuite)
        .build(
            &alice_provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .unwrap();
    let alice_encryption_key_2 = alice_group_2.own_leaf().unwrap().encryption_key();
    assert_eq!(alice_encryption_key, alice_encryption_key_2);

    // In fact the whole group state should be the same
    assert_eq!(
        alice_group.epoch_authenticator(),
        alice_group_2.epoch_authenticator()
    );

    // Change the randomness for Alice's next operations. This prevents some
    // internal sanity checks from failing.
    alice_provider.rand.change_next_encryption_key_seed();
    alice_provider.rand.change_next_path_secret();

    // Alice adds Bob
    let (_commit, _welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signature_keys,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .unwrap();
    // Alice merges her own commit
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // Change the randomness for Alice's next operations. This prevents some
    // internal sanity checks from failing.
    alice_provider.rand.change_next_encryption_key_seed();
    alice_provider.rand.change_next_path_secret();

    // Let's clone the group so we can apply an update twice
    let mut alice_group_clone = alice_group.clone();
    let alice_provider_clone = alice_provider.clone();

    // Alice creates an update and merges it
    alice_group
        .self_update(
            &alice_provider,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // Alice creates an update on the cloned group and merges it
    alice_group_clone
        .self_update(
            &alice_provider_clone,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .unwrap();
    alice_group_clone
        .merge_pending_commit(&alice_provider_clone)
        .unwrap();

    // Leaf encryption keys should be the same
    let alice_encryption_key_after_update = alice_group.own_leaf().unwrap().encryption_key();
    let alice_encryption_key_after_update_2 =
        alice_group_clone.own_leaf().unwrap().encryption_key();
    assert_eq!(
        alice_encryption_key_after_update,
        alice_encryption_key_after_update_2
    );
    // The whole ratchet tree should be the same
    assert_eq!(
        alice_group.export_ratchet_tree(),
        alice_group_clone.export_ratchet_tree()
    );
}
