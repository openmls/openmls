//! This modules contains KATs for testing the stability of storage.
//!
//! The KAT generation performs a few group operations (e.g. create, add, set required capabilties)
//! and at each step saves a serialized copy of the provider, along with the group id of the
//! created group.
//!
//! The KAT test reads the serialized providers, loads the [`MlsGroup`] for the given group id, and
//! checks that the group contains the expected information.
//!
//! It contains
//! - a helper function that does the generation of the KAT for a single pair of provider and
//!   ciphersuite
//! - a test that runs the KAT generation
//! - a test that runs the KAT generation for all supported providers and ciphersuites and writes
//!   the vectors to disk. This test is annotated with #[ignore] and not usually run.
//! - a test that
//!   - loads the test data for the given provider and ciphersuite,
//!   - deserializes the provider and group id
//!   - loads the [`MlsGroup`]
//!   - checks that the group matches expectations

use base64::Engine;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::io::Write;

use openmls_test::openmls_test;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, CryptoError, ExporterSecret, HpkeCiphertext, HpkeConfig, HpkeKeyPair, KemOutput,
    },
    OpenMlsProvider as _,
};
use tls_codec::SecretVLBytes;

use crate::{
    prelude::{test_utils::new_credential, *},
    storage::OpenMlsProvider,
};

#[derive(Serialize, Deserialize)]
struct KatData {
    group_id: GroupId,
    storages: Vec<String>,
}

/// A crypto provider that delegates everything to `inner`, except for
/// randomness, which is generated deterministically.
struct DeterministicCrypto<Provider: OpenMlsProvider> {
    id: String,
    ctr: std::sync::atomic::AtomicUsize,
    inner: std::sync::Mutex<Provider>,
}

impl<Provider: OpenMlsProvider + Default> DeterministicCrypto<Provider> {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            ctr: std::sync::atomic::AtomicUsize::new(0),
            inner: std::sync::Mutex::new(Provider::default()),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Provider> {
        self.inner.lock().unwrap()
    }

    fn encode(ctr: usize, id: &str) -> Vec<u8> {
        ctr.to_be_bytes().into_iter().chain(id.bytes()).collect()
    }

    fn block(&self, mut dst: &mut [u8]) -> usize {
        let ctr = self.ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let block = self
            .inner()
            .crypto()
            .hash(HashType::Sha2_256, &Self::encode(ctr, &self.id))
            .unwrap();

        let write = usize::min(dst.len(), block.len());
        dst.write_all(&block[..write]).unwrap();
        write
    }

    fn fill(&self, mut dst: &mut [u8]) {
        while !dst.is_empty() {
            let written = self.block(dst);
            dst = &mut dst[written..];
        }
    }
}

impl<Provider: OpenMlsProvider + Default + Send> OpenMlsCrypto for DeterministicCrypto<Provider> {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.inner().crypto().supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.inner().crypto().supported_ciphersuites()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner().crypto().hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner().crypto().hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner()
            .crypto()
            .hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner().crypto().hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner()
            .crypto()
            .aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner()
            .crypto()
            .aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner().crypto().signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner()
            .crypto()
            .verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner().crypto().sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner()
            .crypto()
            .hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner()
            .crypto()
            .hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.inner().crypto().hpke_setup_sender_and_export(
            config,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner().crypto().hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.inner().crypto().derive_hpke_keypair(config, ikm)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_open_psk(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner()
            .crypto()
            .hpke_open_psk(config, input, sk_r, info, aad, psk, psk_id)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_seal_psk(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner()
            .crypto()
            .hpke_seal_psk(config, pk_r, info, aad, ptxt, psk, psk_id)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_encrypt(&self, key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
        self.inner().crypto().ff1_aes128_encrypt(key, plaintext)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_decrypt(&self, key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
        self.inner().crypto().ff1_aes128_decrypt(key, ciphertext)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N], CryptoError> {
        let mut arr = [0u8; N];
        self.fill(&mut arr);
        Ok(arr)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut arr = vec![0u8; len];
        self.fill(&mut arr);
        Ok(arr)
    }
}

struct StorageTestProvider<Provider: OpenMlsProvider> {
    crypto: DeterministicCrypto<Provider>,
    storage: openmls_memory_storage::MemoryStorage,
}

impl<Provider: OpenMlsProvider + Default> StorageTestProvider<Provider> {
    fn new(id: &str) -> Self {
        Self {
            crypto: DeterministicCrypto::new(id),
            storage: Default::default(),
        }
    }
}

impl<Provider: OpenMlsProvider + Default + Send> openmls_traits::OpenMlsProvider
    for StorageTestProvider<Provider>
{
    type CryptoProvider = DeterministicCrypto<Provider>;

    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
}

fn deserialize_provider<R: std::io::Read, Provider: OpenMlsProvider + Default>(
    r: &mut R,
    name: &str,
) -> StorageTestProvider<Provider> {
    StorageTestProvider::<Provider> {
        storage: openmls_memory_storage::MemoryStorage::deserialize(r).unwrap(),
        crypto: DeterministicCrypto::new(name),
    }
}

fn check_serialized_group_equality<R: std::io::Read, Provider: OpenMlsProvider + Default + Send>(
    r: &mut R,
    name: &str,
    group_id: &GroupId,
    group: &MlsGroup,
) {
    let provider = deserialize_provider::<_, Provider>(r, name);
    let loaded_group = MlsGroup::load(provider.storage(), group_id)
        .unwrap()
        .unwrap();

    assert_eq!(group, &loaded_group);
}

fn helper_generate_kat<Provider: OpenMlsProvider + Default + Send>(
    ciphersuite: Ciphersuite,
) -> (GroupId, Vec<Vec<u8>>) {
    let alice_provider = StorageTestProvider::<Provider>::new("alice");
    let (alice_cwk, alice_signer) =
        new_credential(&alice_provider, b"alice", ciphersuite.signature_algorithm());

    let bob_provider = StorageTestProvider::<Provider>::new("bob");
    let (bob_cwk, bob_signer) =
        new_credential(&bob_provider, b"bob", ciphersuite.signature_algorithm());

    let charlie_provider = StorageTestProvider::<Provider>::new("charlie");
    let (charlie_cwk, charlie_signer) = new_credential(
        &charlie_provider,
        b"charlie",
        ciphersuite.signature_algorithm(),
    );

    /////// prepare a group that has some content
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[ExtensionType::Unknown(0xf042)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .build(&alice_provider, &alice_signer, alice_cwk)
        .expect("error creating group using builder");

    let group_id = alice_group.group_id().clone();

    let mut testdata_new_group = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_new_group)
        .unwrap();

    check_serialized_group_equality::<_, Provider>(
        &mut testdata_new_group.as_slice(),
        "alice",
        &group_id,
        &alice_group,
    );

    let bob_kpb = KeyPackageBuilder::new()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[ExtensionType::Unknown(0xf042)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .build(ciphersuite, &bob_provider, &bob_signer, bob_cwk.clone())
        .unwrap();

    alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_kpb.key_package().to_owned()],
        )
        .unwrap();

    let mut testdata_pending_add_commit = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_pending_add_commit)
        .unwrap();

    check_serialized_group_equality::<_, Provider>(
        &mut testdata_pending_add_commit.as_slice(),
        "alice",
        &group_id,
        &alice_group,
    );

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut testdata_bob_added = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_bob_added)
        .unwrap();

    alice_group
        .update_group_context_extensions(
            &alice_provider,
            Extensions::single(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf042)], &[], &[]),
            ))
            .unwrap(),
            &alice_signer,
        )
        .unwrap();

    let mut testdata_pending_gce_commit = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_pending_gce_commit)
        .unwrap();

    check_serialized_group_equality::<_, Provider>(
        &mut testdata_pending_gce_commit.as_slice(),
        "alice",
        &group_id,
        &alice_group,
    );

    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let mut testdata_gce_updated = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_gce_updated)
        .unwrap();

    check_serialized_group_equality::<_, Provider>(
        &mut testdata_gce_updated.as_slice(),
        "alice",
        &group_id,
        &alice_group,
    );

    //// also serialize with a pending proposal

    let charlie_kpb = KeyPackageBuilder::new()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[ExtensionType::Unknown(0xf042)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .build(
            ciphersuite,
            &charlie_provider,
            &charlie_signer,
            charlie_cwk.clone(),
        )
        .unwrap();

    alice_group
        .propose_add_member(&alice_provider, &alice_signer, charlie_kpb.key_package())
        .unwrap();

    let mut testdata_pending_proposal = vec![];
    alice_provider
        .storage
        .serialize(&mut testdata_pending_proposal)
        .unwrap();

    check_serialized_group_equality::<_, Provider>(
        &mut testdata_pending_proposal.as_slice(),
        "alice",
        &group_id,
        &alice_group,
    );

    (
        group_id,
        vec![
            testdata_new_group,
            testdata_pending_add_commit,
            testdata_bob_added,
            testdata_pending_gce_commit,
            testdata_gce_updated,
            testdata_pending_proposal,
        ],
    )
}

#[openmls_test]
fn generate_kats() {
    helper_generate_kat::<Provider>(ciphersuite);
}

#[cfg(all(
    feature = "generate-kats",
    not(all(
        feature = "libcrux-provider",
        not(any(
            target_arch = "wasm32",
            all(target_arch = "x86", target_os = "windows")
        ))
    ))
))]
#[test]
fn write_kats() {
    // setup
    let rustcrypto_provider = openmls_rust_crypto::OpenMlsRustCrypto::default();

    // make a list of all supported ciphersuites
    let ciphersuites = rustcrypto_provider.crypto().supported_ciphersuites();

    // generate the kat data
    let kat_data = ciphersuites
        .into_iter()
        .map(|ciphersuite| {
            let (group_id, storages) =
                helper_generate_kat::<openmls_rust_crypto::OpenMlsRustCrypto>(ciphersuite);

            (ciphersuite, group_id, storages)
        })
        .collect();

    // encode and write to disk
    helper_write_kats(kat_data);
}

#[cfg(all(
    feature = "generate-kats",
    feature = "libcrux-provider",
    not(any(
        target_arch = "wasm32",
        all(target_arch = "x86", target_os = "windows")
    ))
))]
#[test]
fn write_kats() {
    // setup
    let libcrux_provider = openmls_libcrux_crypto::Provider::default();
    let rustcrypto_provider = openmls_rust_crypto::OpenMlsRustCrypto::default();

    // make a list of all supported ciphersuites
    let mut ciphersuites = libcrux_provider.crypto().supported_ciphersuites();
    for ciphersuite in rustcrypto_provider.crypto().supported_ciphersuites() {
        if !ciphersuites.contains(&ciphersuite) {
            ciphersuites.push(ciphersuite);
        }
    }

    // generate the kat data
    let kat_data = ciphersuites
        .into_iter()
        .map(|ciphersuite| {
            let (group_id, storages) = if libcrux_provider.crypto().supports(ciphersuite).is_ok() {
                helper_generate_kat::<openmls_libcrux_crypto::Provider>(ciphersuite)
            } else {
                helper_generate_kat::<openmls_rust_crypto::OpenMlsRustCrypto>(ciphersuite)
            };

            (ciphersuite, group_id, storages)
        })
        .collect();

    // encode and write to disk
    helper_write_kats(kat_data);
}

#[cfg(feature = "generate-kats")]
fn helper_write_kats(kat_data: Vec<(Ciphersuite, GroupId, Vec<Vec<u8>>)>) {
    let base64_engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new(),
    );

    // test data, keyed by ciphersuite
    let mut data = HashMap::new();

    for (ciphersuite, group_id, storages_bytes) in kat_data {
        let storages: Vec<String> = storages_bytes
            .iter()
            .map(|test| base64_engine.encode(test))
            .collect();

        data.insert(ciphersuite, KatData { group_id, storages });
    }
    // write to file
    let mut file = std::fs::File::create("test_vectors/storage-stability-new.json").unwrap();
    serde_json::to_writer(&mut file, &data).unwrap();
}

#[openmls_test]
fn test() {
    // setup
    let base64_engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new(),
    );

    // load data — skip unknown ciphersuite keys (e.g. PQ suites when that feature is off)
    let mut data: HashMap<Ciphersuite, KatData> = {
        let file = std::fs::File::open("test_vectors/storage-stability.json").unwrap();
        let raw: HashMap<String, KatData> = serde_json::from_reader(file).unwrap();
        raw.into_iter()
            .filter_map(|(k, v)| {
                serde_json::from_value::<Ciphersuite>(serde_json::Value::String(k))
                    .ok()
                    .map(|cs| (cs, v))
            })
            .collect()
    };

    let KatData { group_id, storages } = data.remove(&ciphersuite).unwrap();

    // parse base64-encoded serialized storage
    let mut storages = storages
        .iter()
        .map(|storage| base64_engine.decode(storage).unwrap());

    //// load group from state right after creation

    let provider_new_group =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_new_group = MlsGroup::load(provider_new_group.storage(), &group_id)
        .unwrap()
        .unwrap();

    // alice is the sole member
    let members = alice_group_new_group.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );

    // there are no pending proposals or commits
    assert!(alice_group_new_group.pending_proposals().next().is_none());
    assert!(alice_group_new_group.pending_commit().is_none());

    // we are in the right epoch
    assert_eq!(alice_group_new_group.epoch(), 0.into());
    assert_eq!(alice_group_new_group.resumption_psk_store().cursor(), 1);

    // dropping to prevent accidentally using the wrong provider or group later
    drop(alice_group_new_group);
    drop(provider_new_group);

    //// load group from state after bob was added, but commit not yet merged

    let provider_pending_add_commit =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_pending_add_commit =
        MlsGroup::load(provider_pending_add_commit.storage(), &group_id)
            .unwrap()
            .unwrap();

    // alice is the sole member
    let members = alice_group_pending_add_commit.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );

    // there is one pending add commit
    match alice_group_pending_add_commit.pending_commit() {
        Some(staged_commit) => {
            assert_eq!(staged_commit.queued_proposals().count(), 1);
            assert_eq!(staged_commit.add_proposals().count(), 1);
            let add_proposal = staged_commit.add_proposals().next().unwrap();
            assert_eq!(
                add_proposal
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
                &BasicCredential::new(b"bob".to_vec()).into()
            );
        }
        None => panic!("expected a pending commit"),
    };

    // there are no pending proposals
    assert_eq!(
        alice_group_pending_add_commit.pending_proposals().count(),
        0
    );

    // we are in the right epoch
    assert_eq!(alice_group_pending_add_commit.epoch(), 0.into());
    assert_eq!(
        alice_group_pending_add_commit
            .resumption_psk_store()
            .cursor(),
        1
    );

    // dropping to prevent accidentally using the wrong provider or group later
    drop(alice_group_pending_add_commit);
    drop(provider_pending_add_commit);

    //// load group from state after bob was added

    let provider_bob_added =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_bob_added = MlsGroup::load(provider_bob_added.storage(), &group_id)
        .unwrap()
        .unwrap();

    // alice and bob are members
    let members = alice_group_bob_added.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(members[1].index, LeafNodeIndex::new(1));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );
    assert_eq!(
        members[1].credential,
        BasicCredential::new(b"bob".to_vec()).into()
    );

    // there are no pending proposals or commits
    assert!(alice_group_bob_added.pending_proposals().next().is_none());
    assert!(alice_group_bob_added.pending_commit().is_none());

    // we are in the right epoch
    assert_eq!(alice_group_bob_added.epoch(), 1.into());
    assert_eq!(alice_group_bob_added.resumption_psk_store().cursor(), 2);

    // dropping to prevent accidentally using the wrong provider or group later
    drop(alice_group_bob_added);
    drop(provider_bob_added);

    //// load group from state after alice updated GCE, but commit is not yet merged

    let provider_pending_gce_commit =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_pending_gce_commit =
        MlsGroup::load(provider_pending_gce_commit.storage(), &group_id)
            .unwrap()
            .unwrap();

    // alice and bob are members
    let members = alice_group_pending_gce_commit.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(members[1].index, LeafNodeIndex::new(1));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );
    assert_eq!(
        members[1].credential,
        BasicCredential::new(b"bob".to_vec()).into()
    );

    // there are no pending proposals
    assert!(alice_group_pending_gce_commit
        .pending_proposals()
        .next()
        .is_none());

    // there is one pending gce commit
    match alice_group_pending_gce_commit.pending_commit() {
        Some(staged_commit) => {
            let proposals: Vec<_> = staged_commit.queued_proposals().collect();
            assert_eq!(proposals.len(), 1);

            let Proposal::GroupContextExtensions(gce_proposal) = &proposals[0].proposal() else {
                panic!(
                    "expected a group context extension proposal, got {:?}",
                    proposals[0]
                )
            };

            assert_eq!(
                gce_proposal.extensions(),
                &Extensions::<GroupContext>::single(Extension::RequiredCapabilities(
                    RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf042)], &[], &[])
                ))
                .unwrap()
            );
        }
        None => panic!("expected a pending commit"),
    };

    // we are in the right epoch
    assert_eq!(alice_group_pending_gce_commit.epoch(), 1.into());
    assert_eq!(
        alice_group_pending_gce_commit
            .resumption_psk_store()
            .cursor(),
        2
    );

    // dropping to prevent accidentally using the wrong provider or group later
    drop(alice_group_pending_gce_commit);
    drop(provider_pending_gce_commit);

    //// load group from state after alice updated GCE

    let provider_gce_updated =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_gce_updated = MlsGroup::load(provider_gce_updated.storage(), &group_id)
        .unwrap()
        .unwrap();

    // alice and bob are members
    let members = alice_group_gce_updated.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(members[1].index, LeafNodeIndex::new(1));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );
    assert_eq!(
        members[1].credential,
        BasicCredential::new(b"bob".to_vec()).into()
    );

    // there are no pending proposals or commits
    assert!(alice_group_gce_updated.pending_proposals().next().is_none());
    assert!(alice_group_gce_updated.pending_commit().is_none());

    drop(alice_group_gce_updated);
    drop(provider_gce_updated);

    //// load group from state after alice creates another proposal

    let provider_pending_proposal =
        deserialize_provider::<_, Provider>(&mut storages.next().unwrap().as_slice(), "alice");

    let alice_group_pending_proposal =
        MlsGroup::load(provider_pending_proposal.storage(), &group_id)
            .unwrap()
            .unwrap();

    // alice and bob are members
    let members = alice_group_pending_proposal.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].index, LeafNodeIndex::new(0));
    assert_eq!(members[1].index, LeafNodeIndex::new(1));
    assert_eq!(
        members[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );
    assert_eq!(
        members[1].credential,
        BasicCredential::new(b"bob".to_vec()).into()
    );

    // there is one pending add proposal
    let proposals: Vec<_> = alice_group_pending_proposal.pending_proposals().collect();
    assert_eq!(proposals.len(), 1);
    match &proposals[0].proposal() {
        Proposal::Add(add_proposal) => {
            assert_eq!(
                add_proposal.key_package().leaf_node().credential(),
                &BasicCredential::new(b"charlie".to_vec()).into()
            )
        }
        other => panic!("expected add proposal, got {other:?}"),
    }

    // there is no pending commit
    assert!(alice_group_pending_proposal.pending_commit().is_none());
}
