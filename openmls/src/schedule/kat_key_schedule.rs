//! # Known Answer Tests for the key schedule
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.
//!
//! If values are not present, they are encoded as empty strings.

use crate::{ciphersuite::*, group::*, schedule::*, test_utils::*};

#[cfg(test)]
use crate::test_utils::{read, write};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    key_store::OpenMlsKeyStore, random::OpenMlsRand, types::HpkeKeyPair, OpenMlsCryptoProvider,
};
use rand::{rngs::OsRng, RngCore};
use serde::{self, Deserialize, Serialize};
use tls_codec::Serialize as TlsSerialize;

use super::{errors::KsTestVectorError, PskSecret};
use super::{CommitSecret, PreSharedKeyId};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct PskValue {
    psk_id: String, /* hex encoded PreSharedKeyID */
    psk: String,    /* hex-encoded binary data */
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Epoch {
    // Chosen by the generator
    tree_hash: String,
    commit_secret: String,
    // XXX: PSK is not supported in OpenMLS yet #751
    psks: Vec<PskValue>,
    confirmed_transcript_hash: String,

    // Computed values
    group_context: String,
    joiner_secret: String,
    welcome_secret: String,
    init_secret: String,
    sender_data_secret: String,
    encryption_secret: String,
    exporter_secret: String,
    authentication_secret: String,
    external_secret: String,
    confirmation_key: String,
    membership_key: String,
    resumption_secret: String,

    external_pub: String, // TLS serialized HpkePublicKey
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KeyScheduleTestVector {
    pub cipher_suite: u16,
    group_id: String,
    initial_init_secret: String,
    epochs: Vec<Epoch>,
}

// Ignore clippy warning since this just used for testing
#[allow(clippy::type_complexity)]
fn generate(
    ciphersuite: Ciphersuite,
    init_secret: &InitSecret,
    group_id: &[u8],
    epoch: u64,
) -> (
    Vec<u8>,
    CommitSecret,
    JoinerSecret,
    Vec<(PreSharedKeyId, Secret)>,
    WelcomeSecret,
    EpochSecrets,
    Vec<u8>,
    GroupContext,
    HpkeKeyPair,
) {
    let crypto = OpenMlsRustCrypto::default();
    let tree_hash = crypto
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");
    let commit_secret = CommitSecret::random(ciphersuite, &crypto);

    // Build the PSK secret.
    let mut psk_ids = Vec::new();
    let mut psks = Vec::new();
    let mut psks_out = Vec::new();
    for _ in 0..(OsRng.next_u32() % 0x10) {
        let psk_id =
        // XXX: Test all different PSK types.
        PreSharedKeyId::new(
            ciphersuite,
            crypto.rand(),
            Psk::Branch(BranchPsk {
                psk_group_id: GroupId::random(&crypto),
                psk_epoch: epoch.into(),
            }),
        ).expect("An unexpected error occurred.");
        let psk = PskSecret::random(ciphersuite, &crypto);
        psk_ids.push(psk_id.clone());
        psks.push(psk.secret().clone());
        psks_out.push((psk_id.clone(), psk.secret().clone()));
        let psk_bundle = PskBundle::new(psk.secret().clone()).expect("Could not create PskBundle.");
        crypto
            .key_store()
            .store(
                &psk_id
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
                &psk_bundle,
            )
            .expect("Could not store PskBundle in key store.");
    }
    let psk_secret =
        PskSecret::new(ciphersuite, &crypto, &psk_ids).expect("Could not create PskSecret.");

    let joiner_secret = JoinerSecret::new(&crypto, commit_secret.clone(), init_secret)
        .expect("Could not create JoinerSecret.");
    let mut key_schedule = KeySchedule::init(
        ciphersuite,
        &crypto,
        joiner_secret.clone(),
        Some(psk_secret.clone()),
    )
    .expect("Could not create KeySchedule.");
    let welcome_secret = key_schedule
        .welcome(&crypto)
        .expect("An unexpected error occurred.");

    let confirmed_transcript_hash = crypto
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");

    let group_context = GroupContext::new(
        GroupId::from_slice(group_id),
        epoch,
        tree_hash.to_vec(),
        confirmed_transcript_hash.clone(),
        &[], // Extensions
    );

    let serialized_group_context = group_context
        .tls_serialize_detached()
        .expect("Could not serialize group context.");

    key_schedule
        .add_context(&crypto, &serialized_group_context)
        .expect("An unexpected error occurred.");
    let epoch_secrets = key_schedule
        .epoch_secrets(&crypto)
        .expect("An unexpected error occurred.");

    // Calculate external HPKE key pair
    let external_key_pair = epoch_secrets
        .external_secret()
        .derive_external_keypair(crypto.crypto(), ciphersuite);

    (
        confirmed_transcript_hash,
        commit_secret,
        joiner_secret,
        psks_out,
        welcome_secret,
        epoch_secrets,
        tree_hash,
        group_context,
        external_key_pair,
    )
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(n_epochs: u64, ciphersuite: Ciphersuite) -> KeyScheduleTestVector {
    use tls_codec::Serialize;

    let crypto = OpenMlsRustCrypto::default();

    // Set up setting.
    let mut init_secret = InitSecret::random(ciphersuite, &crypto, ProtocolVersion::default())
        .expect("Not enough randomness.");
    let initial_init_secret = init_secret.clone();
    let group_id = crypto
        .rand()
        .random_vec(16)
        .expect("An unexpected error occurred.");

    let mut epochs = Vec::new();

    // Generate info for all epochs
    for epoch in 0..n_epochs {
        println!("Generating epoch: {:?}", epoch);
        let (
            confirmed_transcript_hash,
            commit_secret,
            joiner_secret,
            psks,
            welcome_secret,
            epoch_secrets,
            tree_hash,
            group_context,
            external_key_pair,
        ) = generate(ciphersuite, &init_secret, &group_id, epoch);

        let psks = psks
            .iter()
            .map(|(psk_id, psk)| PskValue {
                psk_id: bytes_to_hex(
                    &psk_id
                        .tls_serialize_detached()
                        .expect("An unexpected error occurred."),
                ),
                psk: bytes_to_hex(psk.as_slice()),
            })
            .collect::<Vec<_>>();

        let epoch_info = Epoch {
            tree_hash: bytes_to_hex(&tree_hash),
            commit_secret: bytes_to_hex(commit_secret.as_slice()),
            psks,
            confirmed_transcript_hash: bytes_to_hex(&confirmed_transcript_hash),
            group_context: bytes_to_hex(
                &group_context
                    .tls_serialize_detached()
                    .expect("An unexpected error occurred."),
            ),
            joiner_secret: bytes_to_hex(joiner_secret.as_slice()),
            welcome_secret: bytes_to_hex(welcome_secret.as_slice()),
            init_secret: bytes_to_hex(epoch_secrets.init_secret().as_slice()),
            sender_data_secret: bytes_to_hex(epoch_secrets.sender_data_secret().as_slice()),
            encryption_secret: bytes_to_hex(epoch_secrets.encryption_secret().as_slice()),
            exporter_secret: bytes_to_hex(epoch_secrets.exporter_secret().as_slice()),
            authentication_secret: bytes_to_hex(epoch_secrets.authentication_secret().as_slice()),
            external_secret: bytes_to_hex(epoch_secrets.external_secret().as_slice()),
            confirmation_key: bytes_to_hex(epoch_secrets.confirmation_key().as_slice()),
            membership_key: bytes_to_hex(epoch_secrets.membership_key().as_slice()),
            resumption_secret: bytes_to_hex(epoch_secrets.resumption_secret().as_slice()),
            external_pub: bytes_to_hex(
                &HpkePublicKey::from(external_key_pair.public)
                    .tls_serialize_detached()
                    .expect("An unexpected error occurred."),
            ),
        };
        epochs.push(epoch_info);
        init_secret = epoch_secrets.init_secret().clone();
    }

    KeyScheduleTestVector {
        cipher_suite: ciphersuite as u16,
        group_id: bytes_to_hex(&group_id),
        initial_init_secret: bytes_to_hex(initial_init_secret.as_slice()),
        epochs,
    }
}

#[test]
fn write_test_vectors() {
    const NUM_EPOCHS: u64 = 200;
    let mut tests = Vec::new();
    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        tests.push(generate_test_vector(NUM_EPOCHS, ciphersuite));
    }
    write("test_vectors/kat_key_schedule_openmls-new.json", &tests);
}

#[apply(backends)]
fn read_test_vectors_key_schedule(backend: &impl OpenMlsCryptoProvider) {
    let tests: Vec<KeyScheduleTestVector> = read("test_vectors/kat_key_schedule_openmls.json");
    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking key schedule test vector.\n{:?}", e),
        }
    }

    // FIXME: Interop #495
    // // mlspp test vectors
    // let tv_files = [
    //     "test_vectors/mlspp/mlspp_key_schedule_1.json",
    //     "test_vectors/mlspp/mlspp_key_schedule_2.json",
    //     "test_vectors/mlspp/mlspp_key_schedule_3.json",
    // ];
    // for &tv_file in tv_files.iter() {
    //     let tv: KeyScheduleTestVector = read(tv_file);
    //     run_test_vector(tv).expect("Error while checking key schedule test vector.");
    // }
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test_vector: KeyScheduleTestVector,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), KsTestVectorError> {
    use tls_codec::{Deserialize, Serialize};

    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    log::trace!("  {:?}", test_vector);

    let group_id = hex_to_bytes(&test_vector.group_id);
    let init_secret = hex_to_bytes(&test_vector.initial_init_secret);
    log::trace!(
        "  InitSecret from tve: {:?}",
        test_vector.initial_init_secret
    );
    let mut init_secret = InitSecret::from(Secret::from_slice(
        &init_secret,
        ProtocolVersion::default(),
        ciphersuite,
    ));

    for (i, epoch) in test_vector.epochs.iter().enumerate() {
        log::debug!("  Epoch {:?}", i);
        let tree_hash = hex_to_bytes(&epoch.tree_hash);
        let secret = hex_to_bytes(&epoch.commit_secret);
        let commit_secret = CommitSecret::from(PathSecret::from(Secret::from_slice(
            &secret,
            ProtocolVersion::default(),
            ciphersuite,
        )));
        log::trace!("    CommitSecret from tve {:?}", epoch.commit_secret);
        let mut psks = Vec::new();
        let mut psk_ids = Vec::new();
        for psk_value in epoch.psks.iter() {
            let psk_id =
                PreSharedKeyId::tls_deserialize(&mut hex_to_bytes(&psk_value.psk_id).as_slice())
                    .expect("An unexpected error occurred.");
            psk_ids.push(psk_id.clone());
            let secret = Secret::from_slice(
                &hex_to_bytes(&psk_value.psk),
                ProtocolVersion::default(),
                ciphersuite,
            );
            psks.push(secret.clone());
            let psk_bundle = PskBundle::new(secret).expect("Could not create PskBundle.");
            backend
                .key_store()
                .store(
                    &psk_id
                        .tls_serialize_detached()
                        .expect("Error serializing signature key."),
                    &psk_bundle,
                )
                .expect("Could not store PskBundle in key store.");
        }

        let psk_secret =
            PskSecret::new(ciphersuite, backend, &psk_ids).expect("An unexpected error occurred.");

        let joiner_secret = JoinerSecret::new(backend, commit_secret, &init_secret)
            .expect("Could not create JoinerSecret.");
        if hex_to_bytes(&epoch.joiner_secret) != joiner_secret.as_slice() {
            if cfg!(test) {
                panic!("Joiner secret mismatch");
            }
            return Err(KsTestVectorError::JoinerSecretMismatch);
        }

        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            joiner_secret.clone(),
            Some(psk_secret),
        )
        .expect("Could not create KeySchedule.");
        let welcome_secret = key_schedule
            .welcome(backend)
            .expect("An unexpected error occurred.");

        if hex_to_bytes(&epoch.welcome_secret) != welcome_secret.as_slice() {
            if cfg!(test) {
                panic!("Welcome secret mismatch");
            }
            return Err(KsTestVectorError::WelcomeSecretMismatch);
        }

        let confirmed_transcript_hash = hex_to_bytes(&epoch.confirmed_transcript_hash);

        let group_context = GroupContext::new(
            GroupId::from_slice(&group_id),
            i as u64,
            tree_hash.to_vec(),
            confirmed_transcript_hash.clone(),
            &[], // Extensions
        );

        let expected_group_context = hex_to_bytes(&epoch.group_context);
        let group_context_serialized = group_context
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
        if group_context_serialized != expected_group_context {
            log::error!("  Group context mismatch");
            log::debug!("    Computed: {:x?}", group_context_serialized);
            log::debug!("    Expected: {:x?}", expected_group_context);
            if cfg!(test) {
                panic!("Group context mismatch");
            }
            return Err(KsTestVectorError::GroupContextMismatch);
        }

        key_schedule
            .add_context(backend, &group_context_serialized)
            .expect("An unexpected error occurred.");

        let epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .expect("An unexpected error occurred.");

        init_secret = epoch_secrets.init_secret().clone();
        if hex_to_bytes(&epoch.init_secret) != init_secret.as_slice() {
            log_crypto!(
                debug,
                "    Epoch secret mismatch: {:x?} != {:x?}",
                hex_to_bytes(&epoch.init_secret),
                init_secret.as_slice()
            );
            if cfg!(test) {
                panic!("Init secret mismatch");
            }
            return Err(KsTestVectorError::InitSecretMismatch);
        }
        if hex_to_bytes(&epoch.sender_data_secret) != epoch_secrets.sender_data_secret().as_slice()
        {
            if cfg!(test) {
                panic!("Sender data secret mismatch");
            }
            return Err(KsTestVectorError::SenderDataSecretMismatch);
        }
        if hex_to_bytes(&epoch.encryption_secret) != epoch_secrets.encryption_secret().as_slice() {
            if cfg!(test) {
                panic!("Encryption secret mismatch");
            }
            return Err(KsTestVectorError::EncryptionSecretMismatch);
        }
        if hex_to_bytes(&epoch.exporter_secret) != epoch_secrets.exporter_secret().as_slice() {
            if cfg!(test) {
                panic!("Exporter secret mismatch");
            }
            return Err(KsTestVectorError::ExporterSecretMismatch);
        }
        if hex_to_bytes(&epoch.authentication_secret)
            != epoch_secrets.authentication_secret().as_slice()
        {
            if cfg!(test) {
                panic!("Authentication secret mismatch");
            }
            return Err(KsTestVectorError::AuthenticationSecretMismatch);
        }
        if hex_to_bytes(&epoch.external_secret) != epoch_secrets.external_secret().as_slice() {
            if cfg!(test) {
                panic!("External secret mismatch");
            }
            return Err(KsTestVectorError::ExternalSecretMismatch);
        }
        if hex_to_bytes(&epoch.confirmation_key) != epoch_secrets.confirmation_key().as_slice() {
            if cfg!(test) {
                panic!("Confirmation key mismatch");
            }
            return Err(KsTestVectorError::ConfirmationKeyMismatch);
        }
        if hex_to_bytes(&epoch.membership_key) != epoch_secrets.membership_key().as_slice() {
            if cfg!(test) {
                panic!("Membership key mismatch");
            }
            return Err(KsTestVectorError::MembershipKeyMismatch);
        }
        if hex_to_bytes(&epoch.resumption_secret) != epoch_secrets.resumption_secret().as_slice() {
            if cfg!(test) {
                panic!("Resumption secret mismatch");
            }
            return Err(KsTestVectorError::ResumptionSecretMismatch);
        }

        // Calculate external HPKE key pair
        let external_key_pair = epoch_secrets
            .external_secret()
            .derive_external_keypair(backend.crypto(), ciphersuite);
        if hex_to_bytes(&epoch.external_pub)
            != HpkePublicKey::from(external_key_pair.public.clone())
                .tls_serialize_detached()
                .expect("An unexpected error occurred.")
        {
            log::error!("  External public key mismatch");
            log::debug!(
                "    Computed: {:x?}",
                HpkePublicKey::from(external_key_pair.public)
                    .tls_serialize_detached()
                    .expect("An unexpected error occurred.")
            );
            log::debug!("    Expected: {:x?}", hex_to_bytes(&epoch.external_pub));
            if cfg!(test) {
                panic!("External pub mismatch");
            }
            return Err(KsTestVectorError::ExternalPubMismatch);
        }
    }
    Ok(())
}
