//! # Known Answer Tests for the key schedule
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.
//!
//! If values are not present, they are encoded as empty strings.

use log::info;
use openmls_traits::{random::OpenMlsRand, types::HpkeKeyPair, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::Serialize as TlsSerializeTrait;

#[cfg(test)]
use crate::test_utils::write;
use crate::{
    ciphersuite::*,
    extensions::Extensions,
    group::*,
    schedule::{errors::KsTestVectorError, CommitSecret, *},
    test_utils::*,
};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Exporter {
    label: String,
    context: String,
    length: u32,
    secret: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Epoch {
    // Chosen by the generator
    tree_hash: String,
    commit_secret: String,
    psk_secret: String,
    confirmed_transcript_hash: String,

    // Computed values
    group_context: String,
    joiner_secret: String,
    welcome_secret: String,
    init_secret: String,
    sender_data_secret: String,
    encryption_secret: String,
    exporter_secret: String,
    epoch_authenticator: String,
    external_secret: String,
    confirmation_key: String,
    membership_key: String,
    resumption_psk: String,

    external_pub: String,
    exporter: Exporter,
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
    PskSecret,
    JoinerSecret,
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
    let commit_secret = CommitSecret::random(ciphersuite, crypto.rand());

    let confirmed_transcript_hash = crypto
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");

    // PSK secret can sometimes be the all zero vector
    let a: [u8; 1] = crypto.rand().random_array().unwrap();
    let psk_secret = if a[0] > 127 {
        PskSecret::from(Secret::random(ciphersuite, crypto.rand()).unwrap())
    } else {
        PskSecret::from(Secret::zero(ciphersuite))
    };

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(group_id),
        epoch,
        tree_hash.to_vec(),
        confirmed_transcript_hash.clone(),
        Extensions::empty(),
    );

    let joiner_secret = JoinerSecret::new(
        crypto.crypto(),
        ciphersuite,
        commit_secret.clone(),
        init_secret,
        &group_context.tls_serialize_detached().unwrap(),
    )
    .expect("Could not create JoinerSecret.");
    let mut key_schedule = KeySchedule::init(
        ciphersuite,
        crypto.crypto(),
        &joiner_secret,
        psk_secret.clone(),
    )
    .expect("Could not create KeySchedule.");
    let welcome_secret = key_schedule
        .welcome(crypto.crypto(), ciphersuite)
        .expect("An unexpected error occurred.");

    let serialized_group_context = group_context
        .tls_serialize_detached()
        .expect("Could not serialize group context.");

    key_schedule
        .add_context(crypto.crypto(), &serialized_group_context)
        .expect("An unexpected error occurred.");
    let epoch_secrets = key_schedule
        .epoch_secrets(crypto.crypto(), ciphersuite)
        .expect("An unexpected error occurred.");

    // Calculate external HPKE key pair
    let external_key_pair = epoch_secrets
        .external_secret()
        .derive_external_keypair(crypto.crypto(), ciphersuite)
        .expect("An unexpected crypto error occurred.");

    (
        confirmed_transcript_hash,
        commit_secret,
        psk_secret,
        joiner_secret,
        welcome_secret,
        epoch_secrets,
        tree_hash,
        group_context,
        external_key_pair,
    )
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(
    n_epochs: u64,
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> KeyScheduleTestVector {
    use tls_codec::Serialize;

    // Set up setting.
    let mut init_secret =
        InitSecret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let initial_init_secret = init_secret.clone();
    let group_id = provider
        .rand()
        .random_vec(16)
        .expect("An unexpected error occurred.");

    let mut epochs = Vec::new();

    // Generate info for all epochs
    for epoch in 0..n_epochs {
        println!("Generating epoch: {epoch:?}");
        let (
            confirmed_transcript_hash,
            commit_secret,
            psk_secret,
            joiner_secret,
            welcome_secret,
            epoch_secrets,
            tree_hash,
            group_context,
            external_key_pair,
        ) = generate(ciphersuite, &init_secret, &group_id, epoch);

        // exporter
        let exporter_label = "exporter label";
        let exporter_length = 32u32;
        let exporter_context = b"exporter context";
        let exported = epoch_secrets
            .exporter_secret()
            .derive_exported_secret(
                ciphersuite,
                provider.crypto(),
                exporter_label,
                exporter_context,
                exporter_length as usize,
            )
            .unwrap();

        let epoch_info = Epoch {
            tree_hash: bytes_to_hex(&tree_hash),
            commit_secret: bytes_to_hex(commit_secret.as_slice()),
            psk_secret: bytes_to_hex(psk_secret.as_slice()),
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
            epoch_authenticator: bytes_to_hex(epoch_secrets.epoch_authenticator().as_slice()),
            external_secret: bytes_to_hex(epoch_secrets.external_secret().as_slice()),
            confirmation_key: bytes_to_hex(epoch_secrets.confirmation_key().as_slice()),
            membership_key: bytes_to_hex(epoch_secrets.membership_key().as_slice()),
            resumption_psk: bytes_to_hex(epoch_secrets.resumption_psk().as_slice()),
            external_pub: bytes_to_hex(&external_key_pair.public),
            exporter: Exporter {
                label: exporter_label.into(),
                context: bytes_to_hex(exporter_context),
                length: exporter_length,
                secret: bytes_to_hex(&exported),
            },
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
    const NUM_EPOCHS: u64 = 2;
    let mut tests = Vec::new();
    let provider = OpenMlsRustCrypto::default();
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        tests.push(generate_test_vector(NUM_EPOCHS, ciphersuite, &provider));
    }
    write("test_vectors/key-schedule-new.json", &tests);
}

#[openmls_test::openmls_test]
fn read_test_vectors_key_schedule() {
    let _ = pretty_env_logger::try_init();

    let tests: Vec<KeyScheduleTestVector> =
        read_json!("../../../../test_vectors/key-schedule.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking key schedule test vector.\n{e:?}"),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test_vector: KeyScheduleTestVector,
    provider: &impl OpenMlsProvider,
) -> Result<(), KsTestVectorError> {
    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    log::trace!("  {:?}", test_vector);

    if !provider
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        info!("Skipping unsupported ciphersuite `{ciphersuite:?}`.");
        return Ok(());
    }

    let group_id = hex_to_bytes(&test_vector.group_id);
    let init_secret = hex_to_bytes(&test_vector.initial_init_secret);
    log::trace!(
        "  InitSecret from tve: {:?}",
        test_vector.initial_init_secret
    );
    let mut init_secret = InitSecret::from(Secret::from_slice(&init_secret));

    for (epoch_ctr, epoch) in test_vector.epochs.iter().enumerate() {
        let tree_hash = hex_to_bytes(&epoch.tree_hash);
        let secret = hex_to_bytes(&epoch.commit_secret);
        let commit_secret = CommitSecret::from(PathSecret::from(Secret::from_slice(&secret)));
        log::trace!("    CommitSecret from tve {:?}", epoch.commit_secret);

        let confirmed_transcript_hash = hex_to_bytes(&epoch.confirmed_transcript_hash);

        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::from_slice(&group_id),
            GroupEpoch::from(epoch_ctr as u64),
            tree_hash.to_vec(),
            confirmed_transcript_hash.clone(),
            Extensions::empty(),
        );

        let joiner_secret = JoinerSecret::new(
            provider.crypto(),
            ciphersuite,
            commit_secret,
            &init_secret,
            &group_context.tls_serialize_detached().unwrap(),
        )
        .expect("Could not create JoinerSecret.");
        if hex_to_bytes(&epoch.joiner_secret) != joiner_secret.as_slice() {
            if cfg!(test) {
                panic!("Joiner secret mismatch");
            }
            return Err(KsTestVectorError::JoinerSecretMismatch);
        }

        let psk_secret_inner = Secret::from_slice(&hex_to_bytes(&epoch.psk_secret));
        let psk_secret = PskSecret::from(psk_secret_inner);

        let mut key_schedule =
            KeySchedule::init(ciphersuite, provider.crypto(), &joiner_secret, psk_secret)
                .expect("Could not create KeySchedule.");
        let welcome_secret = key_schedule
            .welcome(provider.crypto(), ciphersuite)
            .expect("An unexpected error occurred.");

        if hex_to_bytes(&epoch.welcome_secret) != welcome_secret.as_slice() {
            if cfg!(test) {
                panic!("Welcome secret mismatch");
            }
            return Err(KsTestVectorError::WelcomeSecretMismatch);
        }

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
            .add_context(provider.crypto(), &group_context_serialized)
            .expect("An unexpected error occurred.");

        let epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), ciphersuite)
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
        if hex_to_bytes(&epoch.epoch_authenticator)
            != epoch_secrets.epoch_authenticator().as_slice()
        {
            if cfg!(test) {
                panic!("Epoch authenticator mismatch");
            }
            return Err(KsTestVectorError::EpochAuthenticatorMismatch);
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
        if hex_to_bytes(&epoch.resumption_psk) != epoch_secrets.resumption_psk().as_slice() {
            if cfg!(test) {
                panic!("Resumption psk mismatch");
            }
            return Err(KsTestVectorError::ResumptionPskMismatch);
        }

        // Calculate external HPKE key pair
        let external_key_pair = epoch_secrets
            .external_secret()
            .derive_external_keypair(provider.crypto(), ciphersuite)
            .expect("an unexpected crypto error occurred");
        if hex_to_bytes(&epoch.external_pub) != external_key_pair.public {
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

        // Check exported secret
        let exported = epoch_secrets
            .exporter_secret()
            .derive_exported_secret(
                ciphersuite,
                provider.crypto(),
                &epoch.exporter.label,
                &hex_to_bytes(&epoch.exporter.context),
                epoch.exporter.length as usize,
            )
            .unwrap();
        if hex_to_bytes(&epoch.exporter.secret) != exported {
            if cfg!(test) {
                panic!("Exporter mismatch");
            }
            return Err(KsTestVectorError::ExporterMismatch);
        }
    }
    Ok(())
}
