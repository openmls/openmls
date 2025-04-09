//! ## Welcome
//!
//! Parameters:
//! * Ciphersuite
//!
//! Format:
//!
//! See [`WelcomeTestVector`] documentation.
//!
//! Verification:
//! * Decrypt the Welcome message:
//!   * Identify the entry in `welcome.secrets` corresponding to `key_package`
//!   * Decrypt the encrypted group secrets using `init_priv`
//!   * Decrypt the encrypted group info
//! * Verify the signature on the decrypted group info using `signer_pub`
//! * Verify the `confirmation_tag` in the decrypted group info:
//!   * Initialize a key schedule epoch using the decrypted `joiner_secret` and no PSKs
//!   * Recompute a candidate `confirmation_tag` value using the `confirmation_key`
//!     from the key schedule epoch and the `confirmed_transcript_hash` from the
//!     decrypted GroupContext

use crate::{test_utils::OpenMlsRustCrypto, treesync::node::encryption_keys::EncryptionPrivateKey};
use openmls_traits::{crypto::OpenMlsCrypto, storage::StorageProvider, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::signable::Verifiable,
    framing::{MlsMessageBodyIn, MlsMessageIn},
    group::{HpkePrivateKey, OpenMlsSignaturePublicKey, SignaturePublicKey},
    key_packages::*,
    messages::*,
    prelude::group_info::{GroupInfo, VerifiableGroupInfo},
    schedule::{
        psk::{load_psks, store::ResumptionPskStore, PskSecret},
        KeySchedule,
    },
    test_utils::*,
};

const TEST_VECTOR_PATH_READ: &str = "test_vectors/welcome.json";
// TODO(#1279)
// const TEST_VECTOR_PATH_WRITE: &str = "test_vectors/welcome-new.json";
// const NUM_TESTS: usize = 100;

/// ```json
/// {
///   "cipher_suite": /* uint16 */,
///   // Chosen by the generator
///   "init_priv": /* hex-encoded serialized HPKE private key */,
///   "signer_pub": /* hex-encoded serialized signature public key */,
///   "key_package": /* hex-encoded serialized KeyPackage */,
///   "welcome": /* hex-encoded serialized Welcome */,
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WelcomeTestVector {
    cipher_suite: u16,
    #[serde(with = "hex::serde")]
    init_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signer_pub: Vec<u8>,
    #[serde(with = "hex::serde")]
    key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    welcome: Vec<u8>,
}

#[test]
fn test_read_vectors() {
    let test_vectors: Vec<WelcomeTestVector> = read(TEST_VECTOR_PATH_READ);

    for (i, test_vector) in test_vectors.into_iter().enumerate() {
        println!("# {i:04}");
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking messages test vector.\n{e:?}"),
        }
        println!()
    }
}

// # TODO(#1279)
// #[test]
// fn test_write_vectors() {
//     let mut tests = Vec::new();
//
//     for &ciphersuite in OpenMlsRustCrypto::default()
//         .crypto()
//         .supported_ciphersuites()
//         .iter()
//     {
//         for _ in 0..NUM_TESTS {
//             let test = generate_test_vector(ciphersuite);
//             tests.push(test);
//         }
//     }
//
//     write(TEST_VECTOR_PATH_WRITE, &tests);
// }
//
// pub fn generate_test_vector(_ciphersuite: Ciphersuite) -> WelcomeTestVector {
//     unimplemented!()
// }

pub fn run_test_vector(test_vector: WelcomeTestVector) -> Result<(), &'static str> {
    let _ = pretty_env_logger::formatted_builder()
        .is_test(true)
        .try_init();

    let provider = OpenMlsRustCrypto::default();

    // ---------------------------------------------------------------------------------------------

    let cipher_suite = Ciphersuite::try_from(test_vector.cipher_suite).unwrap();

    let init_priv = HpkePrivateKey::from(test_vector.init_priv);

    let signer_pub = {
        OpenMlsSignaturePublicKey::from_signature_key(
            SignaturePublicKey::from(test_vector.signer_pub),
            cipher_suite.signature_algorithm(),
        )
    };

    let key_package: KeyPackage = {
        let mls_message_key_package =
            MlsMessageIn::tls_deserialize_exact(test_vector.key_package).unwrap();

        match mls_message_key_package.body {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package.into(),
            _ => return Err("Expected MLSMessage.wire_format == mls_key_package."),
        }
    };

    println!("{key_package:?}");

    let welcome: Welcome = {
        let mls_message_welcome = MlsMessageIn::tls_deserialize_exact(test_vector.welcome).unwrap();

        match mls_message_welcome.body {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err("Expected MLSMessage.wire_format == mls_welcome."),
        }
    };

    println!("{welcome:?}");

    // ---------------------------------------------------------------------------------------------

    // TODO(#1259)
    if !provider
        .crypto()
        .supported_ciphersuites()
        .contains(&cipher_suite)
    {
        println!("Unsupported ciphersuite.");
        return Ok(());
    }

    // ---------------------------------------------------------------------------------------------

    let key_package_bundle = KeyPackageBundle {
        key_package: key_package.clone(),
        private_init_key: init_priv,
        private_encryption_key: EncryptionPrivateKey::from(vec![]),
    };

    let hash_ref = key_package.hash_ref(provider.crypto()).unwrap();
    provider
        .storage()
        .write_key_package(&hash_ref, &key_package_bundle)
        .unwrap();

    // Verification:
    // * Decrypt the Welcome message:
    //  * Identify the entry in `welcome.secrets` corresponding to `key_package`
    let encrypted_group_secrets = welcome
        .find_encrypted_group_secret(
            key_package_bundle
                .key_package()
                .hash_ref(provider.crypto())
                .unwrap(),
        )
        .unwrap();
    println!("{encrypted_group_secrets:?}");

    // // //  * Decrypt the encrypted group secrets using `init_priv`
    let group_secrets = GroupSecrets::try_from_ciphertext(
        key_package_bundle.init_private_key(),
        encrypted_group_secrets.encrypted_group_secrets(),
        welcome.encrypted_group_info(),
        welcome.ciphersuite(),
        provider.crypto(),
    )
    .unwrap();
    println!("{group_secrets:?}");

    // // //  * Decrypt the encrypted group info
    let psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(provider.storage(), &resumption_psk_store, &[]).unwrap();

        PskSecret::new(provider.crypto(), cipher_suite, psks).unwrap()
    };

    let mut key_schedule = KeySchedule::init(
        welcome.ciphersuite(),
        provider.crypto(),
        &group_secrets.joiner_secret,
        psk_secret,
    )
    .unwrap();

    let group_info: GroupInfo = {
        let verifiable_group_info: VerifiableGroupInfo = {
            let (welcome_key, welcome_nonce) = key_schedule
                .welcome(provider.crypto(), welcome.ciphersuite())
                .unwrap()
                .derive_welcome_key_nonce(provider.crypto(), welcome.ciphersuite())
                .unwrap();

            VerifiableGroupInfo::try_from_ciphertext(
                &welcome_key,
                &welcome_nonce,
                welcome.encrypted_group_info(),
                &[],
                provider.crypto(),
            )
            .unwrap()
        };
        println!("{verifiable_group_info:?}");

        verifiable_group_info
            .verify(provider.crypto(), &signer_pub)
            .unwrap()
    };
    println!("{group_info:?}");

    // * Verify the confirmation_tag in the decrypted group info:
    //
    //   * Initialize a key schedule epoch using the decrypted joiner_secret and no PSKs
    //   * Recompute a candidate confirmation_tag value using the confirmation_key from the key schedule epoch and the confirmed_transcript_hash from the decrypted GroupContext
    let group_context = group_info.group_context().clone();

    let serialized_group_context = group_context.tls_serialize_detached().unwrap();

    key_schedule
        .add_context(provider.crypto(), &serialized_group_context)
        .unwrap();

    let (_group_epoch_secrets, message_secrets) = {
        let epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), welcome.ciphersuite())
            .unwrap();

        epoch_secrets.split_secrets(
            serialized_group_context.to_vec(),
            TreeSize::new(8),
            LeafNodeIndex::new(1),
        )
    };

    let confirmation_tag = message_secrets
        .confirmation_key()
        .tag(
            provider.crypto(),
            welcome.ciphersuite(),
            group_context.confirmed_transcript_hash(),
        )
        .unwrap();

    assert_eq!(&confirmation_tag, group_info.confirmation_tag());

    Ok(())
}
