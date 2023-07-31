//! ## Secret Tree
//!
//! Parameters:
//! * Ciphersuite
//! * Number of leaves
//! * Set of generations
//!
//! Format:
//!
//! ```text
//! {
//!   "cipher_suite": /* uint16 */,
//!
//!   "sender_data": {
//!     "sender_data_secret": /* hex-encoded binary data */,
//!     "ciphertext": /* hex-encoded binary data */,
//!     "key": /* hex-encoded binary data */,
//!     "nonce": /* hex-encoded binary data */,
//!   },
//!
//!   "encryption_secret": /* hex-encoded binary data */,
//!   "leaves": [
//!     [
//!       {
//!         "generation": /* uint32 */
//!         "handshake_key": /* hex-encoded binary data */,
//!         "handshake_nonce": /* hex-encoded binary data */,
//!         "application_key": /* hex-encoded binary data */,
//!         "application_nonce": /* hex-encoded binary data */,
//!       },
//!       ...
//!     ],
//!     ...
//!   ]
//! }
//! ```
//!
//! Verification:
//!
//! * `sender_data`:
//!   * `key == sender_data_key(sender_data_secret, ciphertext)`
//!   * `nonce == sender_data_nonce(sender_data_secret, ciphertext)`
//! * Initialize a secret tree with a number of leaves equal to the number of
//!   entries in the `leaves` array, with `encryption_secret` as the root secret
//! * For each entry in `leaves`:
//!   * For each entry in the array `leaves[i]`, verify that:
//!     * `handshake_key = handshake_ratchet_key_[i]_[generation]`
//!     * `handshake_nonce = handshake_ratchet_nonce_[i]_[generation]`
//!     * `application_key = application_ratchet_key_[i]_[generation]`
//!     * `application_nonce = application_ratchet_nonce_[i]_[generation]`

use serde::{Deserialize, Serialize};

use crate::test_utils::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SenderData {
    sender_data_secret: String,
    ciphertext: String,
    key: String,
    nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Leaf {
    generation: u32,
    application_key: String,
    application_nonce: String,
    handshake_key: String,
    handshake_nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretTree {
    cipher_suite: u16,

    encryption_secret: String,
    sender_data: SenderData,
    leaves: Vec<Vec<Leaf>>,
}

#[cfg(test)]
pub fn run_test_vector(test: SecretTree, provider: &impl OpenMlsProvider) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;

    use crate::{
        binary_tree::{array_representation::TreeSize, LeafNodeIndex},
        schedule::{EncryptionSecret, SenderDataSecret},
        tree::secret_tree::{SecretTree, SecretType},
        versions::ProtocolVersion,
    };

    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();
    // Skip unsupported ciphersuites.
    if !provider
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Unsupported ciphersuite {ciphersuite:?} ...");
        return Ok(());
    }
    log::debug!("Secret tree test for {ciphersuite:?} ...");

    // Check sender data
    let sender_data_secret = hex_to_bytes(&test.sender_data.sender_data_secret);
    let sender_data_secret =
        SenderDataSecret::from_slice(&sender_data_secret, ProtocolVersion::Mls10, ciphersuite);
    let sender_data_ciphertext = hex_to_bytes(&test.sender_data.ciphertext);
    let sender_data_key = hex_to_bytes(&test.sender_data.key);
    let sender_data_nonce = hex_to_bytes(&test.sender_data.nonce);

    let my_sender_data_key = sender_data_secret
        .derive_aead_key(provider.crypto(), &sender_data_ciphertext)
        .unwrap();
    assert_eq!(&sender_data_key, my_sender_data_key.as_slice());
    let my_sender_data_nonce = sender_data_secret
        .derive_aead_nonce(ciphersuite, provider.crypto(), &sender_data_ciphertext)
        .unwrap();
    assert_eq!(&sender_data_nonce, my_sender_data_nonce.as_slice());

    let encryption_secret = hex_to_bytes(&test.encryption_secret);
    let num_leaves = test.leaves.len();

    log::trace!("Testing tree with {num_leaves} leaves.");
    for (leaf_index, leaf) in test.leaves.iter().enumerate() {
        log::trace!("Testing leaf {leaf_index}");

        for leaf_generation in leaf {
            let generation = leaf_generation.generation;
            log::trace!("   Testing generation {generation}");

            let mut secret_tree = SecretTree::new(
                EncryptionSecret::from_slice(
                    &encryption_secret,
                    ProtocolVersion::Mls10,
                    ciphersuite,
                ),
                TreeSize::new(num_leaves as u32),
                LeafNodeIndex::new(leaf_index as u32),
            );

            // Generate the secrets for the `generation`
            log::trace!("       Computing generation {generation}");
            let (application, handshake) = loop {
                log::trace!("       Computing generation {generation}");
                let handshake = secret_tree
                    .secret_for_encryption(
                        ciphersuite,
                        provider.crypto(),
                        LeafNodeIndex::new(leaf_index as u32),
                        SecretType::HandshakeSecret,
                    )
                    .unwrap();
                let application = secret_tree
                    .secret_for_encryption(
                        ciphersuite,
                        provider.crypto(),
                        LeafNodeIndex::new(leaf_index as u32),
                        SecretType::ApplicationSecret,
                    )
                    .unwrap();
                if handshake.0 == generation {
                    break (application.1, handshake.1);
                }
            };

            assert_eq!(
                application.0.as_slice(),
                &hex_to_bytes(&leaf_generation.application_key)
            );
            assert_eq!(
                application.1.as_slice(),
                &hex_to_bytes(&leaf_generation.application_nonce)
            );
            assert_eq!(
                handshake.0.as_slice(),
                &hex_to_bytes(&leaf_generation.handshake_key)
            );
            assert_eq!(
                handshake.1.as_slice(),
                &hex_to_bytes(&leaf_generation.handshake_nonce)
            );
        }
    }

    Ok(())
}

#[apply(providers)]
fn read_test_vectors_st(provider: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<SecretTree> = read("test_vectors/secret-tree.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking secret tree test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
