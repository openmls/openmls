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

use openmls_traits::OpenMlsCryptoProvider;
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
pub struct Leave {
    generation: u32,
    handshake_key: String,
    handshake_nonce: String,
    application_key: String,
    application_nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretTree {
    cipher_suite: u16,

    sender_data: SenderData,
    encryption_secret: String,
    leaves: Vec<Leave>,
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test: SecretTree,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), String> {
    Ok(())
}

#[apply(backends)]
fn read_test_vectors_st(backend: &impl OpenMlsCryptoProvider) {
    // let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<SecretTree> = read("test_vectors/secret-tree.json");

    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking secret tree test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
