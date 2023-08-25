//! # Known Answer Tests for the transcript hashes
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

#[cfg(test)]
use crate::test_utils::{read, write};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::{
        tests::utils::{generate_credential_with_key, randombytes},
        *,
    },
    messages::*,
    schedule::*,
    test_utils::*,
    versions::ProtocolVersion,
};

const TEST_VECTOR_PATH_READ: &str = "test_vectors/transcript-hashes.json";
const TEST_VECTOR_PATH_WRITE: &str = "test_vectors/transcript-hashes-new.json";
const NUM_TESTS: usize = 100;

/// ```json
/// {
///   "cipher_suite": /* uint16 */,
///
///   /* Chosen by the generator */
///   "confirmation_key": /* hex-encoded binary data */,
///   "authenticated_content": /* hex-encoded TLS serialized AuthenticatedContent */,
///   "interim_transcript_hash_before": /* hex-encoded binary data */,
///
///   /* Computed values */
///   "confirmed_transcript_hash_after": /* hex-encoded binary data */,
///   "interim_transcript_hash_after": /* hex-encoded binary data */,
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TranscriptTestVector {
    pub cipher_suite: u16,

    #[serde(with = "hex::serde")]
    pub confirmation_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub authenticated_content: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub interim_transcript_hash_before: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub confirmed_transcript_hash_after: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub interim_transcript_hash_after: Vec<u8>,
}

// -------------------------------------------------------------------------------------------------

#[test]
fn read_test_vectors_transcript() {
    let tests: Vec<TranscriptTestVector> = read(TEST_VECTOR_PATH_READ);

    for test_vector in tests {
        run_test_vector(test_vector);
    }
}

pub fn run_test_vector(test_vector: TranscriptTestVector) {
    let provider = OpenMlsRustCrypto::default();

    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).unwrap();
    if provider.crypto().supports(ciphersuite).is_err() {
        log::debug!("Skipping unsupported ciphersuite `{ciphersuite:?}`.");
        return;
    }

    // Verification:
    //
    // Verify that `authenticated_content` contains a `Commit`, ...
    let authenticated_content = AuthenticatedContent::from(
        AuthenticatedContentIn::tls_deserialize_exact(test_vector.authenticated_content).unwrap(),
    );
    assert!(matches!(
        authenticated_content.content(),
        FramedContentBody::Commit(_)
    ));

    // ... and `authenticated_content.auth.confirmation_tag` is a valid MAC for `authenticated_content` with key `confirmation_key` and input `confirmed_transcript_hash_after`.
    let confirmation_key = ConfirmationKey::from_secret(Secret::from_slice(
        &test_vector.confirmation_key,
        ProtocolVersion::default(),
        ciphersuite,
    ));
    let got_confirmation_tag = confirmation_key
        .tag(
            provider.crypto(),
            &test_vector.confirmed_transcript_hash_after,
        )
        .unwrap();
    assert_eq!(
        got_confirmation_tag,
        *authenticated_content.confirmation_tag().unwrap()
    );

    // Verify that *`confirmed_transcript_hash_after`* and `interim_transcript_hash_after` are the result of updating `interim_transcript_hash_before` with `authenticated_content`.
    let got_confirmed_transcript_hash_after = {
        let input = ConfirmedTranscriptHashInput::try_from(&authenticated_content).unwrap();

        input
            .calculate_confirmed_transcript_hash(
                provider.crypto(),
                ciphersuite,
                &test_vector.interim_transcript_hash_before,
            )
            .unwrap()
    };
    assert_eq!(
        test_vector.confirmed_transcript_hash_after,
        got_confirmed_transcript_hash_after
    );

    // Verify that `confirmed_transcript_hash_after` and *`interim_transcript_hash_after`* are the result of updating `interim_transcript_hash_before` with `authenticated_content`.
    let got_interim_transcript_hash_after = {
        let input = InterimTranscriptHashInput::from(&got_confirmation_tag);

        input
            .calculate_interim_transcript_hash(
                provider.crypto(),
                ciphersuite,
                &got_confirmed_transcript_hash_after,
            )
            .unwrap()
    };
    assert_eq!(
        test_vector.interim_transcript_hash_after,
        got_interim_transcript_hash_after
    );
}

// -------------------------------------------------------------------------------------------------

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for _ in 0..NUM_TESTS {
            let test = generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    write(TEST_VECTOR_PATH_WRITE, &tests);
}

pub fn generate_test_vector(ciphersuite: Ciphersuite) -> TranscriptTestVector {
    let provider = OpenMlsRustCrypto::default();

    let confirmation_key = ConfirmationKey::random(ciphersuite, provider.rand());

    let interim_transcript_hash_before = randombytes(ciphersuite.hash_length());

    // Note: This does not have a valid `confirmation_tag` for now and is only used to
    // calculate `confirmed_transcript_hash_after`.
    let mut authenticated_content = {
        let aad = provider.rand().random_vec(48).unwrap();
        let framing_parameters = FramingParameters::new(&aad, WireFormat::PublicMessage);

        // XXX: Use random but valid sender.
        let sender = Sender::build_member(LeafNodeIndex::new(7));

        let commit = Commit {
            proposals: vec![],
            path: None,
        };

        let group_context = {
            let tree_hash_before = provider
                .rand()
                .random_vec(ciphersuite.hash_length())
                .unwrap();

            let confirmed_transcript_hash_before = provider
                .rand()
                .random_vec(ciphersuite.hash_length())
                .unwrap();

            GroupContext::new(
                ciphersuite,
                GroupId::random(provider.rand()),
                random_u64(),
                tree_hash_before,
                confirmed_transcript_hash_before,
                Extensions::empty(),
            )
        };

        let signer = {
            let credential_with_key_and_signer = generate_credential_with_key(
                b"Alice".to_vec(),
                ciphersuite.signature_algorithm(),
                &provider,
            );

            credential_with_key_and_signer.signer
        };

        AuthenticatedContent::commit(framing_parameters, sender, commit, &group_context, &signer)
            .unwrap()
    };

    // Now, calculate `confirmed_transcript_hash_after` ...
    let confirmed_transcript_hash_after = {
        let input = ConfirmedTranscriptHashInput::try_from(&authenticated_content).unwrap();

        input
            .calculate_confirmed_transcript_hash(
                provider.crypto(),
                ciphersuite,
                &interim_transcript_hash_before,
            )
            .unwrap()
    };

    // ... and the `confirmation_tag` ...
    let confirmation_tag = {
        confirmation_key
            .tag(provider.crypto(), &confirmed_transcript_hash_after)
            .unwrap()
    };

    // ... and set it in `authenticated_content`.
    authenticated_content.set_confirmation_tag(confirmation_tag.clone());

    let interim_transcript_hash_after = {
        let input = InterimTranscriptHashInput::from(&confirmation_tag);

        input
            .calculate_interim_transcript_hash(
                provider.crypto(),
                ciphersuite,
                &confirmed_transcript_hash_after,
            )
            .unwrap()
    };

    TranscriptTestVector {
        cipher_suite: (&ciphersuite).into(),

        confirmation_key: confirmation_key.as_slice().to_vec(),
        authenticated_content: authenticated_content.tls_serialize_detached().unwrap(),
        interim_transcript_hash_before,

        confirmed_transcript_hash_after,
        interim_transcript_hash_after,
    }
}
