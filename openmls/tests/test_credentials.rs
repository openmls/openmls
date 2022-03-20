//! # Credential tests

use openmls::{prelude::*, test_utils::*, *};

// This test makes sure BasicCredentials can be created from a SignatureKeypair.
#[apply(ciphersuites_and_backends)]
fn credential_with_signature_keypair(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Create a signature keypair
    let signature_keypair =
        SignatureKeypair::new(ciphersuite.into(), backend).expect("Could not generate keypair.");

    // Deconstruct the keypair and keep a copy of the keys for later
    let (private_key, public_key) = signature_keypair.into_tuple();
    let original_private_key = private_key.clone();
    let original_public_key = public_key.clone();
    let signature_keypair = SignatureKeypair::from_parts(public_key, private_key);

    // Create a CredentialBundle
    let credential_bundle = CredentialBundle::from_parts(vec![1, 2, 3], signature_keypair);
    let (credential, signature_private_key) = credential_bundle.into_parts();

    // Make sure the credential's keys are the original keys
    assert_eq!(signature_private_key, original_private_key);
    assert_eq!(credential.signature_key(), &original_public_key);
}
