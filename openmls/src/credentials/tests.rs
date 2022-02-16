use crate::test_utils::*;

use super::*;

#[test]
fn test_protocol_version() {
    use crate::versions::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();
    let mls10_e = mls10_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 1);
    assert_eq!(default_e[0], 1);
}

#[apply(ciphersuites_and_backends)]
fn test_credential_bundle_from_parts(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let signature_scheme = ciphersuite.signature_algorithm();
    let keypair = SignatureKeypair::new(signature_scheme, backend)
        .expect("Could not create signature keypair.");

    let _credential_bundle = CredentialBundle::from_parts(vec![1, 2, 3], keypair);
}
