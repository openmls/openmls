use openmls_rust_crypto::OpenMlsRustCrypto;

use super::*;

#[test]
fn test_protocol_version() {
    use crate::config::ProtocolVersion;
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

#[test]
fn test_credential_bundle_from_parts() {
    let backend = OpenMlsRustCrypto::default();
    let signature_scheme = SignatureScheme::ED25519;
    let keypair = SignatureKeypair::new(signature_scheme, &backend)
        .expect("Could not create signature keypair.");

    let _credential_bundle = CredentialBundle::from_parts(vec![1, 2, 3], keypair);
}
