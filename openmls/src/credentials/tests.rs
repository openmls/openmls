use tls_codec::{Deserialize, Serialize};

use super::*;

#[test]
fn test_protocol_version() {
    use crate::versions::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();
    let mls10_e = mls10_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::try_from(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap())).unwrap(),
        mls10_version
    );
    let default_e = default_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::try_from(u16::from_be_bytes(default_e[0..2].try_into().unwrap())).unwrap(),
        default_version
    );
    assert_eq!(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap()), 1);
    assert_eq!(u16::from_be_bytes(default_e[0..2].try_into().unwrap()), 1);
}

#[test]
fn that_unknown_credential_types_are_de_serialized_correctly() {
    let credential_types = [0x0000u16, 0x0A0A, 0x7A7A, 0xF000, 0xFFFF];

    for credential_type in credential_types.into_iter() {
        // Construct an unknown credential type.
        let test = credential_type.to_be_bytes().to_vec();

        // Test deserialization.
        let got = CredentialType::tls_deserialize_exact(&test).unwrap();

        match got {
            CredentialType::Unknown(got_proposal_type) => {
                assert_eq!(credential_type, got_proposal_type);
            }
            other => panic!("Expected `CredentialType::Unknown`, got `{:?}`.", other),
        }

        // Test serialization.
        let got_serialized = got.tls_serialize_detached().unwrap();
        assert_eq!(test, got_serialized);
    }
}
