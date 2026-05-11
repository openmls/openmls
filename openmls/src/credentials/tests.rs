use tls_codec::{Deserialize, Serialize};

use super::*;

#[test]
fn test_protocol_version() {
    use crate::versions::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let other_version = ProtocolVersion::Other(999);
    let mls10_e = mls10_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::from(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap())),
        mls10_version
    );
    let default_e = other_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::from(u16::from_be_bytes(default_e[0..2].try_into().unwrap())),
        other_version
    );
    assert_eq!(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap()), 1);
    assert_eq!(u16::from_be_bytes(default_e[0..2].try_into().unwrap()), 999);
}

#[test]
fn that_unknown_credential_types_are_de_serialized_correctly() {
    // Use non-GREASE unknown values for testing (GREASE values have pattern 0x_A_A)
    let credential_types = [0x0000u16, 0x0B0B, 0x7C7C, 0xF000, 0xFFFF];

    for credential_type in credential_types.into_iter() {
        // Construct an unknown credential type.
        let test = credential_type.to_be_bytes().to_vec();

        // Test deserialization.
        let got = CredentialType::tls_deserialize_exact(&test).unwrap();

        match got {
            CredentialType::Other(got_proposal_type) => {
                assert_eq!(credential_type, got_proposal_type);
            }
            other => panic!("Expected `CredentialType::Unknown`, got `{other:?}`."),
        }

        // Test serialization.
        let got_serialized = got.tls_serialize_detached().unwrap();
        assert_eq!(test, got_serialized);
    }
}

/// Locks the `(variant_index, variant_name)` pair that the manual `Serialize`
/// impl for [`CredentialType`] emits for each variant. These values are the
/// bincode/postcard wire encoding of the enum tag and must not change without
/// a deliberate, versioned migration of every existing persisted group.
///
/// When adding a new variant, append a new `check(...)` line with a fresh
/// `variant_index` — never reuse or renumber the existing entries.
#[test]
fn credential_type_variant_indices() {
    use crate::utils::variant_index_probe::probe;

    fn check(value: CredentialType, expected_index: u32, expected_name: &'static str) {
        let (idx, name) =
            probe(&value).expect("CredentialType Serialize should call serialize_*_variant");
        assert_eq!(
            (idx, name),
            (expected_index, expected_name),
            "CredentialType::{expected_name} drifted from index {expected_index}",
        );
    }

    check(CredentialType::Basic, 0, "Basic");
    check(CredentialType::X509, 1, "X509");
    check(CredentialType::Other(0), 2, "Other");
    check(CredentialType::Grease(0), 3, "Grease");
}
