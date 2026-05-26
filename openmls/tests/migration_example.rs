#![allow(non_camel_case_types)]
//! Migration examples (0.7.1 -> main)

use openmls::prelude::{CredentialType, ExtensionType, ProposalType};

struct Migration<Before, After> {
    before: Before,
    after: After,
}

macro_rules! test_case {
    ($enum_before:ident, $enum_after:ident, $ident:ident($value:literal)) => {
        Migration {
            before: $enum_before::$ident($value),
            after: $enum_after::$ident($value),
        }
    };
    ($enum_before:ident, $enum_after:ident, $ident:ident) => {
        Migration {
            before: $enum_before::$ident,
            after: $enum_after::$ident,
        }
    };
}

#[repr(u16)]
#[derive(serde::Serialize, serde::Deserialize)]
enum CredentialType_0_7_1 {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`Certificate`]
    X509 = 2,
    /// Another type of credential that is not in the MLS protocol spec.
    Other(u16),
}

#[derive(serde::Serialize, serde::Deserialize)]
enum ExtensionType_0_7_1 {
    ApplicationId,
    RatchetTree,
    RequiredCapabilities,
    ExternalPub,
    ExternalSenders,
    LastResort,
    Unknown(u16),
}

/// Compat enum for openmls=0.7.1
#[derive(serde::Serialize, serde::Deserialize)]
enum ProposalType_0_7_1 {
    Add,
    Update,
    Remove,
    PreSharedKey,
    Reinit,
    ExternalInit,
    GroupContextExtensions,
    AppAck,
    SelfRemove,
    Custom(u16),
}

const TEST_CASES_PROPOSAL_TYPE_0_7_1: &[Migration<ProposalType_0_7_1, ProposalType>] = &[
    test_case!(ProposalType_0_7_1, ProposalType, Add),
    test_case!(ProposalType_0_7_1, ProposalType, Update),
    test_case!(ProposalType_0_7_1, ProposalType, Remove),
    test_case!(ProposalType_0_7_1, ProposalType, PreSharedKey),
    test_case!(ProposalType_0_7_1, ProposalType, Reinit),
    test_case!(ProposalType_0_7_1, ProposalType, ExternalInit),
    test_case!(ProposalType_0_7_1, ProposalType, GroupContextExtensions),
    // AppAck
    test_case!(ProposalType_0_7_1, ProposalType, SelfRemove),
    test_case!(ProposalType_0_7_1, ProposalType, Custom(20)),
];

const TEST_CASES_CREDENTIAL_TYPE_0_7_1: &[Migration<CredentialType_0_7_1, CredentialType>] = &[
    test_case!(CredentialType_0_7_1, CredentialType, Basic),
    test_case!(CredentialType_0_7_1, CredentialType, X509),
    test_case!(CredentialType_0_7_1, CredentialType, Other(20)),
];

const TEST_CASES_EXTENSION_TYPE_0_7_1: &[Migration<ExtensionType_0_7_1, ExtensionType>] = &[
    test_case!(ExtensionType_0_7_1, ExtensionType, ApplicationId),
    test_case!(ExtensionType_0_7_1, ExtensionType, RatchetTree),
    test_case!(ExtensionType_0_7_1, ExtensionType, RequiredCapabilities),
    test_case!(ExtensionType_0_7_1, ExtensionType, ExternalPub),
    test_case!(ExtensionType_0_7_1, ExtensionType, ExternalSenders),
    test_case!(ExtensionType_0_7_1, ExtensionType, LastResort),
    test_case!(ExtensionType_0_7_1, ExtensionType, Unknown(20)),
];

impl<Before, After> Migration<Before, After>
where
    Before: serde::Serialize,
    After: for<'a> serde::Deserialize<'a> + std::fmt::Debug + PartialEq,
{
    fn test_serialization_roundtrip(&self) {
        let serialized = postcard::to_allocvec(&self.before).expect("serialization failed");
        let deserialized: After =
            postcard::from_bytes(&serialized).expect("deserialization failed");
        assert_eq!(deserialized, self.after);
    }
}

#[test]
fn migration_0_7_1() {
    // `ProposalType` migration
    TEST_CASES_PROPOSAL_TYPE_0_7_1
        .into_iter()
        .for_each(Migration::test_serialization_roundtrip);

    // `CredentialType` migration
    TEST_CASES_CREDENTIAL_TYPE_0_7_1
        .into_iter()
        .for_each(Migration::test_serialization_roundtrip);

    // `ExtensionType` migration
    TEST_CASES_EXTENSION_TYPE_0_7_1
        .into_iter()
        .for_each(Migration::test_serialization_roundtrip);
}
