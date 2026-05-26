#![allow(non_camel_case_types)]
//! Migration example (0.7.1 -> main)

/// Compat enum for openmls=0.7.1
#[derive(serde::Serialize, serde::Deserialize)]
pub enum ProposalType_0_7_1 {
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

struct Migration<T> {
    before: T,
    after: openmls::prelude::ProposalType,
}

macro_rules! test_case {
    ($enum_version:ident,$ident:ident($value:literal)) => {
        Migration {
            before: $enum_version::$ident($value),
            after: openmls::prelude::ProposalType::$ident($value),
        }
    };
    ($enum_version:ident, $ident:ident) => {
        Migration {
            before: $enum_version::$ident,
            after: openmls::prelude::ProposalType::$ident,
        }
    };
}

const TEST_CASES_0_7_1: &[Migration<ProposalType_0_7_1>] = &[
    test_case!(ProposalType_0_7_1, Add),
    test_case!(ProposalType_0_7_1, Update),
    test_case!(ProposalType_0_7_1, Remove),
    test_case!(ProposalType_0_7_1, PreSharedKey),
    test_case!(ProposalType_0_7_1, Reinit),
    test_case!(ProposalType_0_7_1, ExternalInit),
    test_case!(ProposalType_0_7_1, GroupContextExtensions),
    // AppAck
    test_case!(ProposalType_0_7_1, SelfRemove),
    test_case!(ProposalType_0_7_1, Custom(20)),
];

/// Check that the `ProposalType` from 0.7.1 can be read using the `ProposalType` `main`
#[test]
fn migration_0_7_1() {
    for Migration {
        before,
        after: expected,
    } in TEST_CASES_0_7_1
    {
        let serialized = &postcard::to_allocvec(&before).expect("serialization failed");
        let deserialized: openmls::prelude::ProposalType =
            postcard::from_bytes(serialized).expect("deserialization failed");
        assert_eq!(&deserialized, expected);
    }
}
