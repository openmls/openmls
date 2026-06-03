//! These tests check storage tag stability for `serde` serializations of `Extension`,
//!   `ExtensionType`, `Proposal`, `ProposalType`, and `CredentialType`.
#![allow(dead_code)]

use openmls_compat_tests::storage_tag_check::*;

use std::sync::OnceLock;

static TEST_DATA: OnceLock<TestData> = OnceLock::new();

/// Partly deserialized test data.
///
/// Each `serde_json::Value` is deserialized separately
/// into two versions of a type (Before, After), and
/// can be used to compare their values..
#[derive(serde::Deserialize)]
struct TestData {
    credential_type: Vec<serde_json::Value>,
    extension_type: Vec<serde_json::Value>,
    extension: Vec<serde_json::Value>,
    proposal_type: Vec<serde_json::Value>,
    proposal: Vec<serde_json::Value>,
}

impl TestData {
    fn load() -> &'static Self {
        TEST_DATA.get_or_init(|| {
            serde_json::from_str(include_str!("data/storage_tag_stability.json"))
                .expect("invalid test data")
        })
    }
}

struct Migration<Before, After> {
    before: Before,
    after: After,
}

impl<Before, After> Migration<Before, After>
where
    Before: for<'a> serde::Deserialize<'a>,
    After: for<'a> serde::Deserialize<'a>,
{
    fn from_value(input: &serde_json::Value) -> Self {
        let before: Before =
            serde_json::from_value(input.clone()).expect("error deserializing `before`");
        let after: After =
            serde_json::from_value(input.clone()).expect("error deserializing `after`");
        Migration { before, after }
    }
}

impl<Before, After> Migration<Before, After>
where
    Before: serde::Serialize,
    After: serde::Serialize,
{
    fn test_tag(&self) {
        let tag_before =
            StorageTags::for_enum_variant(&self.before).expect("no tag was serialized");
        let tag_after = StorageTags::for_enum_variant(&self.after).expect("no tag was serialized");
        assert_eq!(tag_before, tag_after);
    }
}

macro_rules! test_case {
    ($test_name:ident,$before:ty,$after:ty,$test_cases:expr) => {
        #[test]
        fn $test_name() {
            $test_cases.iter().for_each(|case| {
                let migration = Migration::<$before, $after>::from_value(case);
                migration.test_tag()
            });
        }
    };
}

macro_rules! compat_tests {
    ($mod_name:ident, $before:tt, $after:tt) => {
        mod $mod_name {
            use super::*;

            test_case!(
                test_extension_type,
                $before::prelude::ExtensionType,
                $after::prelude::ExtensionType,
                TestData::load().extension_type
            );
            test_case!(
                test_extension,
                $before::prelude::Extension,
                $after::prelude::Extension,
                TestData::load().extension
            );
            test_case!(
                test_credential_type,
                $before::prelude::CredentialType,
                $after::prelude::CredentialType,
                TestData::load().credential_type
            );
            test_case!(
                test_proposal_type,
                $before::prelude::ProposalType,
                $after::prelude::ProposalType,
                TestData::load().proposal_type
            );

            test_case!(
                test_proposal,
                $before::prelude::Proposal,
                $after::prelude::Proposal,
                TestData::load().proposal
            );
        }
    };
}

// check the storage tag stability for openmls=0.7.1 => `main`
#[cfg(feature = "compat_0_7_1")]
compat_tests!(test_storage_tags_0_7_1, openmls_0_7_1, openmls);
// check the storage tag stability for openmls=0.8.1 => `main`
#[cfg(feature = "compat_0_8_1")]
compat_tests!(test_storage_tags_0_8_1, openmls_0_8_1, openmls);
