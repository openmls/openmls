//! These tests check storage tag stability for `serde` serializations of `Extension`,
//!   `ExtensionType`, `Proposal`, `ProposalType`, and `CredentialType`.
#![allow(dead_code)]

use openmls_compat_tests::storage_tag_check::*;

use std::sync::OnceLock;

static TEST_DATA: OnceLock<TestData> = OnceLock::new();

#[allow(nonstandard_style)]
#[derive(PartialEq, Debug, serde::Deserialize)]
enum SupportedVersion {
    OpenMls_0_7_0,
    OpenMls_0_8_1,
    OpenMls_0_8_1_Extensions,
}

/// Partly deserialized test data.
///
/// Each `serde_json::Value` is deserialized separately
/// into two versions of a type (Before, After), and
/// can be used to compare their values..
#[derive(serde::Deserialize)]
struct TestData {
    credential_type: Vec<TestCase>,
    extension_type: Vec<TestCase>,
    extension: Vec<TestCase>,
    proposal_type: Vec<TestCase>,
    proposal: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
struct TestCase {
    input: serde_json::Value,
    supported: Vec<SupportedVersion>,
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

/// Helper function to retrieve the enum variant name from the `serde_json::Value` input data
fn name(input: &serde_json::Value) -> String {
    match input {
        serde_json::Value::String(s) => s.to_string(),
        serde_json::Value::Object(map) => map.keys().next().unwrap().to_string(),
        // NOTE: the test data does not include `serde_json::Value`s of other types
        _ => unimplemented!(),
    }
}

macro_rules! generate_test_fn {
    ($test_name:ident,$before:ty,$after:ty,$test_cases:expr,$version:expr) => {
        #[test]
        fn $test_name() {
            $test_cases
                .iter()
                .filter(|case| case.supported.contains(&$version))
                .for_each(|case| {
                    let migration = Migration::<$before, $after>::from_value(&case.input);
                    migration.test_tag();
                    eprintln!(
                        "Tests succeeded for {}::{}",
                        stringify!($before).replace(" ", ""),
                        name(&case.input)
                    );
                });
        }
    };
}

macro_rules! compat_tests {
    ($mod_name:ident, $before:tt, $after:tt, $version:expr) => {
        mod $mod_name {
            use super::*;

            generate_test_fn!(
                test_extension_type,
                $before::prelude::ExtensionType,
                $after::prelude::ExtensionType,
                TestData::load().extension_type,
                $version
            );
            generate_test_fn!(
                test_extension,
                $before::prelude::Extension,
                $after::prelude::Extension,
                TestData::load().extension,
                $version
            );
            generate_test_fn!(
                test_credential_type,
                $before::prelude::CredentialType,
                $after::prelude::CredentialType,
                TestData::load().credential_type,
                $version
            );
            generate_test_fn!(
                test_proposal_type,
                $before::prelude::ProposalType,
                $after::prelude::ProposalType,
                TestData::load().proposal_type,
                $version
            );

            generate_test_fn!(
                test_proposal,
                $before::prelude::Proposal,
                $after::prelude::Proposal,
                TestData::load().proposal,
                $version
            );
        }
    };
}

// check the storage tag stability for openmls=0.7.x => `main`
// (the patch version of `openmls_0_7` is selected in `test.sh`)
#[cfg(feature = "compat_0_7")]
compat_tests!(
    test_storage_tags_0_7,
    openmls_0_7,
    openmls,
    SupportedVersion::OpenMls_0_7_0
);
// check the storage tag stability for openmls=0.8.1 => `main`
#[cfg(all(feature = "compat_0_8_1", not(feature = "compat_0_8_1_extensions")))]
compat_tests!(
    test_storage_tags_0_8_1,
    openmls_0_8_1,
    openmls,
    SupportedVersion::OpenMls_0_8_1
);
// check the storage tag stability for openmls=0.8.1 => `main` with feature `extensions-draft`
#[cfg(feature = "compat_0_8_1_extensions")]
compat_tests!(
    test_storage_tags_0_8_1,
    openmls_0_8_1,
    openmls,
    SupportedVersion::OpenMls_0_8_1_Extensions
);
