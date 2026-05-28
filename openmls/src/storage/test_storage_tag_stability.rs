//! These tests check storage tag stability for `serde` serializations of `Extension`,
//!   `ExtensionType`, `Proposal`, `ProposalType`, and `CredentialType`.

use crate::test_utils::storage_tag_check::*;

const TEST_CASES_CREDENTIAL_TYPE: &[&str] = &[r#""Basic""#, r#""X509""#, r#"{"Other":20}"#];

const TEST_CASES_EXTENSION_TYPE: &[&str] = &[
    r#""ApplicationId""#,
    r#""RatchetTree""#,
    r#""RequiredCapabilities""#,
    r#""ExternalPub""#,
    r#""ExternalSenders""#,
    r#""LastResort""#,
    r#"{"Unknown":20}"#,
];

const TEST_CASES_EXTENSION: &[&str] = &[
    r#"{"ApplicationId":{"key_id":{"vec":[]}}}"#,
    r#"{"RatchetTree":{"ratchet_tree":[]}}"#,
    r#"{"RequiredCapabilities":{"extension_types":[],"proposal_types":[],"credential_types":[]}}"#,
    r#"{"ExternalPub":{"external_pub":{"vec":[]}}}"#,
    r#"{"ExternalSenders":[]}"#,
    r#"{"LastResort":{}}"#,
    r#"{"Unknown":[7,[]]}"#,
];

const TEST_CASES_PROPOSAL: &[&str] = &[
    r#"{"Add":{"key_package":{"payload":{"protocol_version":"Mls10","ciphersuite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519","init_key":{"key":{"vec":[]}},"leaf_node":{"payload":{"encryption_key":{"key":{"vec":[]}},"signature_key":{"value":{"vec":[]}},"credential":{"credential_type":"Basic","serialized_credential_content":{"vec":[]}},"capabilities":{"versions":[],"ciphersuites":[],"extensions":[],"proposals":[],"credentials":[]},"leaf_node_source":"Update","extensions":{"unique":[]}},"signature":{"value":{"vec":[]}}},"extensions":{"unique":[]},"signature":{"value":{"vec":[]}}},"signature":{"value":{"vec":[]}}}}}"#,
    r#"{"Update":{"leaf_node":{"payload":{"encryption_key":{"key":{"vec":[]}},"signature_key":{"value":{"vec":[]}},"credential":{"credential_type":"Basic","serialized_credential_content":{"vec":[]}},"capabilities":{"versions":[],"ciphersuites":[],"extensions":[],"proposals":[],"credentials":[]},"leaf_node_source":"Update","extensions":{"unique":[]}},"signature":{"value":{"vec":[]}}}}}"#,
    r#"{"Remove":{"removed":0}}"#,
    r#"{"PreSharedKey":{"psk":{"psk":{"External":{"psk_id":{"vec":[]}}},"psk_nonce":{"vec":[]}}}}"#,
    r#"{"ReInit":{"group_id":{"value":{"vec":[]}},"version":"Mls10","ciphersuite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519","extensions":{"unique":[]}}}"#,
    r#"{"ExternalInit":{"kem_output":{"vec":[]}}}"#,
    r#"{"GroupContextExtensions":{"extensions":{"unique":[]}}}"#,
    r#""SelfRemove""#,
    r#"{"Custom":{"proposal_type":0,"payload":[]}}"#,
];

const TEST_CASES_PROPOSAL_TYPE: &[&str] = &[
    r#""Add""#,
    r#""Update""#,
    r#""Remove""#,
    r#""PreSharedKey""#,
    r#""Reinit""#,
    r#""ExternalInit""#,
    r#""GroupContextExtensions""#,
    r#""SelfRemove""#,
    r#"{"Custom":20}"#,
];

struct Migration<Before, After> {
    before: Before,
    after: After,
}

impl<Before, After> Migration<Before, After>
where
    Before: for<'a> serde::Deserialize<'a>,
    After: for<'a> serde::Deserialize<'a>,
{
    fn from_str(input: &str) -> Self {
        let before: Before = serde_json::from_str(input).expect("error deserializing `before`");
        let after: After = serde_json::from_str(input).expect("error deserializing `after`");
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
                let migration = Migration::<$before, $after>::from_str(case);
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
                TEST_CASES_EXTENSION_TYPE
            );
            test_case!(
                test_extension,
                $before::prelude::Extension,
                $after::prelude::Extension,
                TEST_CASES_EXTENSION
            );
            test_case!(
                test_credential_type,
                $before::prelude::CredentialType,
                $after::prelude::CredentialType,
                TEST_CASES_CREDENTIAL_TYPE
            );
            test_case!(
                test_proposal_type,
                $before::prelude::ProposalType,
                $after::prelude::ProposalType,
                TEST_CASES_PROPOSAL_TYPE
            );

            test_case!(
                test_proposal,
                $before::prelude::Proposal,
                $after::prelude::Proposal,
                TEST_CASES_PROPOSAL
            );
        }
    };
}

// check the storage tag stability for openmls=0.7.1 => `main`
compat_tests!(test_storage_tags_0_7_1, openmls_0_7_1, openmls);
