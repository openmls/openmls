use tls_codec::{Deserialize, Serialize};

use crate::{
    extensions::Extensions,
    group::GroupId,
    messages::{PreSharedKeyProposal, ProtocolVersion, ReInitProposal},
    schedule::psk::{ExternalPsk, PreSharedKeyId, Psk, ResumptionPsk, ResumptionPskUsage},
    test_utils::*,
};

/// Test the encoding for PreSharedKeyProposal, that also covers some of the
/// other PSK-related structs
#[openmls_test::openmls_test]
fn test_pre_shared_key_proposal_codec() {
    // External
    let psk = PreSharedKeyId {
        psk: Psk::External(ExternalPsk::new(vec![1, 2, 3])),
        psk_nonce: vec![4, 5, 6].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);

    // Resumption/Application
    let psk = PreSharedKeyId {
        psk: Psk::Resumption(ResumptionPsk::new(
            ResumptionPskUsage::Application,
            GroupId::random(provider.rand()),
            1234.into(),
        )),
        psk_nonce: vec![1, 2, 3].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);

    // Resumption/Reinit
    let psk = PreSharedKeyId {
        psk: Psk::Resumption(ResumptionPsk::new(
            ResumptionPskUsage::Reinit,
            GroupId::random(provider.rand()),
            1234.into(),
        )),
        psk_nonce: vec![1, 2, 3].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);

    // Resumption/Branch
    let psk = PreSharedKeyId {
        psk: Psk::Resumption(ResumptionPsk::new(
            ResumptionPskUsage::Branch,
            GroupId::random(provider.rand()),
            1234.into(),
        )),
        psk_nonce: vec![1, 2, 3].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);
}
/// Test the encoding for ReInitProposal, that also covers some of the
/// other PSK-related structs
#[openmls_test::openmls_test]
fn test_reinit_proposal_codec() {
    let orig = ReInitProposal {
        group_id: GroupId::random(provider.rand()),
        version: ProtocolVersion::default(),
        ciphersuite,
        extensions: Extensions::empty(),
    };
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ReInitProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);
}
