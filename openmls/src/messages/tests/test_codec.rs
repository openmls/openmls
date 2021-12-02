use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::{
    config::Config,
    group::{GroupEpoch, GroupId},
    messages::{PreSharedKeyProposal, ProtocolVersion, ReInitProposal},
    schedule::psk::{BranchPsk, ExternalPsk, PreSharedKeyId, Psk, PskType, ReinitPsk},
};

/// Test the encoding for PreSharedKeyProposal, that also covers some of the
/// other PSK-related structs
#[test]
fn test_pre_shared_key_proposal_codec() {
    let crypto = OpenMlsRustCrypto::default();
    // ReInit
    let psk = PreSharedKeyId {
        psk_type: PskType::Reinit,
        psk: Psk::Reinit(ReinitPsk {
            psk_group_id: GroupId::random(&crypto),
            psk_epoch: GroupEpoch(1234),
        }),
        psk_nonce: vec![1, 2, 3].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);

    // External
    let psk = PreSharedKeyId {
        psk_type: PskType::External,
        psk: Psk::External(ExternalPsk::new(vec![4, 5, 6])),
        psk_nonce: vec![1, 2, 3].into(),
    };
    let orig = PreSharedKeyProposal::new(psk);
    let encoded = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = PreSharedKeyProposal::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(decoded, orig);

    // Branch
    let psk = PreSharedKeyId {
        psk_type: PskType::Branch,
        psk: Psk::Branch(BranchPsk {
            psk_group_id: GroupId::random(&crypto),
            psk_epoch: GroupEpoch(1234),
        }),
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
#[test]
fn test_reinit_proposal_codec() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let orig = ReInitProposal {
            group_id: GroupId::random(&crypto),
            version: ProtocolVersion::default(),
            ciphersuite: *ciphersuite_name,
            extensions: vec![].into(),
        };
        let encoded = orig
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
        let decoded = ReInitProposal::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred.");
        assert_eq!(decoded, orig);
    }
}
