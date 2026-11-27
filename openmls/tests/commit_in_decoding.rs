//! Decode the Commit and `FramedContentAuthData` of a real PublicMessage
//! from outside the crate, the way an application parsing a structure that
//! embeds them (such as a `SemiPrivateMessageContent`) would, and check that
//! `CommitIn` and `FramedContentAuthData` expose what they carry and
//! re-encode to the same bytes.
use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_test::openmls_test;
use test_utils::new_credential;

#[openmls_test]
fn commit_in_and_auth_data_decode_from_public_message() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap()
        .key_package()
        .to_owned();

    // Send handshake messages as PublicMessages so the Commit is readable on
    // the wire.
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &config,
        alice_credential.clone(),
    )
    .unwrap();

    let (commit, _welcome, _group_info) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .unwrap();
    let wire = commit.tls_serialize_detached().unwrap();

    // Walk the MLSMessage / PublicMessage / FramedContent header by hand,
    // using only public types, up to the Commit.
    let mut bytes: &[u8] = &wire;
    let _version = u16::tls_deserialize(&mut bytes).unwrap();
    assert_eq!(
        WireFormat::tls_deserialize(&mut bytes).unwrap(),
        WireFormat::PublicMessage
    );
    assert_eq!(
        &GroupId::tls_deserialize(&mut bytes).unwrap(),
        alice_group.group_id()
    );
    let _epoch = GroupEpoch::tls_deserialize(&mut bytes).unwrap();
    assert_eq!(
        Sender::tls_deserialize(&mut bytes).unwrap(),
        Sender::Member(alice_group.own_leaf_index())
    );
    let _authenticated_data = VLBytes::tls_deserialize(&mut bytes).unwrap();
    let content_type = ContentType::tls_deserialize(&mut bytes).unwrap();
    assert_eq!(content_type, ContentType::Commit);

    let commit_start = bytes;
    let commit_in = CommitIn::tls_deserialize(&mut bytes).unwrap();
    let commit_bytes = &commit_start[..commit_start.len() - bytes.len()];

    let auth_start = bytes;
    let auth = FramedContentAuthData::deserialize(&mut bytes, content_type).unwrap();
    let auth_bytes = &auth_start[..auth_start.len() - bytes.len()];

    // The Commit adds Bob inline and carries Alice's path.
    let proposals = commit_in.unverified_proposals();
    assert_eq!(proposals.len(), 1);
    assert!(matches!(
        &proposals[0],
        ProposalOrRefIn::Proposal(proposal) if matches!(proposal.as_ref(), ProposalIn::Add(_))
    ));
    assert_eq!(commit_in.unverified_credential(), Some(alice_credential));

    // A Commit's auth data carries a signature and a confirmation tag.
    assert!(auth.confirmation_tag().is_some());
    assert!(!auth
        .signature()
        .tls_serialize_detached()
        .unwrap()
        .is_empty());

    // Both re-encode to exactly the bytes they were decoded from.
    assert_eq!(commit_in.tls_serialize_detached().unwrap(), commit_bytes);
    assert_eq!(auth.tls_serialize_detached().unwrap(), auth_bytes);
}
