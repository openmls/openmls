use openmls_rust_crypto::OpenMlsRustCrypto;
use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::Serialize;

use crate::{
    credentials::*,
    framing::*,
    group::{errors::*, *},
    messages::{
        external_proposals::*,
        proposals::{AddProposal, Proposal, ProposalType},
    },
};

use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite};

use super::utils::*;

struct ProposalValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
}

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> MlsGroup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let credential = generate_credential_bundle(
        identity.into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    // Generate KeyPackages
    let key_package =
        generate_key_package_bundle(&[ciphersuite], &credential, vec![], backend).unwrap();

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    let kpr = key_package
        .hash_ref(backend.crypto())
        .expect("Could not hash KeyPackage.");

    MlsGroup::new_with_group_id(backend, &mls_group_config, group_id, kpr.as_slice()).unwrap()
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ProposalValidationTestSetup {
    // === Alice creates a group ===
    let mut alice_group = new_test_group("Alice", wire_format_policy, ciphersuite, backend);

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating group from welcome");

    ProposalValidationTestSetup {
        alice_group,
        bob_group,
    }
}

#[apply(ciphersuites_and_backends)]
fn external_add_proposal_should_succeed(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    for policy in WIRE_FORMAT_POLICIES {
        let ProposalValidationTestSetup {
            mut alice_group,
            mut bob_group,
        } = validation_test_setup(policy, ciphersuite, backend);

        assert_eq!(alice_group.members().unwrap().len(), 2);
        assert_eq!(bob_group.members().unwrap().len(), 2);

        // A new client, Charlie, will now ask joining with an external Add proposal
        let charlie_cb = get_credential_bundle(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .unwrap();

        let charlie_kp =
            generate_key_package_bundle(&[ciphersuite], charlie_cb.credential(), vec![], backend)
                .unwrap();

        let proposal = JoinProposal::new(
            charlie_kp.clone(),
            alice_group.group_id().clone(),
            alice_group.epoch(),
            &charlie_cb,
            backend,
        )
        .unwrap();

        // an external proposal is always plaintext and has sender type 'new_member_proposal'
        let verify_proposal = |msg: &MlsPlaintext| {
            *msg.sender() == Sender::NewMemberProposal
                && msg.content_type() == ContentType::Proposal
                && matches!(msg.content(), MlsContentBody::Proposal(p) if p.proposal_type() == ProposalType::Add)
        };
        assert!(
            matches!(proposal.mls_message.body, MlsMessageBody::Plaintext(ref msg) if verify_proposal(msg))
        );

        let msg = alice_group
            .process_message(backend, proposal.clone().into())
            .unwrap();

        match msg.into_content() {
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                assert!(matches!(proposal.sender(), Sender::NewMemberProposal));
                assert!(matches!(
                    proposal.proposal(),
                    Proposal::Add(AddProposal { key_package }) if key_package == &charlie_kp
                ));
                alice_group.store_pending_proposal(*proposal)
            }
            _ => unreachable!(),
        }

        let msg = bob_group.process_message(backend, proposal.into()).unwrap();

        match msg.into_content() {
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                bob_group.store_pending_proposal(*proposal)
            }
            _ => unreachable!(),
        }

        // and Alice will commit it
        let (commit, welcome) = alice_group.commit_to_pending_proposals(backend).unwrap();
        alice_group.merge_pending_commit().unwrap();
        assert_eq!(alice_group.members().unwrap().len(), 3);

        // Bob will also process the commit
        let msg = bob_group.process_message(backend, commit.into()).unwrap();
        match msg.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                bob_group.merge_staged_commit(*commit).unwrap()
            }
            _ => unreachable!(),
        }
        assert_eq!(bob_group.members().unwrap().len(), 3);

        // Finally, Charlie can join with the Welcome
        let cfg = MlsGroupConfig::builder().wire_format_policy(policy).build();
        let charlie_group = MlsGroup::new_from_welcome(
            backend,
            &cfg,
            welcome.unwrap(),
            Some(alice_group.export_ratchet_tree()),
        )
        .unwrap();
        assert_eq!(charlie_group.members().unwrap().len(), 3);
    }
}

#[apply(ciphersuites_and_backends)]
fn external_add_proposal_should_be_signed_by_key_package_it_references(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let ProposalValidationTestSetup {
        mut alice_group, ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let attacker_cb = get_credential_bundle(
        "Attacker".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    // A new client, Charlie, will now ask joining with an external Add proposal
    let charlie_cb = get_credential_bundle(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    let charlie_kp =
        generate_key_package_bundle(&[ciphersuite], charlie_cb.credential(), vec![], backend)
            .unwrap();

    let invalid_proposal = JoinProposal::new(
        charlie_kp,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &attacker_cb,
        backend,
    )
    .unwrap();

    // fails because the message was not signed by the same credential as the one in the Add proposal
    assert!(matches!(
        alice_group
            .process_message(backend, invalid_proposal.into())
            .unwrap_err(),
        ProcessMessageError::InvalidSignature
    ));
}

// TODO #1093: move this test to a dedicated external proposal ValSem test module once all external proposals implemented
#[apply(ciphersuites_and_backends)]
fn new_member_proposal_sender_should_be_reserved_for_join_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Add proposal can have a 'new_member_proposal' sender
    let any_credential = generate_credential_bundle(
        "Any".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    let any_credential_bundle: CredentialBundle = backend
        .key_store()
        .read(
            &any_credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Could not serialize signature key."),
        )
        .expect("Could not read signature key from key store.");

    let any_kp =
        generate_key_package_bundle(&[ciphersuite], &any_credential, vec![], backend).unwrap();

    let join_proposal = JoinProposal::new(
        any_kp,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &any_credential_bundle,
        backend,
    )
    .unwrap();

    if let MlsMessageBody::Plaintext(plaintext) = &join_proposal.mls_message.body {
        // Make sure it's an add proposal...
        assert!(matches!(
            plaintext.content(),
            MlsContentBody::Proposal(Proposal::Add(_))
        ));

        // ... and that it has the right sender type
        assert!(matches!(plaintext.sender(), Sender::NewMemberProposal));

        // Finally check that the message can be processed without errors
        assert!(bob_group
            .process_message(backend, join_proposal.into())
            .is_ok());
    } else {
        panic!()
    };
    alice_group.clear_pending_proposals();

    // Remove proposal cannot have a 'new_member_proposal' sender
    let remove_proposal = alice_group.propose_remove_member(backend, 1).unwrap();
    if let MlsMessageBody::Plaintext(mut plaintext) = remove_proposal.mls_message.body {
        plaintext.set_sender(Sender::NewMemberProposal);
        assert!(matches!(
            bob_group
                .process_message(backend, plaintext.into())
                .unwrap_err(),
            ProcessMessageError::ValidationError(ValidationError::NotAnExternalAddProposal)
        ));
    } else {
        panic!()
    };
    alice_group.clear_pending_proposals();

    // Update proposal cannot have a 'new_member_proposal' sender
    let update_proposal = alice_group.propose_self_update(backend, None).unwrap();
    if let MlsMessageBody::Plaintext(mut plaintext) = update_proposal.mls_message.body {
        plaintext.set_sender(Sender::NewMemberProposal);
        assert!(matches!(
            bob_group
                .process_message(backend, plaintext.into())
                .unwrap_err(),
            ProcessMessageError::ValidationError(ValidationError::NotAnExternalAddProposal)
        ));
    } else {
        panic!()
    };
    alice_group.clear_pending_proposals();
}
