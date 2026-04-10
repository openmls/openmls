//! This module tests the validation of commits as defined in
//! https://book.openmls.tech/message_validation.html#commit-message-validation

use openmls_traits::{
    crypto::OpenMlsCrypto, prelude::*, signatures::Signer, types::Ciphersuite, OpenMlsProvider,
};
use proposal_store::QueuedProposal;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::Signable,
    extensions::Extensions,
    framing::*,
    group::{
        tests_and_kats::utils::{
            generate_credential_with_key, generate_key_package, resign_message,
            CredentialWithKeyAndSigner,
        },
        *,
    },
    messages::proposals::*,
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::{
        errors::ApplyUpdatePathError, node::parent_node::PlainUpdatePathNode, treekem::UpdatePath,
        LeafNodeParameters,
    },
};

struct CommitValidationTestSetup {
    alice_group: MlsGroup,
    alice_credential: CredentialWithKeyAndSigner,
    bob_group: MlsGroup,
    charlie_group: MlsGroup,
}

// Validation test setup
#[maybe_async::maybe_async]
async fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    alice_provider: &impl crate::storage::OpenMlsProvider,
    bob_provider: &impl crate::storage::OpenMlsProvider,
    charlie_provider: &impl crate::storage::OpenMlsProvider,
) -> CommitValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    )
    .await;

    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    )
    .await;

    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    )
    .await;

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential,
    )
    .await;

    let charlie_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential,
    )
    .await;

    // Define the MlsGroup configuration

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        group_id,
        alice_credential.credential_with_key.clone(),
    )
    .await
    .expect("An unexpected error occurred.");

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            &[
                bob_key_package.key_package().clone(),
                charlie_key_package.key_package().clone(),
            ],
        )
        .await
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit(alice_provider)
        .await
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome.clone(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("error creating staged join from welcome")
    .into_group(bob_provider)
    .await
    .expect("error creating group from staged join");

    let charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .await
    .expect("error creating staged join from welcome")
    .into_group(charlie_provider)
    .await
    .expect("error creating group from staged join");

    CommitValidationTestSetup {
        alice_group,
        alice_credential,
        bob_group,
        charlie_group,
    }
}

// ValSem200: Commit must not cover inline self Remove proposal
#[openmls_test::openmls_test]
async fn test_valsem200() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    // Since Alice won't commit to her own removal directly, we have to create
    // proposal and commit independently and then insert the proposal into the
    // commit manually.
    let serialized_proposal_message = alice_group
        .propose_remove_member(
            alice_provider,
            &alice_credential.signer,
            alice_group.own_leaf_index(),
        )
        .await
        .expect("error creating commit")
        .tls_serialize_detached()
        .expect("serialization error");

    // Let's get the proposal out of the message.
    let proposal_message =
        MlsMessageIn::tls_deserialize(&mut serialized_proposal_message.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

    let proposal = if let FramedContentBody::Proposal(proposal) = proposal_message.content() {
        proposal.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // We have to clear the pending proposals so Alice doesn't try to commit to
    // her own remove.
    alice_group
        .clear_pending_proposals(alice_provider.storage())
        .await
        .unwrap();

    // Now let's stick it in the commit.
    let serialized_message = alice_group
        .self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .expect("Error creating self-update")
        .into_messages()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content
        .proposals
        .push(ProposalOrRef::proposal(proposal));

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");

    // We have to re-sign, since we changed the content.
    let tbs: FramedContentTbs = plaintext.into();
    let mut signed_plaintext: AuthenticatedContent = tbs
        .with_context(serialized_context)
        .sign(&alice_credential.signer)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let mut signed_plaintext: PublicMessage = signed_plaintext.into();

    let membership_key = alice_group.message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(
            alice_provider.crypto(),
            ciphersuite,
            membership_key,
            alice_group.message_secrets().serialized_context(),
        )
        .expect("error refreshing membership tag");

    // Have Bob try to process the commit.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = bob_group
        .process_message(bob_provider, message_in)
        .await
        .expect_err("Could process unverified message despite self remove.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::AttemptedSelfRemoval)
    ));

    // Positive case
    bob_group
        .process_message(bob_provider, ProtocolMessage::from(original_plaintext))
        .await
        .expect("Unexpected error.");
}
impl Proposal {
    /// Helper to create a queued proposal
    /// from a provided Proposal, where Alice is the sender.
    fn into_queued_proposal_with_alice_sender<Crypto: OpenMlsCrypto>(
        self,
        crypto: &Crypto,
        alice_group: &MlsGroup,
    ) -> QueuedProposal {
        QueuedProposal::from_proposal_and_sender(
            alice_group.ciphersuite(),
            crypto,
            self,
            &Sender::Member(alice_group.own_leaf_index()),
        )
        .unwrap()
    }
}

// ValSem201: Path must be present, if at least one proposal requires a path
#[openmls_test::openmls_test]
async fn test_valsem201() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let dave_provider = &Provider::default();

    let wire_format_policy = PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        charlie_group,
        ..
    } = validation_test_setup(
        wire_format_policy,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    /// Helper that returns a proposal to add Dave to `alice_group`
    /// using a new key package, as a QueuedProposal with Alice as the sender.
    #[maybe_async::maybe_async]
    async fn create_queued_add_proposal(
        alice_provider: &Provider,
        alice_group: &MlsGroup,
        dave_provider: &Provider,
    ) -> QueuedProposal {
        let ciphersuite = alice_group.ciphersuite();

        // create a new CredentialWithKey and KeyPackage
        let dave_credential = generate_credential_with_key(
            "Dave".into(),
            ciphersuite.signature_algorithm(),
            dave_provider,
        )
        .await;
        let dave_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            dave_provider,
            dave_credential,
        )
        .await;

        Proposal::add(AddProposal {
            key_package: dave_key_package.key_package().clone(),
        })
        .into_queued_proposal_with_alice_sender(alice_provider.crypto(), alice_group)
    }

    /// Helper that returns a new PreSharedKeyProposal as a QueuedProposal with Alice as the sender.
    #[maybe_async::maybe_async]
    async fn create_queued_psk_proposal<Provider: OpenMlsProvider>(
        alice_provider: &Provider,
        bob_provider: &Provider,
        alice_group: &MlsGroup,
    ) -> QueuedProposal {
        let ciphersuite = alice_group.ciphersuite();

        let secret = Secret::random(ciphersuite, alice_provider.rand()).unwrap();
        let rand = alice_provider
            .rand()
            .random_vec(ciphersuite.hash_length())
            .unwrap();
        let psk_id = PreSharedKeyId::new(
            ciphersuite,
            alice_provider.rand(),
            Psk::External(ExternalPsk::new(rand)),
        )
        .unwrap();
        psk_id
            .store(alice_provider, secret.as_slice())
            .await
            .unwrap();
        psk_id.store(bob_provider, secret.as_slice()).await.unwrap();
        Proposal::psk(PreSharedKeyProposal::new(psk_id))
            .into_queued_proposal_with_alice_sender(alice_provider.crypto(), alice_group)
    }

    let update_proposal = Proposal::update(UpdateProposal {
        leaf_node: alice_group
            .own_leaf()
            .expect("Unable to get own leaf")
            .clone(),
    })
    .into_queued_proposal_with_alice_sender(alice_provider.crypto(), &alice_group);

    /// Helper that returns a proposal to remove Charlie from the group
    /// as a QueuedProposal with Alice as the sender.
    fn create_queued_remove_proposal(
        alice_provider: &Provider,
        alice_group: &MlsGroup,
        charlie_leaf_index: LeafNodeIndex,
    ) -> QueuedProposal {
        Proposal::remove(RemoveProposal {
            removed: charlie_leaf_index,
        })
        .into_queued_proposal_with_alice_sender(alice_provider.crypto(), alice_group)
    }

    let group_context_extensions: Extensions<GroupContext> =
        alice_group.context().extensions().clone();
    /// Helper that returns a proposal to update the group context extensions
    /// as a QueuedProposal with Alice as the sender.
    fn create_queued_gce_proposal(
        alice_provider: &Provider,
        alice_group: &MlsGroup,
        group_context_extensions: Extensions<GroupContext>,
    ) -> QueuedProposal {
        Proposal::group_context_extensions(GroupContextExtensionProposal::new(
            group_context_extensions,
        ))
        .into_queued_proposal_with_alice_sender(alice_provider.crypto(), alice_group)
    }

    // ExternalInit Proposal cannot be used alone and has to be in an external commit which
    // always contains a path anyway
    // TODO: #916 when/if AppAck proposal are implemented (path not required)
    // TODO: #751 when ReInit proposal validation are implemented (path not required). Currently one
    // cannot distinguish when the commit has a single ReInit proposal from the commit without proposals
    // in [MlsGroup::apply_proposals()]
    let cases = Vec::from([
        (
            Vec::from([
                create_queued_add_proposal(alice_provider, &alice_group, dave_provider).await,
            ]),
            false,
        ),
        (
            Vec::from([
                create_queued_psk_proposal(alice_provider, bob_provider, &alice_group).await,
            ]),
            false,
        ),
        (vec![update_proposal.clone()], true),
        (
            vec![create_queued_remove_proposal(
                alice_provider,
                &alice_group,
                charlie_group.own_leaf_index(),
            )],
            true,
        ),
        (
            vec![create_queued_gce_proposal(
                alice_provider,
                &alice_group,
                group_context_extensions,
            )],
            true,
        ),
        // !path_required + !path_required = !path_required
        (
            Vec::from([
                create_queued_add_proposal(alice_provider, &alice_group, dave_provider).await,
                create_queued_psk_proposal(alice_provider, bob_provider, &alice_group).await,
            ]),
            false,
        ),
        // path_required + !path_required = path_required
        (
            Vec::from([
                create_queued_remove_proposal(
                    alice_provider,
                    &alice_group,
                    charlie_group.own_leaf_index(),
                ),
                create_queued_add_proposal(alice_provider, &alice_group, dave_provider).await,
            ]),
            true,
        ),
        // path_required + path_required = path_required
        (
            vec![
                update_proposal,
                create_queued_remove_proposal(
                    alice_provider,
                    &alice_group,
                    charlie_group.own_leaf_index(),
                ),
            ],
            true,
        ),
        // TODO: #566 this should work if GCE proposals validation were implemented
        // (vec![add_proposal(), gce_proposal()], true),
    ]);

    for (proposal, is_path_required) in cases {
        // create a commit containing the proposals
        for p in proposal {
            alice_group
                .store_pending_proposal(alice_provider.storage(), p.clone())
                .await
                .unwrap();
        }

        let commit = alice_group
            .commit_builder()
            .force_self_update(false)
            .load_psks(alice_provider.storage())
            .await
            .unwrap()
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_credential.signer,
                |_| true,
            )
            .unwrap()
            .commit_result()
            .commit;

        // verify that path can be omitted in some situations
        if let FramedContentBody::Commit(commit) = commit.content() {
            assert_eq!(commit.has_path(), is_path_required);
        } else {
            panic!()
        };

        let mut commit: PublicMessage = commit.into();
        let membership_key = alice_group.message_secrets().membership_key();
        commit
            .set_membership_tag(
                alice_provider.crypto(),
                ciphersuite,
                membership_key,
                alice_group.message_secrets().serialized_context(),
            )
            .unwrap();
        // verify that a path is indeed required when the commit is received
        if is_path_required {
            let commit_wo_path = erase_path(
                alice_provider,
                ciphersuite,
                commit.clone(),
                &alice_group,
                &alice_credential.signer,
            );
            let processed_msg = bob_group
                .process_message(bob_provider, commit_wo_path)
                .await;
            assert!(matches!(
                processed_msg.unwrap_err(),
                ProcessMessageError::InvalidCommit(StageCommitError::RequiredPathNotFound)
            ));
        }

        // Positive case
        let process_message_result = bob_group.process_message(bob_provider, commit).await;
        assert!(process_message_result.is_ok(), "{process_message_result:?}");

        // cleanup & restore for next iteration
        alice_group
            .clear_pending_proposals(alice_provider.storage())
            .await
            .unwrap();
        alice_group
            .clear_pending_commit(alice_provider.storage())
            .await
            .unwrap();
        bob_group
            .clear_pending_commit(bob_provider.storage())
            .await
            .unwrap();
    }
}

fn erase_path(
    provider: &impl crate::storage::OpenMlsProvider,
    ciphersuite: Ciphersuite,
    mut plaintext: PublicMessage,
    alice_group: &MlsGroup,
    alice_signer: &impl Signer,
) -> ProtocolMessage {
    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };
    commit_content.path = None;

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let plaintext = resign_message(
        alice_group,
        plaintext,
        &original_plaintext,
        provider,
        alice_signer,
        ciphersuite,
    );

    plaintext.into()
}

// ValSem202: Path must be the right length
#[openmls_test::openmls_test]
async fn test_valsem202() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    // Have Alice generate a self-updating commit, remove a node from the path,
    // re-sign and have Bob process it.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .expect("Error creating self-update")
        .into_messages()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };
    if let Some(ref mut path) = commit_content.path {
        path.pop();
    };

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let plaintext = resign_message(
        &alice_group,
        plaintext,
        &original_plaintext,
        alice_provider,
        &alice_credential.signer,
        ciphersuite,
    );

    let update_message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(bob_provider, update_message_in)
        .await
        .expect_err("Could process unverified message despite path length mismatch.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::PathLengthMismatch
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            bob_provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .await
        .expect("Unexpected error.");
}

// ValSem203: Path secrets must decrypt correctly
#[openmls_test::openmls_test]
async fn test_valsem203() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    // Set up test framework

    // Have Alice generate a self-updating commit, scramble some ciphertexts and
    // have Bob process the resulting commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .expect("Error creating self-update")
        .into_messages()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // This should cause decryption to fail.
    if let Some(ref mut path) = commit_content.path {
        path.flip_eps_bytes();
    };

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let plaintext = resign_message(
        &alice_group,
        plaintext,
        &original_plaintext,
        alice_provider,
        &alice_credential.signer,
        ciphersuite,
    );

    let update_message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(bob_provider, update_message_in)
        .await
        .expect_err("Could process unverified message despite scrambled ciphertexts.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::UnableToDecrypt
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            bob_provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .await
        .expect("Unexpected error.");
}

// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
#[openmls_test::openmls_test]
async fn test_valsem204() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        mut charlie_group,
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    // Have Alice generate a self-updating commit, flip the last byte of one of
    // the public keys in the path and have Bob process the commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .expect("Error creating self-update")
        .into_messages()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Let's piece together a context that we can use for decryption.
    // Let Charlie process the commit, so we can pull the post-merge tree hash
    // from them.
    let message = charlie_group
        .process_message(charlie_provider, original_plaintext.clone())
        .await
        .unwrap();
    match message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => charlie_group
            .merge_staged_commit(charlie_provider, *staged_commit)
            .await
            .unwrap(),
        _ => panic!("Unexpected message type."),
    }
    let mut encryption_context = alice_group.export_group_context().clone();
    let post_merge_tree_hash = charlie_group.export_group_context().tree_hash().to_vec();
    // We want a context, where everything is post-merge except the confirmed transcript hash.
    encryption_context.increment_epoch();
    encryption_context.update_tree_hash(post_merge_tree_hash);

    // We want to fail the check for public key equality, but we don't want to
    // invalidate the parent hash. So we'll have to encrypt new secrets. The
    // public keys derived from those secrets will then differ from the public
    // keys in the update path, thus causing the error.
    if let Some(ref mut path) = commit_content.path {
        let new_plain_path: Vec<PlainUpdatePathNode> = path
            .nodes()
            .iter()
            .map(|upn| {
                PlainUpdatePathNode::new(
                    upn.encryption_key().clone(),
                    Secret::random(ciphersuite, alice_provider.rand())
                        .unwrap()
                        .into(),
                )
            })
            .collect();
        let new_nodes = alice_group
            .public_group()
            .encrypt_path(
                alice_provider,
                ciphersuite,
                &new_plain_path,
                &encryption_context.tls_serialize_detached().unwrap(),
                &[].into(),
                LeafNodeIndex::new(0),
            )
            .unwrap();
        let new_path = UpdatePath::new(path.leaf_node().clone(), new_nodes);
        commit_content.path = Some(new_path);
    };

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let plaintext = resign_message(
        &alice_group,
        plaintext,
        &original_plaintext,
        alice_provider,
        &alice_credential.signer,
        ciphersuite,
    );

    let update_message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(bob_provider, update_message_in)
        .await
        .expect_err("Could process unverified message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::PathMismatch
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            bob_provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .await
        .expect("Unexpected error.");
}

// ValSem205: Confirmation tag must be successfully verified
#[openmls_test::openmls_test]
async fn test_valsem205() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    // Have Alice generate a self-updating commit, flip the last bit of the
    // confirmation tag and have Bob process the commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .expect("Error creating self-update")
        .into_messages()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut new_confirmation_tag = plaintext
        .confirmation_tag()
        .expect("no confirmation tag on commit")
        .clone();

    new_confirmation_tag.0.flip_last_byte();

    plaintext.set_confirmation_tag(Some(new_confirmation_tag));

    // Since the membership tag covers the confirmation tag, we have to refresh it.
    let membership_key = alice_group.message_secrets().membership_key();

    plaintext
        .set_membership_tag(
            alice_provider.crypto(),
            ciphersuite,
            membership_key,
            alice_group.message_secrets().serialized_context(),
        )
        .expect("error refreshing membership tag");

    let update_message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(bob_provider, update_message_in)
        .await
        .expect_err("Could process unverified message despite confirmation tag mismatch.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ConfirmationTagMismatch)
    ));

    // Positive case
    bob_group
        .process_message(bob_provider, ProtocolMessage::from(original_plaintext))
        .await
        .expect("Unexpected error.");
}

// this ensures that a member can process commits not containing all the stored proposals
#[openmls_test::openmls_test]
async fn test_partial_proposal_commit() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Test with PublicMessage
    let CommitValidationTestSetup {
        mut alice_group,
        alice_credential,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        charlie_provider,
    )
    .await;

    let charlie_index = alice_group
        .members()
        .find(|m| m.credential.serialized_content() == b"Charlie")
        .unwrap()
        .index;

    // Create first proposal in Alice's group
    let proposal_1 = alice_group
        .propose_remove_member(alice_provider, &alice_credential.signer, charlie_index)
        .await
        .map(|(out, _)| MlsMessageIn::from(out))
        .unwrap();
    let proposal_1 = bob_group
        .process_message(
            bob_provider,
            proposal_1.try_into_protocol_message().unwrap(),
        )
        .await
        .unwrap();
    match proposal_1.into_content() {
        ProcessedMessageContent::ProposalMessage(p) => bob_group
            .store_pending_proposal(bob_provider.storage(), *p)
            .await
            .unwrap(),
        _ => unreachable!(),
    }

    // Create second proposal in Alice's group
    let proposal_2 = alice_group
        .propose_self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .await
        .map(|(out, _)| MlsMessageIn::from(out))
        .unwrap();
    let proposal_2 = bob_group
        .process_message(
            bob_provider,
            proposal_2.try_into_protocol_message().unwrap(),
        )
        .await
        .unwrap();
    match proposal_2.into_content() {
        ProcessedMessageContent::ProposalMessage(p) => bob_group
            .store_pending_proposal(bob_provider.storage(), *p)
            .await
            .unwrap(),
        _ => unreachable!(),
    }

    // Alice creates a commit with only a subset of the epoch's proposals. Bob should still be able to process it.
    let remaining_proposal = alice_group
        .proposal_store()
        .proposals()
        .next()
        .cloned()
        .unwrap();
    alice_group.proposal_store_mut().empty();
    alice_group.proposal_store_mut().add(remaining_proposal);
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_credential.signer)
        .await
        .unwrap();
    // Alice herself should be able to merge the commit
    alice_group
        .merge_pending_commit(alice_provider)
        .await
        .expect("Commits with partial proposals are not supported");

    // Bob should be able to process the commit
    bob_group
        .process_message(bob_provider, commit.into_protocol_message().unwrap())
        .await
        .expect("Commits with partial proposals are not supported");
    bob_group
        .merge_pending_commit(bob_provider)
        .await
        .expect("Commits with partial proposals are not supported");
}
