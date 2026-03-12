use mls_group::tests_and_kats::utils::setup_client;
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::types::Ciphersuite;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{
    ciphersuite::hash_ref::ProposalRef,
    credentials::CredentialWithKey,
    framing::*,
    group::*,
    key_packages::{errors::KeyPackageVerifyError, *},
    messages::group_info::GroupInfo,
    test_utils::frankenstein::{self, FrankenMlsMessage},
    treesync::{
        errors::LeafNodeValidationError, node::leaf_node::Capabilities, LeafNodeParameters,
    },
};

/// The state of a group member: A PartyState and the corresponding MlsGroup.
struct MemberState<Provider> {
    party: PartyState<Provider>,
    group: MlsGroup,
}

/// The state of a party that is not part of any groups.
#[allow(dead_code)]
struct PartyState<Provider> {
    provider: Provider,
    credential_with_key: CredentialWithKey,
    key_package_bundle: KeyPackageBundle,
    signer: SignatureKeyPair,
    sig_pk: OpenMlsSignaturePublicKey,
    name: &'static str,
}

impl<Provider: crate::storage::OpenMlsProvider + Default> PartyState<Provider> {
    /// Generate the PartyState for a new identity.
    fn generate(name: &'static str, ciphersuite: Ciphersuite) -> Self {
        let provider = Provider::default();
        let (credential_with_key, key_package_bundle, signer, sig_pk) =
            setup_client(name, ciphersuite, &provider);

        PartyState {
            provider,
            name,
            credential_with_key,
            key_package_bundle,
            signer,
            sig_pk,
        }
    }

    /// Generate a new [`KeyPackage`] for the party.
    fn key_package<F: FnOnce(KeyPackageBuilder) -> KeyPackageBuilder>(
        &self,
        ciphersuite: Ciphersuite,
        f: F,
    ) -> KeyPackageBundle {
        f(KeyPackage::builder())
            .build(
                ciphersuite,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap_or_else(|err| panic!("failed to build key package at {}: {err}", self.name))
    }
}

struct TestState<Provider> {
    alice: MemberState<Provider>,
    bob: MemberState<Provider>,
}

/// Sets up a group with two parties Alice and Bob, where Alice has capabilities for unknown
/// extensions 0xf001 and  0xf002, and Bob has capabilities for extension 0xf001, 0xf002 and
/// 0xf003.
fn setup<Provider: crate::storage::OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
) -> TestState<Provider> {
    let alice_party = PartyState::generate("alice", ciphersuite);
    let bob_party = PartyState::generate("bob", ciphersuite);

    // === Alice creates a group ===
    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .with_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                ])
                .build(),
        )
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    let mut alice = MemberState {
        party: alice_party,
        group: alice_group,
    };

    // === Alice adds Bob ===
    let bob_key_package = bob_party.key_package(ciphersuite, |builder| {
        builder.leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
    });

    alice.propose_add_member(bob_key_package.key_package());
    let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
        panic!("expected receiving a welcome")
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice.group.configuration(),
        welcome,
        Some(alice.group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_party.provider)
    .expect("Error creating group from staged join");

    TestState {
        alice,
        bob: MemberState {
            party: bob_party,
            group: bob_group,
        },
    }
}

impl<Provider: crate::storage::OpenMlsProvider> MemberState<Provider> {
    /// Thin wrapper around [`MlsGroup::propose_group_context_extensions`].
    fn propose_group_context_extensions(
        &mut self,
        extensions: Extensions<GroupContext>,
    ) -> (MlsMessageOut, ProposalRef) {
        self.group
            .propose_group_context_extensions(&self.party.provider, extensions, &self.party.signer)
            .unwrap_or_else(|err| panic!("couldn't propose GCE at {}: {err}", self.party.name))
    }

    /// Thin wrapper around [`MlsGroup::update_group_context_extensions`].
    fn update_group_context_extensions(
        &mut self,
        extensions: Extensions<GroupContext>,
    ) -> (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>) {
        self.group
            .update_group_context_extensions(&self.party.provider, extensions, &self.party.signer)
            .unwrap_or_else(|err| panic!("couldn't propose GCE at {}: {err}", self.party.name))
    }

    /// Thin wrapper around [`MlsGroup::propose_add_member`].
    fn propose_add_member(&mut self, key_package: &KeyPackage) -> (MlsMessageOut, ProposalRef) {
        self.group
            .propose_add_member(&self.party.provider, &self.party.signer, key_package)
            .unwrap_or_else(|err| panic!("failed to propose member at {}: {err}", self.party.name))
    }

    /// Wrapper around [`MlsGroup::process_message`], asserting it's a commit and [`MlsGroup::merge_staged_commit`].
    fn process_and_merge_commit(&mut self, msg: MlsMessageIn) {
        let msg = msg.into_protocol_message().unwrap();

        let processed_msg = self
            .group
            .process_message(&self.party.provider, msg)
            .unwrap_or_else(|err| panic!("error processing message at {}: {err}", self.party.name));

        match processed_msg.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => self
                .group
                .merge_staged_commit(&self.party.provider, *staged_commit)
                .unwrap_or_else(|err| {
                    panic!("error merging staged commit at {}: {err}", self.party.name)
                }),

            other => {
                panic!(
                    "expected a commit message at {}, got {:?}",
                    self.party.name, other
                )
            }
        }
    }

    /// Wrapper around [`MlsGroup::process_message`], asserting it's a proposal and [`MlsGroup::store_pending_proposal`].
    fn process_and_store_proposal(&mut self, msg: MlsMessageIn) -> ProposalRef {
        let msg = msg.into_protocol_message().unwrap();

        let processed_msg = self
            .group
            .process_message(&self.party.provider, msg)
            .unwrap_or_else(|err| panic!("error processing message at {}: {err}", self.party.name));

        match processed_msg.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal) => {
                let reference = proposal.proposal_reference();

                self.group
                    .store_pending_proposal(self.party.provider.storage(), *proposal)
                    .unwrap_or_else(|err| {
                        panic!("error storing proposal at {}: {err}", self.party.name)
                    });

                reference
            }
            other => {
                panic!(
                    "expected a proposal message at {}, got {:?}",
                    self.party.name, other
                )
            }
        }
    }

    /// This wrapper that expects [`MlsGroup::process_message`] to return an error.
    fn fail_processing(
        &mut self,
        msg: MlsMessageIn,
    ) -> ProcessMessageError<Provider::StorageError> {
        let msg = msg.into_protocol_message().unwrap();
        let err_msg = format!(
            "expected an error when processing message at {}",
            self.party.name
        );

        self.group
            .process_message(&self.party.provider, msg)
            .expect_err(&err_msg)
    }

    /// This wrapper around [`MlsGroup::commit_to_pending_proposals`]
    fn commit_to_pending_proposals(
        &mut self,
    ) -> (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>) {
        self.group
            .commit_to_pending_proposals(&self.party.provider, &self.party.signer)
            .unwrap_or_else(|err| {
                panic!(
                    "{} couldn't commit pending proposal: {err}",
                    self.party.name
                )
            })
    }

    /// This wrapper around [`MlsGroup::merge_pending_commit`]
    fn merge_pending_commit(&mut self) {
        self.group
            .merge_pending_commit(&self.party.provider)
            .unwrap_or_else(|err| panic!("{} couldn't merge commit: {err}", self.party.name));
    }

    /// Wrapper around [`MlsGroup::commit_to_pending_proposals`] and [`MlsGroup::merge_pending_commit`].
    fn commit_and_merge_pending(
        &mut self,
    ) -> (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>) {
        let commit_out = self.commit_to_pending_proposals();
        self.merge_pending_commit();
        commit_out
    }
}

/// Test that the happy case of group context extensions works
/// 1. set up group
/// 2. alice sets gce, commits
#[openmls_test]
fn happy_case() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    // make extension with type 0xf001 a required capability
    let (commit, _, _) = alice.update_group_context_extensions(
        Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
        ))
        .expect("failed to create single-element extensions list"),
    );

    alice.merge_pending_commit();
    bob.process_and_merge_commit(commit.into());

    // make extensions with type 0xf001 0xf002 a required capability, too;
    // this time with a separate proposal
    let (proposal, _) = bob.propose_group_context_extensions(
        Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &[
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                ],
                &[],
                &[],
            ),
        ))
        .expect("failed to create single-element extensions list"),
    );

    alice.process_and_store_proposal(proposal.into());

    let (commit, _, _) = alice.commit_and_merge_pending();
    bob.process_and_merge_commit(commit.into());
}

#[openmls_test]
fn self_update_happy_case() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    let (update_prop, _) = bob
        .group
        .propose_self_update(
            &bob.party.provider,
            &bob.party.signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();
    alice.process_and_store_proposal(update_prop.into());
    let (commit, _, _) = alice.commit_and_merge_pending();
    bob.process_and_merge_commit(commit.into())
}

/// This test does the same as self_update_happy_case, but does not use MemberState, so we can
/// can exactly see which calls to OpenMLS are done
#[openmls_test]
fn self_update_happy_case_simple() {
    let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
    let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    // === Alice adds Bob ===
    let bob_key_package = bob_party.key_package(ciphersuite, |builder| builder);

    alice_group
        .propose_add_member(
            &alice_party.provider,
            &alice_party.signer,
            bob_key_package.key_package(),
        )
        .unwrap();

    let (_, Some(welcome), _) = alice_group
        .commit_to_pending_proposals(&alice_party.provider, &alice_party.signer)
        .unwrap()
    else {
        panic!("expected receiving a welcome")
    };

    alice_group
        .merge_pending_commit(&alice_party.provider)
        .unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice_group.configuration(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_party.provider)
    .expect("Error creating group from staged join");

    let (update_proposal_msg, _) = bob_group
        .propose_self_update(
            &bob_party.provider,
            &bob_party.signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(update_proposal) = alice_group
        .process_message(
            &alice_party.provider,
            update_proposal_msg.clone().into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    else {
        panic!("expected a proposal, got {update_proposal_msg:?}");
    };
    alice_group
        .store_pending_proposal(alice_party.provider.storage(), *update_proposal)
        .unwrap();

    let (commit_msg, _, _) = alice_group
        .commit_to_pending_proposals(&alice_party.provider, &alice_party.signer)
        .unwrap();

    bob_group
        .process_message(
            &bob_party.provider,
            commit_msg.into_protocol_message().unwrap(),
        )
        .unwrap();

    bob_group.merge_pending_commit(&bob_party.provider).unwrap()
}

/// This tests makes sure that validation check 103 is performed:
///
///   Verify that the LeafNode is compatible with the group's parameters.
///   If the GroupContext has a required_capabilities extension, then the
///   required extensions, proposals, and credential types MUST be listed
///   in the LeafNode's capabilities field.
///
/// So far, we only test whether the check is done for extension types.
/// https://validation.openmls.tech/#valn0103
#[openmls_test]
fn fail_insufficient_extensiontype_capabilities_add_valn0103() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    let (gce_req_cap_commit, _, _) = alice.update_group_context_extensions(
        Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf002)], &[], &[]),
        ))
        .expect("failed to create single-element extensions list"),
    );

    alice.merge_pending_commit();
    bob.process_and_merge_commit(gce_req_cap_commit.clone().into());

    // extract values we need later
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content:
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch: gce_commit_epoch,
                        sender,
                        authenticated_data,
                        ..
                    },
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(gce_req_cap_commit)
    else {
        unreachable!()
    };

    let charlie = PartyState::<Provider>::generate("charlie", ciphersuite);
    let charlie_kpb = charlie.key_package(ciphersuite, |builder| {
        builder.leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::Unknown(0xf001)])
                .build(),
        )
    });

    let commit_content = frankenstein::FrankenFramedContent {
        body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
            proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                frankenstein::FrankenProposal::Add(frankenstein::FrankenAddProposal {
                    key_package: charlie_kpb.key_package.into(),
                }),
            )],
            path: None,
        }),
        group_id,
        epoch: gce_commit_epoch + 1,
        sender,
        authenticated_data,
    };

    let group_context = alice.group.export_group_context().clone();

    let bob_group_context = bob.group.export_group_context();
    assert_eq!(
        bob_group_context.confirmed_transcript_hash(),
        group_context.confirmed_transcript_hash()
    );

    let secrets = alice.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice.party.provider,
                ciphersuite,
                &alice.party.signer,
                commit_content,
                Some(&group_context.into()),
                Some(membership_key),
                // this is a dummy confirmation_tag:
                Some(vec![0u8; 32].into()),
            ),
        ),
    };

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    // Note: If this starts failing, the order in which validation is checked may have changed and we
    // fail on the fact that the confirmation tag is wrong. in that case, either the check has to be
    // disabled, or the frankenstein framework needs code to properly compute it.
    let err = bob.fail_processing(fake_commit);
    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::LeafNodeValidation(
                    LeafNodeValidationError::UnsupportedExtensions
                )
            ))
        ),
        "got wrong error: {err:#?}"
    );
}

// Test structure:
// - (alice creates group, adds bob, bob accepts)
//   - This is part of the setup function
// - alice proposal GCE with required capabilities and commits
// - bob adds the proposal and merges the commit
// - bob proposes a self-update, but we tamper with it by removing
//   an extension type from the capabilities. This makes it invalid.
// - we craft a commit by alice, committing the invalid proposal
//   - it can't be done by bob, because the sender of a commit
//     containing an update proposal can not be the owner of the
//     leaf node
// - bob processes the invalid commit, which should give an InsufficientCapabilities error
// https://validation.openmls.tech/#valn0103
#[openmls_test]
fn fail_insufficient_extensiontype_capabilities_update_valn0103() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    // requires that all members need support for extension type 0xf002
    let (gce_req_cap_commit, _, _) = alice.update_group_context_extensions(
        Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf002)], &[], &[]),
        ))
        .expect("failed to create single-element extensions list"),
    );

    alice.merge_pending_commit();
    bob.process_and_merge_commit(gce_req_cap_commit.clone().into());

    // let bob propose an update to their leaf node.
    // we immediately discard it, because we want to tamper with it.
    let (update_prop, _) = bob
        .group
        .propose_self_update(
            &bob.party.provider,
            &bob.party.signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();
    bob.group
        .clear_pending_proposals(bob.party.provider.storage())
        .unwrap();

    // extract the FramedContent from the proposal MlsMessage, because that is
    // what we'll have to pass into the `FrankenPublicMessage::auth` method later.
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content: mut franken_proposal_content,
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(update_prop.clone())
    else {
        unreachable!()
    };

    // we want to change the leaf node in the update proposal, so let's get a mutable borrow on that
    let frankenstein::FrankenFramedContent {
        body:
            frankenstein::FrankenFramedContentBody::Proposal(frankenstein::FrankenProposal::Update(
                frankenstein::FrankenUpdateProposal {
                    leaf_node: bob_franken_leaf_node,
                },
            )),
        ..
    } = &mut franken_proposal_content
    else {
        unreachable!();
    };

    // Remove the extension type from the capabilities that is part of required capabilities
    // Committing this would be illegal
    assert_eq!(
        bob_franken_leaf_node.capabilities.extensions.remove(1),
        0xf002
    );

    // Re-sign the leaf node so the signature checks pass
    bob_franken_leaf_node.resign(
        Some(frankenstein::FrankenTreePosition {
            group_id: bob.group.group_id().as_slice().to_vec().into(),
            leaf_index: bob.group.own_leaf_index().u32(),
        }),
        &bob.party.signer,
    );

    // prepare data needed for proposal
    let group_context = bob.group.export_group_context().clone();
    let secrets = bob.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    // build MlsMessage containing the proposal
    let franken_proposal = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &bob.party.provider,
                ciphersuite,
                &bob.party.signer,
                franken_proposal_content.clone(),
                Some(&group_context.into()),
                Some(membership_key),
                // proposals don't have confirmation tags
                None,
            ),
        ),
    };
    let fake_proposal = MlsMessageIn::tls_deserialize(
        &mut franken_proposal
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    // alice stores the proposal.
    alice.process_and_store_proposal(fake_proposal.clone());

    // Now we'll craft a commit to the proposal signed by alice.
    // For that we need a few values, let's fetch and build them.
    let proposal_ref = bob.process_and_store_proposal(fake_proposal);
    let alice_sender = frankenstein::FrankenSender::Member(0);

    // This is a commit, claimed to be from alice, that commits to the proposal ref of the invalid proposal
    let commit_content = frankenstein::FrankenFramedContent {
        sender: alice_sender,
        body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
            proposals: vec![frankenstein::FrankenProposalOrRef::Reference(
                proposal_ref.as_slice().to_vec().into(),
            )],
            path: None,
        }),

        ..franken_proposal_content
    };

    // prepare data needed for making the message authentic
    let group_context = alice.group.export_group_context().clone();
    let secrets = alice.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice.party.provider,
                ciphersuite,
                &alice.party.signer,
                commit_content,
                Some(&group_context.into()),
                Some(membership_key),
                Some(vec![0; 32].into()),
            ),
        ),
    };
    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    // when bob processes the commit, it should fail because the leaf node's capabilties do not
    // satisfy those required by the group.
    let err = bob.fail_processing(fake_commit);

    // Note: If this starts failing, the order in which validation is checked may have changed and we
    // fail on the fact that the confirmation tag is wrong. in that case, either the check has to be
    // disabled, or the frankenstein framework yet yet needs code to properly commpute it.
    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::InsufficientCapabilities
            ))
        ),
        "expected a different error, got: {err} ({err:#?})"
    );
}

// This test doesn't belong here, but it's nice to have. It would be nice to factor it out, but
// it relies on the testing functions.
//
// I suppose we need to talk about which test framework is the one we need.
// See https://github.com/openmls/openmls/issues/1618.
// https://validation.openmls.tech/#valn0201
#[openmls_test]
fn fail_key_package_version_valn0201() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    let charlie = PartyState::<Provider>::generate("charlie", ciphersuite);
    let charlie_key_package_bundle = charlie.key_package(ciphersuite, |b| b);
    let charlie_key_package = charlie_key_package_bundle.key_package();

    let (original_proposal, _) = alice.propose_add_member(charlie_key_package);

    alice
        .group
        .clear_pending_proposals(alice.party.provider.storage())
        .unwrap();

    let Ok(frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content:
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch,
                        sender,
                        authenticated_data,
                        body:
                            frankenstein::FrankenFramedContentBody::Proposal(
                                frankenstein::FrankenProposal::Add(
                                    frankenstein::FrankenAddProposal { mut key_package },
                                ),
                            ),
                    },
                ..
            }),
    }) = frankenstein::FrankenMlsMessage::tls_deserialize(
        &mut original_proposal
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    else {
        panic!("proposal message has unexpected format: {original_proposal:#?}")
    };

    key_package.protocol_version = 2;
    key_package.resign(&charlie.signer);

    let group_context = alice.group.export_group_context();
    let membership_key = alice.group.message_secrets().membership_key();

    let franken_commit_message = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice.party.provider,
                ciphersuite,
                &alice.party.signer,
                frankenstein::FrankenFramedContent {
                    group_id,
                    epoch,
                    sender,
                    authenticated_data,
                    body: frankenstein::FrankenFramedContentBody::Commit(
                        frankenstein::FrankenCommit {
                            proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                                frankenstein::FrankenProposal::Add(
                                    frankenstein::FrankenAddProposal { key_package },
                                ),
                            )],
                            path: None,
                        },
                    ),
                },
                Some(&group_context.clone().into()),
                Some(membership_key.as_slice()),
                // dummy value
                Some(vec![0; 32].into()),
            ),
        ),
    };

    let fake_commit_message = MlsMessageIn::tls_deserialize(
        &mut franken_commit_message
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let err = {
        let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
        validation_skip_handle.with_disabled(|| bob.fail_processing(fake_commit_message.clone()))
    };

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::InvalidProtocolVersion
        ))
    ));
}

// This tests that a commit containing more than one GCE Proposals does not pass validation.
// https://validation.openmls.tech/#valn0308
#[openmls_test]
fn fail_2_gce_proposals_1_commit_valn0308() {
    let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

    // No required capabilities, so no specifically required extensions.
    assert!(alice
        .group
        .context()
        .extensions()
        .required_capabilities()
        .is_none());

    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    let (proposal, _) = alice.propose_group_context_extensions(new_extensions.clone());
    bob.process_and_store_proposal(proposal.into());

    assert_eq!(alice.group.pending_proposals().count(), 1);

    let (commit, _, _) = alice.commit_to_pending_proposals();

    // we'll change the commit we feed to bob to include two GCE proposals
    let mut franken_commit = FrankenMlsMessage::tls_deserialize(
        &mut commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    // Craft a commit that has two GroupContextExtension proposals. This is forbidden by the RFC.
    // Change the commit before alice commits, so alice's state is still in the old epoch and we can
    // use her state to forge the macs and signatures
    match &mut franken_commit.body {
        frankenstein::FrankenMlsMessageBody::PublicMessage(msg) => {
            match &mut msg.content.body {
                frankenstein::FrankenFramedContentBody::Commit(commit) => {
                    let second_gces = frankenstein::FrankenProposalOrRef::Proposal(
                        frankenstein::FrankenProposal::GroupContextExtensions(vec![
                            // ideally this should be some unknown extension, but it's tricky
                            // to get the payload set up correctly so we'll just go with this
                            frankenstein::FrankenExtension::RequiredCapabilities(
                                frankenstein::FrankenRequiredCapabilitiesExtension {
                                    extension_types: vec![],
                                    proposal_types: vec![],
                                    credential_types: vec![],
                                },
                            ),
                        ]),
                    );

                    commit.proposals.push(second_gces);
                }
                _ => unreachable!(),
            }

            let group_context = alice.group.export_group_context().clone();

            let bob_group_context = bob.group.export_group_context();
            assert_eq!(
                bob_group_context.confirmed_transcript_hash(),
                group_context.confirmed_transcript_hash()
            );

            let secrets = alice.group.message_secrets();
            let membership_key = secrets.membership_key().as_slice();

            *msg = frankenstein::FrankenPublicMessage::auth(
                &alice.party.provider,
                group_context.ciphersuite(),
                &alice.party.signer,
                msg.content.clone(),
                Some(&group_context.into()),
                Some(membership_key),
                // this is a dummy confirmation_tag:
                Some(vec![0u8; 32].into()),
            );
        }
        _ => unreachable!(),
    }

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    let err = {
        let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
        validation_skip_handle.with_disabled(|| bob.fail_processing(fake_commit.clone()))
    };

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(
            StageCommitError::GroupContextExtensionsProposalValidationError(
                GroupContextExtensionsProposalValidationError::TooManyGCEProposals
            )
        )
    ));
}

/// This test makes sure that a commit to a GCE proposal with required_capabilities that are
/// not satisfied by all members' capabilities does not pass validation.
///
// Test structure:
// - (alice creates group, adds bob, bob accepts)
//   - This is part of the setup function
// - bob proposes updating the GC to have required_capabilities with extensions 0xf001
//   - both alice and bob support this extension
// - we modify the proposal and add 0xf003 - this is only supported by bob (see setup function)
// - we craft a commit to the proposal, signed by bob
// - alice processes the commit expecting an error, and the error should be that the GCE is
//   invalid
// https://validation.openmls.tech/#valn1001
#[openmls_test]
fn fail_unsupported_gces_add_valn1001() {
    let TestState { mut alice, mut bob }: TestState<Provider> = setup(ciphersuite);

    // No required capabilities, so no specifically required extensions.
    assert!(alice
        .group
        .context()
        .extensions()
        .required_capabilities()
        .is_none());

    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    let (original_proposal, _) = bob.propose_group_context_extensions(new_extensions.clone());

    assert_eq!(bob.group.pending_proposals().count(), 1);
    bob.group
        .clear_pending_proposals(bob.party.provider.storage())
        .unwrap();

    let Ok(frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content:
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch,
                        sender: bob_sender,
                        authenticated_data,
                        body:
                            frankenstein::FrankenFramedContentBody::Proposal(
                                frankenstein::FrankenProposal::GroupContextExtensions(mut gces),
                            ),
                    },
                ..
            }),
    }) = frankenstein::FrankenMlsMessage::tls_deserialize(
        &mut original_proposal
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    else {
        panic!("proposal message has unexpected format: {original_proposal:#?}")
    };

    let Some(frankenstein::FrankenExtension::RequiredCapabilities(
        frankenstein::FrankenRequiredCapabilitiesExtension {
            extension_types, ..
        },
    )) = gces.get_mut(0)
    else {
        panic!("required capabilities are malformed")
    };

    // this one is supported by bob, but not alice
    extension_types.push(0xf003);

    let group_context = bob.group.export_group_context().clone();
    let secrets = bob.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_commit_message = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &bob.party.provider,
                ciphersuite,
                &bob.party.signer,
                frankenstein::FrankenFramedContent {
                    group_id,
                    epoch,
                    sender: bob_sender,
                    authenticated_data,
                    body: frankenstein::FrankenFramedContentBody::Commit(
                        frankenstein::FrankenCommit {
                            proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                                frankenstein::FrankenProposal::GroupContextExtensions(gces),
                            )],
                            path: None,
                        },
                    ),
                },
                Some(&group_context.into()),
                Some(membership_key),
                // this is a dummy confirmation_tag:
                Some(vec![0u8; 32].into()),
            ),
        ),
    };

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit_message
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let err = {
        let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
        validation_skip_handle.with_disabled(|| alice.fail_processing(fake_commit.clone()))
    };

    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(
                StageCommitError::GroupContextExtensionsProposalValidationError(
                    GroupContextExtensionsProposalValidationError::RequiredExtensionNotSupportedByAllMembers
                )
            )
        ),
        "expected different error. got {err:?}"
    );
}

// Test that the builder pattern accurately configures the new group.
#[openmls_test]
fn proposal() {
    let TestState { mut alice, mut bob }: TestState<Provider> = setup(ciphersuite);

    // No required capabilities, so no specifically required extensions.
    assert!(alice
        .group
        .context()
        .extensions()
        .required_capabilities()
        .is_none());

    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    let (proposal, _) = alice.propose_group_context_extensions(new_extensions.clone());
    bob.process_and_store_proposal(proposal.into());

    assert_eq!(alice.group.pending_proposals().count(), 1);

    let (commit, _, _) = alice.commit_and_merge_pending();
    bob.process_and_merge_commit(commit.into());
    assert_eq!(alice.group.pending_proposals().count(), 0);

    let required_capabilities = alice
        .group
        .context()
        .extensions()
        .required_capabilities()
        .expect("couldn't get required_capabilities");

    // has required_capabilities as required capability
    assert!(required_capabilities.extension_types() == [ExtensionType::Unknown(0xf001)]);

    // === committing to two group context extensions should fail
    let new_extensions_2 = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::RatchetTree], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    alice
        .group
        .propose_group_context_extensions(
            &alice.party.provider,
            new_extensions,
            &alice.party.signer,
        )
        .expect("failed to build group context extensions proposal");

    // the proposals need to be different or they will be deduplicated
    alice
        .group
        .propose_group_context_extensions(
            &alice.party.provider,
            new_extensions_2,
            &alice.party.signer,
        )
        .expect("failed to build group context extensions proposal");

    assert_eq!(alice.group.pending_proposals().count(), 2);

    alice
        .group
        .commit_to_pending_proposals(&alice.party.provider, &alice.party.signer)
        .expect_err(
            "expected error when committing to multiple group context extensions proposals",
        );

    // === can't update required required_capabilities to extensions that existing group members
    //       are not capable of

    // contains unsupported extension
    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf042)], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    alice
        .group
        .propose_group_context_extensions(
            &alice.party.provider,
            new_extensions,
            &alice.party.signer,
        )
        .expect_err("expected an error building GCE proposal with bad required_capabilities");
}

/// Test that update proposals are rejected when the leaf node doesn't support
/// group context extensions (valn0602).
///
/// This test validates that when processing an update proposal, the leaf node's
/// capabilities must include all extension types present in the group context extensions.
///
/// Test structure:
/// - Alice creates group with group context extension 0xf003
/// - Bob proposes self-update, but we tamper with it to remove 0xf003 from capabilities
/// - Alice commits to the tampered proposal
/// - Bob should reject the commit with UnsupportedExtensions error
///
/// https://validation.openmls.tech/#valn0602
#[openmls_test]
fn fail_insufficient_extensiontype_capabilities_update_proposal_valn0502() {
    let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
    let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

    // Alice creates a group with a group context extension 0xf003
    let gc_extensions = Extensions::single(Extension::Unknown(
        0xf003,
        crate::extensions::UnknownExtension(vec![0x01]),
    ))
    .expect("unknown extensions should be considered valid in group context");

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .with_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    let mut alice = MemberState {
        party: alice_party,
        group: alice_group,
    };

    // Bob joins the group with support for extension 0xf003
    let bob_key_package = bob_party.key_package(ciphersuite, |builder| {
        builder.leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
    });

    alice.propose_add_member(bob_key_package.key_package());
    let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
        panic!("expected receiving a welcome")
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice.group.configuration(),
        welcome,
        Some(alice.group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_party.provider)
    .expect("Error creating group from staged join");

    let mut bob = MemberState {
        party: bob_party,
        group: bob_group,
    };

    // Bob proposes a self-update
    let (update_prop, _) = bob
        .group
        .propose_self_update(
            &bob.party.provider,
            &bob.party.signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();

    bob.group
        .clear_pending_proposals(bob.party.provider.storage())
        .unwrap();

    // Extract the FramedContent from the proposal to tamper with it
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content: mut franken_proposal_content,
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(update_prop.clone())
    else {
        unreachable!()
    };

    // Get a mutable reference to the leaf node in the update proposal
    let frankenstein::FrankenFramedContent {
        body:
            frankenstein::FrankenFramedContentBody::Proposal(frankenstein::FrankenProposal::Update(
                frankenstein::FrankenUpdateProposal {
                    leaf_node: bob_franken_leaf_node,
                },
            )),
        ..
    } = &mut franken_proposal_content
    else {
        unreachable!();
    };

    // Remove extension type 0xf003 from capabilities (the one in group context)
    // This makes the update proposal invalid according to valn0602
    bob_franken_leaf_node
        .capabilities
        .extensions
        .retain(|&e| e != 0xf003);

    // Re-sign the leaf node so signature checks pass
    bob_franken_leaf_node.resign(
        Some(frankenstein::FrankenTreePosition {
            group_id: bob.group.group_id().as_slice().to_vec().into(),
            leaf_index: bob.group.own_leaf_index().u32(),
        }),
        &bob.party.signer,
    );

    // Prepare data needed for the proposal
    let group_context = bob.group.export_group_context().clone();
    let secrets = bob.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    // Build the tampered proposal message
    let franken_proposal = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &bob.party.provider,
                ciphersuite,
                &bob.party.signer,
                franken_proposal_content.clone(),
                Some(&group_context.into()),
                Some(membership_key),
                None, // proposals don't have confirmation tags
            ),
        ),
    };

    let fake_proposal = MlsMessageIn::tls_deserialize(
        &mut franken_proposal
            .tls_serialize_detached()
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    // Alice stores the tampered proposal
    alice.process_and_store_proposal(fake_proposal.clone());

    // Bob also stores it to get the proposal ref
    let proposal_ref = bob.process_and_store_proposal(fake_proposal);

    // Craft a commit by Alice that commits to the tampered proposal
    let alice_sender = frankenstein::FrankenSender::Member(0);
    let commit_content = frankenstein::FrankenFramedContent {
        sender: alice_sender,
        body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
            proposals: vec![frankenstein::FrankenProposalOrRef::Reference(
                proposal_ref.as_slice().to_vec().into(),
            )],
            path: None,
        }),
        ..franken_proposal_content
    };

    // Prepare data for the commit
    let group_context = alice.group.export_group_context().clone();
    let secrets = alice.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice.party.provider,
                ciphersuite,
                &alice.party.signer,
                commit_content,
                Some(&group_context.into()),
                Some(membership_key),
                Some(vec![0; 32].into()), // dummy confirmation tag
            ),
        ),
    };

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    // Bob processes the commit and should get an UnsupportedExtensions error
    let err = bob.fail_processing(fake_commit);

    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::LeafNodeValidation(
                    LeafNodeValidationError::UnsupportedExtensions
                )
            ))
        ),
        "expected UnsupportedExtensions error, got: {err} ({err:#?})"
    );
}

/// Test that commits with update paths are rejected when the leaf node in the path
/// doesn't support group context extensions (valn1210).
///
/// This test validates that when processing a commit with an update path, the leaf node
/// in the path must support all extension types present in the group context extensions.
///
/// Test structure:
/// - Alice creates group with group context extension 0xf003
/// - Bob joins the group
/// - Bob creates a commit with an update path using force_self_update
/// - We tamper with the commit to remove 0xf003 from the path leaf node capabilities
/// - Alice should reject the commit with UnsupportedExtensions error
///
/// https://validation.openmls.tech/#valn1210
#[openmls_test]
fn fail_insufficient_extensiontype_capabilities_commit_path_valn0502() {
    let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
    let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

    // Alice creates a group with a group context extension 0xf003
    let gc_extensions = Extensions::single(Extension::Unknown(
        0xf003,
        crate::extensions::UnknownExtension(vec![0x01]),
    ))
    .expect("unknown extensions should be considered valid in group context");

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .with_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    let mut alice = MemberState {
        party: alice_party,
        group: alice_group,
    };

    // Bob joins the group with support for extension 0xf003
    let bob_key_package = bob_party.key_package(ciphersuite, |builder| {
        builder.leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
    });

    alice.propose_add_member(bob_key_package.key_package());
    let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
        panic!("expected receiving a welcome")
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice.group.configuration(),
        welcome,
        Some(alice.group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_party.provider)
    .expect("Error creating group from staged join");

    let mut bob = MemberState {
        party: bob_party,
        group: bob_group,
    };

    // Bob creates a commit with an update path (using force_self_update)
    let commit_bundle = bob
        .group
        .commit_builder()
        .force_self_update(true)
        .load_psks(bob.party.provider.storage())
        .unwrap()
        .build(
            bob.party.provider.rand(),
            bob.party.provider.crypto(),
            &bob.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&bob.party.provider)
        .unwrap();

    let commit_msg = commit_bundle.commit().clone();

    bob.group
        .clear_pending_commit(bob.party.provider.storage())
        .unwrap();

    // Extract the commit to tamper with it
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content: mut franken_commit_content,
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(commit_msg.clone())
    else {
        unreachable!()
    };

    // Get a mutable reference to the update path in the commit
    let frankenstein::FrankenFramedContent {
        body:
            frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
                path: Some(ref mut path),
                ..
            }),
        ..
    } = &mut franken_commit_content
    else {
        unreachable!("expected commit with update path");
    };

    // Remove extension type 0xf003 from the leaf node capabilities in the path
    // This makes the commit invalid according to valn1210
    path.leaf_node
        .capabilities
        .extensions
        .retain(|&e| e != 0xf003);

    // Re-sign the leaf node so signature checks pass
    path.leaf_node.resign(
        Some(frankenstein::FrankenTreePosition {
            group_id: bob.group.group_id().as_slice().to_vec().into(),
            leaf_index: bob.group.own_leaf_index().u32(),
        }),
        &bob.party.signer,
    );

    // Prepare data needed for the commit
    let group_context = bob.group.export_group_context().clone();
    let secrets = bob.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    // Build the tampered commit message
    let franken_commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &bob.party.provider,
                ciphersuite,
                &bob.party.signer,
                franken_commit_content,
                Some(&group_context.into()),
                Some(membership_key),
                Some(vec![0; 32].into()), // dummy confirmation tag
            ),
        ),
    };

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();

    // Alice processes the commit and should get an UnsupportedExtensions error
    let err = alice.fail_processing(fake_commit);

    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::LeafNodeValidation(
                LeafNodeValidationError::UnsupportedExtensions
            ))
        ),
        "expected UnsupportedExtensions error, got: {err} ({err:#?})"
    );
}

/// Test that creating update proposals locally fails when the leaf node parameters
/// don't support group context extensions (pre-validation).
///
/// This test validates that when creating an update proposal locally, the API should
/// pre-validate that the leaf node parameters support all extension types present in
/// the group context extensions, similar to how commit_builder validates with force_self_update.
///
/// Test structure:
/// - Alice creates group with group context extension 0xf003
/// - Bob joins the group
/// - Bob attempts to create an update proposal with leaf node parameters that don't support 0xf003
/// - The proposal creation should fail with UnsupportedExtensions error
///
/// https://validation.openmls.tech/#valn0602
#[openmls_test]
fn fail_create_update_proposal_insufficient_capabilities() {
    let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
    let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

    // Alice creates a group with a group context extension 0xf003
    let gc_extensions = Extensions::single(Extension::Unknown(
        0xf003,
        crate::extensions::UnknownExtension(vec![0x01]),
    ))
    .expect("unknown extensions should be considered valid in group context");

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .with_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    let mut alice = MemberState {
        party: alice_party,
        group: alice_group,
    };

    // Bob joins the group with support for extension 0xf003
    let bob_key_package = bob_party.key_package(ciphersuite, |builder| {
        builder.leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    ExtensionType::Unknown(0xf003),
                ])
                .build(),
        )
    });

    alice.propose_add_member(bob_key_package.key_package());
    let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
        panic!("expected receiving a welcome")
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice.group.configuration(),
        welcome,
        Some(alice.group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_party.provider)
    .expect("Error creating group from staged join");

    let mut bob = MemberState {
        party: bob_party,
        group: bob_group,
    };

    // Bob tries to create an update proposal with leaf node parameters
    // that don't support extension 0xf003 (only supports 0xf001 and 0xf002)
    let bad_params = LeafNodeParameters::builder()
        .with_capabilities(
            Capabilities::builder()
                .extensions(vec![
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                    // Missing 0xf003!
                ])
                .build(),
        )
        .build();

    // This should fail because the leaf node doesn't support all group context extensions
    // Once validation (valn0602) is implemented for propose_self_update, this will return an error
    // Until then, this test will fail because no error is returned
    bob.group
        .propose_self_update(
            &bob.party.provider,
            &bob.party.signer,
            bad_params,
        )
        .expect_err(
            "proposal creation should fail with validation error due to unsupported group context extensions (valn0602)"
        );
}

// NOTE: Need to disable the check for valn0502 in group/public_group/validation.rs for this to
//       run. Otherwise we won't be able to create an illegal commit.
#[openmls_test]
#[ignore]
fn join_rejects_unsupported_group_context_extension() {
    let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
    let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

    let gc_extensions = Extensions::single(Extension::Unknown(
        0x4141,
        crate::extensions::UnknownExtension(vec![0x01]),
    ))
    .expect("unknown extensions should be considered valid in group context");

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .with_group_context_extensions(gc_extensions)
        .build(
            &alice_party.provider,
            &alice_party.signer,
            alice_party.credential_with_key.clone(),
        )
        .expect("error creating group using builder");

    let mut alice = MemberState {
        party: alice_party,
        group: alice_group,
    };

    let bob_key_package = bob_party.key_package(ciphersuite, |builder| builder);
    alice.propose_add_member(bob_key_package.key_package());

    let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
        panic!("expected receiving a welcome")
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    if let Ok(staged) = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        alice.group.configuration(),
        welcome,
        Some(alice.group.export_ratchet_tree().into()),
    ) {
        assert!(alice
            .group
            .extensions()
            .contains(ExtensionType::Unknown(0x4141)));

        assert!(!bob_party
            .key_package_bundle
            .key_package
            .extensions()
            .contains(ExtensionType::Unknown(0x4141)));

        assert!(staged
            .group_context()
            .extensions()
            .contains(ExtensionType::Unknown(0x4141)));

        unreachable!("join should reject unsupported GroupContext extensions");
    }
}
