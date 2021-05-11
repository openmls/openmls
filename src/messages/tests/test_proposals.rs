use crate::{
    ciphersuite::Secret,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, LifetimeExtension},
    framing::sender::{Sender, SenderType},
    framing::MlsPlaintext,
    group::{GroupContext, GroupEpoch, GroupId},
    key_packages::KeyPackageBundle,
    messages::proposals::{
        AddProposal, Proposal, ProposalOrRef, ProposalQueue, ProposalReference, ProposalType,
        QueuedProposal, RemoveProposal,
    },
    schedule::MembershipKey,
    tree::index::*,
};

/// This test makes sure ProposalQueue works as intented. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[test]
fn proposal_queue_functions() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Define identities
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

        // Mandatory extensions, will be fixed in #164
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> = vec![lifetime_extension];

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();
        let alice_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let alice_update_key_package = alice_update_key_package_bundle.key_package();
        assert!(alice_update_key_package.verify().is_ok());

        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(0), vec![], vec![], vec![])
                .expect("Could not create new GroupContext");

        // Let's create some proposals
        let add_proposal_alice1 = AddProposal {
            key_package: alice_key_package_bundle.key_package().clone(),
        };
        let add_proposal_alice2 = AddProposal {
            key_package: alice_key_package_bundle.key_package().clone(),
        };
        let add_proposal_bob1 = AddProposal {
            key_package: bob_key_package.clone(),
        };

        let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
        let proposal_reference_add_alice1 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_alice1);
        let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
        let proposal_reference_add_alice2 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_alice2);
        let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);
        let proposal_reference_add_bob1 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_bob1);

        // Test proposal types
        assert!(proposal_add_alice1.is_type(ProposalType::Add));
        assert!(!proposal_add_alice1.is_type(ProposalType::Update));
        assert!(!proposal_add_alice1.is_type(ProposalType::Remove));

        // Frame proposals in MlsPlaintext
        let mls_plaintext_add_alice1 = MlsPlaintext::new_from_proposal_member(
            LeafIndex::from(0u32),
            &[],
            proposal_add_alice1,
            &alice_credential_bundle,
            &group_context,
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create proposal.");
        let mls_plaintext_add_alice2 = MlsPlaintext::new_from_proposal_member(
            LeafIndex::from(1u32),
            &[],
            proposal_add_alice2,
            &alice_credential_bundle,
            &group_context,
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create proposal.");
        let _mls_plaintext_add_bob1 = MlsPlaintext::new_from_proposal_member(
            LeafIndex::from(1u32),
            &[],
            proposal_add_bob1,
            &alice_credential_bundle,
            &group_context,
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create proposal.");

        let proposals = &[&mls_plaintext_add_alice1, &mls_plaintext_add_alice2];

        let proposal_queue = ProposalQueue::from_proposals_by_reference(&ciphersuite, proposals);

        // Test if proposals are all covered
        let valid_proposal_reference_list = &[
            proposal_reference_add_alice1.clone(),
            proposal_reference_add_alice2.clone(),
        ];
        assert!(proposal_queue.contains(valid_proposal_reference_list));

        let invalid_proposal_reference_list = &[
            proposal_reference_add_alice1,
            proposal_reference_add_alice2,
            proposal_reference_add_bob1,
        ];
        assert!(!proposal_queue.contains(invalid_proposal_reference_list));

        // Get filtered proposals
        for filtered_proposal in proposal_queue.filtered_by_type(ProposalType::Add) {
            assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
        }
    }
}

/// Test, that we the ProposalQueue is iterated in the right order.
#[test]
fn proposal_queue_order() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Define identities
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .expect("Could not create CredentialBundle");
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .expect("Could not create CredentialBundle");

        // Generate KeyPackages
        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();
        let alice_update_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();
        let alice_update_key_package = alice_update_key_package_bundle.key_package();
        assert!(alice_update_key_package.verify().is_ok());

        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(0), vec![], vec![], vec![]).unwrap();

        // Let's create some proposals
        let add_proposal_alice1 = AddProposal {
            key_package: alice_key_package_bundle.key_package().clone(),
        };
        let add_proposal_bob1 = AddProposal {
            key_package: bob_key_package.clone(),
        };

        let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
        let proposal_reference_add_alice1 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_alice1);
        let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);

        // Frame proposals in MlsPlaintext
        let mls_plaintext_add_alice1 = MlsPlaintext::new_from_proposal_member(
            LeafIndex::from(0u32),
            &[],
            proposal_add_alice1.clone(),
            &alice_credential_bundle,
            &group_context,
            &MembershipKey::from_secret(Secret::random(ciphersuite, None /* MLS version */)),
        )
        .expect("Could not create proposal.");
        let mls_plaintext_add_bob1 = MlsPlaintext::new_from_proposal_member(
            LeafIndex::from(1u32),
            &[],
            proposal_add_bob1.clone(),
            &alice_credential_bundle,
            &group_context,
            &MembershipKey::from_secret(Secret::random(ciphersuite, None /* MLS version */)),
        )
        .expect("Could not create proposal.");

        // This should set the order of the proposals.
        let proposals = &[&mls_plaintext_add_alice1, &mls_plaintext_add_bob1];

        let proposal_queue = ProposalQueue::from_proposals_by_reference(&ciphersuite, proposals);

        // Now let's iterate over the queue. This should be in order.
        let proposal_collection: Vec<&QueuedProposal> =
            proposal_queue.filtered_by_type(ProposalType::Add).collect();

        assert_eq!(proposal_collection[0].proposal(), &proposal_add_alice1);
        assert_eq!(proposal_collection[1].proposal(), &proposal_add_bob1);

        let proposal_or_refs = &[
            ProposalOrRef::Proposal(proposal_add_bob1.clone()),
            ProposalOrRef::Reference(proposal_reference_add_alice1),
        ];

        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(0u32),
        };

        // And the same should go for proposal queues built from committed
        // proposals. The order here should be dictated by the proposals passed
        // as ProposalOrRefs.
        let proposal_queue = ProposalQueue::from_committed_proposals(
            ciphersuite,
            proposal_or_refs,
            proposals,
            sender,
        )
        .unwrap();

        let proposal_collection: Vec<&QueuedProposal> =
            proposal_queue.filtered_by_type(ProposalType::Add).collect();

        assert_eq!(proposal_collection[0].proposal(), &proposal_add_bob1);
        assert_eq!(proposal_collection[1].proposal(), &proposal_add_alice1);
    }
}

/// This test encodes and decodes the `ProposalOrRef` struct and makes sure the
/// decoded values are the same as the original
#[test]
fn proposals_codec() {
    use crate::ciphersuite::*;
    use crate::codec::{Codec, Cursor};

    let ciphersuite =
        &Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap();

    // Proposal

    let remove_proposal = RemoveProposal { removed: 123 };
    let proposal = Proposal::Remove(remove_proposal);
    let proposal_or_ref = ProposalOrRef::Proposal(proposal.clone());
    let encoded = proposal_or_ref.encode_detached().unwrap();
    let decoded = ProposalOrRef::decode(&mut Cursor::new(&encoded)).unwrap();

    assert_eq!(proposal_or_ref, decoded);

    // Reference

    let reference = ProposalReference::from_proposal(ciphersuite, &proposal);
    let proposal_or_ref = ProposalOrRef::Reference(reference);
    let encoded = proposal_or_ref.encode_detached().unwrap();
    let decoded = ProposalOrRef::decode(&mut Cursor::new(&encoded)).unwrap();

    assert_eq!(proposal_or_ref, decoded);
}
