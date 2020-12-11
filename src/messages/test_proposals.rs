use crate::config::*;
use crate::creds::*;
use crate::extensions::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::proposals::*;
use crate::tree::index::*;

/// This test makes sure ProposalQueue works as intented. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[test]
fn proposal_queue_functions() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Define identities
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

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

        let group_context = GroupContext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(0),
            tree_hash: vec![],
            confirmed_transcript_hash: vec![],
        };

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
        let proposal_id_add_alice1 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_alice1);
        let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
        let proposal_id_add_alice2 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_alice2);
        let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);
        let proposal_id_add_bob1 =
            ProposalReference::from_proposal(ciphersuite, &proposal_add_bob1);

        // Test proposal types
        assert!(proposal_add_alice1.is_type(ProposalType::Add));
        assert!(!proposal_add_alice1.is_type(ProposalType::Update));
        assert!(!proposal_add_alice1.is_type(ProposalType::Remove));

        // Frame proposals in MLSPlaintext
        let mls_plaintext_add_alice1 = MLSPlaintext::new(
            LeafIndex::from(0u32),
            &[],
            MLSPlaintextContentType::Proposal(proposal_add_alice1),
            &alice_credential_bundle,
            &group_context,
        );
        let mls_plaintext_add_alice2 = MLSPlaintext::new(
            LeafIndex::from(1u32),
            &[],
            MLSPlaintextContentType::Proposal(proposal_add_alice2),
            &alice_credential_bundle,
            &group_context,
        );
        let _mls_plaintext_add_bob1 = MLSPlaintext::new(
            LeafIndex::from(1u32),
            &[],
            MLSPlaintextContentType::Proposal(proposal_add_bob1),
            &alice_credential_bundle,
            &group_context,
        );

        let proposals = &[&mls_plaintext_add_alice1, &mls_plaintext_add_alice2];

        let proposal_queue = ProposalQueue::from_proposals_by_reference(&ciphersuite, proposals);

        // Test if proposals are all covered
        let valid_proposal_id_list = &[
            proposal_id_add_alice1.clone(),
            proposal_id_add_alice2.clone(),
        ];
        assert!(proposal_queue.contains(valid_proposal_id_list));

        let invalid_proposal_id_list = &[
            proposal_id_add_alice1,
            proposal_id_add_alice2,
            proposal_id_add_bob1,
        ];
        assert!(!proposal_queue.contains(invalid_proposal_id_list));

        // Get filtered proposals
        for filtered_proposal_reference in proposal_queue.filtered_by_type(ProposalType::Add) {
            // We can unwrap here, because the iterator will only return
            // proposal references for which a matching proposal exists.
            let filtered_proposal = proposal_queue.get(filtered_proposal_reference).unwrap();
            assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
        }
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
