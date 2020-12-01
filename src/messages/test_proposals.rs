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
/// `filtered_proposals` returns only proposals of a certain type
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
        let proposal_id_add_alice1 = ProposalID::from_proposal(ciphersuite, &proposal_add_alice1);
        let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
        let proposal_id_add_alice2 = ProposalID::from_proposal(ciphersuite, &proposal_add_alice2);
        let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);
        let proposal_id_add_bob1 = ProposalID::from_proposal(ciphersuite, &proposal_add_bob1);

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

        let proposal_queue = ProposalQueue::new_from_committed_proposals(
            &ciphersuite,
            vec![mls_plaintext_add_alice1, mls_plaintext_add_alice2],
        );

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
        let filtered_proposals =
            proposal_queue.filtered_queued_proposals(valid_proposal_id_list, ProposalType::Add);
        for filtered_proposal in filtered_proposals {
            assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
        }
    }
}
