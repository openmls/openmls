//! This module contains helpers for removing and re-adding members that merged a wrong
//! commit. It is the responsibility of the application to determine which commit is the right one,
//! as well as which members need to be re-added. This is a relatively cheap mechanism, but it
//! requires knowing about the partitions.

use crate::binary_tree::LeafNodeIndex;

use crate::{
    group::{
        commit_builder::{CommitBuilder, Initial},
        Member, MlsGroup,
    },
    prelude::KeyPackage,
};

/// A stage for the [`CommitBuilder`] for removing and re-adding members from other partitions.
pub struct ReAddExpectKeyPackages {
    complement_partition: Vec<Member>,
}

impl MlsGroup {
    /// Create a [`CommitBuilder`] that is preparing to remove and re-add members from other fork
    /// partitions. `own_partition` is the list of [`LeafNodeIndex`] that are members in the
    /// partition that the initiating client is in. This should include the [`LeafNodeIndex`] of
    /// the initiating client.
    pub fn recover_fork_by_readding(
        &'_ mut self,
        own_partition: &[LeafNodeIndex],
    ) -> Result<CommitBuilder<'_, ReAddExpectKeyPackages>, ReAddError> {
        // Load member info. This is None if at least one of the indexes is not a valid member
        let own_partition: Option<Vec<_>> = own_partition
            .iter()
            .cloned()
            .map(|leaf_index| self.member_at(leaf_index))
            .collect();

        // Fail if there is a leaf node index that is not a member
        let own_partition = own_partition.ok_or(ReAddError::InvalidLeafNodeIndex)?;

        // Compute the complement partition, i.e. the list of members that are not in our partition
        let complement_partition = complement(&own_partition, self.members()).collect();

        let stage = ReAddExpectKeyPackages {
            complement_partition,
        };

        Ok(self.commit_builder().into_stage(stage))
    }
}

impl<'a> CommitBuilder<'a, ReAddExpectKeyPackages> {
    /// Returns the complement partition, i.e. the list of members that are not in our partition.
    pub fn complement_partition(&self) -> &[Member] {
        self.stage().complement_partition.as_slice()
    }

    /// Takes the key packages needed to re-add the other members and returns the prepared
    /// [`CommitBuilder`].
    pub fn provide_key_packages(
        self,
        new_key_packages: Vec<KeyPackage>,
    ) -> CommitBuilder<'a, Initial> {
        let (stage, builder) = self.replace_stage(Initial::default());

        builder
            .propose_removals(stage.complement_partition.iter().map(|member| member.index))
            .propose_adds(new_key_packages)
    }
}

#[derive(Debug, thiserror::Error)]
/// Indicates an error occurred during re-adding
pub enum ReAddError {
    /// An invalid leaf node index was provided
    #[error("An invalid leaf node index was provided.")]
    InvalidLeafNodeIndex,
}

/// Computes the complement partition of the provided list of members.
// NOTE: If we require that the list of LeafNodeIndex is ordered, we can make this O(n) instead
// of O(n^2).
fn complement<'a, MembersIter>(
    partition: &'a [Member],
    members: MembersIter,
) -> impl Iterator<Item = Member> + 'a
where
    MembersIter: IntoIterator<Item = Member> + 'a,
{
    members.into_iter().filter(|member| {
        partition
            .iter()
            .all(|own_member| member.index != own_member.index)
    })
}

#[cfg(test)]
mod test {
    use crate::{
        framing::MlsMessageIn,
        group::{
            mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client},
            tests_and_kats::utils::{generate_key_package, CredentialWithKeyAndSigner},
            Extensions, StagedWelcome,
        },
    };

    #[openmls_test::openmls_test]
    fn example_readd() {
        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let charlie_provider = &Provider::default();
        let dave_provider = &Provider::default();

        // Create group with alice and bob
        let (mut alice_group, alice_signer, mut bob_group, bob_signer, _alice_cwk, bob_cwk) =
            setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

        let (charlie_cwk, charlie_kpb, charlie_signer, _charlie_sig_pk) =
            setup_client("Charlie", ciphersuite, charlie_provider);

        let (_dave_cwk, dave_kpb, _dave_signer, _dave_sig_pk) =
            setup_client("Dave", ciphersuite, dave_provider);

        let bob_cwkas = CredentialWithKeyAndSigner {
            credential_with_key: bob_cwk.clone(),
            signer: bob_signer.clone(),
        };

        let charlie_cwkas = CredentialWithKeyAndSigner {
            credential_with_key: charlie_cwk.clone(),
            signer: charlie_signer.clone(),
        };

        // Alice and Bob concurrently invite someone and merge for whatever reason
        alice_group
            .commit_builder()
            .propose_adds(Some(charlie_kpb.key_package().clone()))
            .load_psks(alice_provider.storage())
            .unwrap()
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(alice_provider)
            .unwrap();

        bob_group
            .commit_builder()
            .propose_adds(Some(dave_kpb.key_package().clone()))
            .load_psks(bob_provider.storage())
            .unwrap()
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                &bob_signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(bob_provider)
            .unwrap();

        alice_group.merge_pending_commit(alice_provider).unwrap();
        bob_group.merge_pending_commit(bob_provider).unwrap();

        // We are forked now! Let's try to recover by rebooting. first get new key packages
        let bob_new_kpb =
            generate_key_package(ciphersuite, Extensions::empty(), bob_provider, bob_cwkas);

        let charlie_new_kpb = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            charlie_provider,
            charlie_cwkas,
        );

        // Now, re-add bob to the group
        let builder = alice_group
            .recover_fork_by_readding(&[alice_group.own_leaf_index()])
            .unwrap();
        let key_packages = builder
            .complement_partition()
            .iter()
            .map(|member| match member.credential.serialized_content() {
                b"Bob" => bob_new_kpb.key_package().clone(),
                b"Charlie" => charlie_new_kpb.key_package().clone(),
                _ => unreachable!(),
            })
            .collect();

        let message_bundle = builder
            .provide_key_packages(key_packages)
            .load_psks(alice_provider.storage())
            .unwrap()
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(alice_provider)
            .unwrap();

        let (_commit, welcome, _group_info) = message_bundle.into_messages();
        alice_group.merge_pending_commit(alice_provider).unwrap();

        // Invite everyone
        let welcome = welcome.unwrap();
        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome.into_welcome().unwrap();
        let ratchet_tree = alice_group.export_ratchet_tree();

        // Delete Bob's old group
        bob_group.delete(bob_provider.storage()).unwrap();

        let new_bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            welcome.clone(),
            Some(ratchet_tree.clone().into()),
        )
        .unwrap()
        .into_group(bob_provider)
        .unwrap();

        let new_group_charlie = StagedWelcome::new_from_welcome(
            charlie_provider,
            alice_group.configuration(),
            welcome.clone(),
            Some(ratchet_tree.clone().into()),
        )
        .unwrap()
        .into_group(bob_provider)
        .unwrap();

        let alice_comparison = alice_group
            .export_secret(alice_provider.crypto(), "comparison", b"", 32)
            .unwrap();

        let bob_comparison = new_bob_group
            .export_secret(bob_provider.crypto(), "comparison", b"", 32)
            .unwrap();

        let charlie_comparison = new_group_charlie
            .export_secret(charlie_provider.crypto(), "comparison", b"", 32)
            .unwrap();

        assert_eq!(alice_comparison, bob_comparison);
        assert_eq!(alice_comparison, charlie_comparison);
    }
}
