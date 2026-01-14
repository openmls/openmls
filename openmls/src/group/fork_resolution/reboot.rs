//! The [`reboot`] module contains helpers to set up a new group and add all members of the current
//! group. The application needs to determine who should set that new group up and how to migrate
//! the group context extensions from the old group. This is the more expensive mechanism.

use openmls_traits::signatures::Signer;

use crate::{
    credentials::CredentialWithKey,
    extensions::errors::InvalidExtensionError,
    group::{
        commit_builder::{CommitBuilder, CommitMessageBundle, Initial},
        mls_group::builder::MlsGroupBuilder,
        CommitBuilderStageError, CreateCommitError, Extensions, GroupId, Member, MlsGroup,
        NewGroupError,
    },
    prelude::GroupContext,
    prelude::KeyPackage,
    storage::OpenMlsProvider,
};

impl MlsGroup {
    /// The first step towards creating a new group based on the parameters and membership list of
    /// the current one.
    pub fn reboot(&'_ self, group_id: GroupId) -> RebootBuilder<'_> {
        let group_builder = MlsGroup::builder()
            .with_wire_format_policy(self.configuration().wire_format_policy)
            .padding_size(self.configuration().padding_size)
            .max_past_epochs(self.configuration().max_past_epochs)
            .number_of_resumption_psks(self.configuration().number_of_resumption_psks)
            .use_ratchet_tree_extension(self.configuration().use_ratchet_tree_extension)
            .sender_ratchet_configuration(self.configuration().sender_ratchet_configuration)
            .ciphersuite(self.ciphersuite())
            .with_group_id(group_id);

        RebootBuilder {
            group: self,
            group_builder,
        }
    }
}

/// The builder type for a group reboot.
pub struct RebootBuilder<'a> {
    group: &'a MlsGroup,
    group_builder: MlsGroupBuilder,
}

impl<'a> RebootBuilder<'a> {
    /// Returns the group context extensions of the old group, so they can be updated and passed
    /// into the new group.
    pub fn old_group_context_extensions(&self) -> &Extensions<GroupContext> {
        self.group.context().extensions()
    }

    /// The members of the old group, so new key packages for other members can be retrieved.
    pub fn old_members(&self) -> impl Iterator<Item = Member> + 'a {
        self.group
            .members()
            .filter(|member| member.index != self.group.own_leaf_index())
    }

    /// Lets the caller make changes to the [`MlsGroupBuilder`] before the group is created.
    pub fn refine_group_builder(
        self,
        mut f: impl FnMut(MlsGroupBuilder) -> MlsGroupBuilder,
    ) -> Self {
        Self {
            group_builder: f(self.group_builder),
            ..self
        }
    }

    /// Creates the group and commit using the provided `extensions` and `new_members`. The caller
    /// can also make further changes to the [`CommitBuilder`] using the `refine_commit_builder`
    /// argument. If that is not desired, provide the identity function (`|b| b`).
    pub fn finish<Provider: OpenMlsProvider>(
        self,
        extensions: Extensions<GroupContext>,
        new_members: Vec<KeyPackage>,
        refine_commit_builder: impl FnMut(CommitBuilder<Initial>) -> CommitBuilder<Initial>,
        provider: &Provider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<(MlsGroup, CommitMessageBundle), RebootError<Provider::StorageError>> {
        let group_builder = self.group_builder.with_group_context_extensions(extensions);

        let mut new_group = group_builder.build(provider, signer, credential_with_key)?;

        new_group
            .commit_builder()
            .propose_adds(new_members)
            .pipe_through(refine_commit_builder)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)
            .map_err(RebootError::CommitBuilderStage)
            .map(|message_bundle| (new_group, message_bundle))
    }
}

/// Indicates an error occurred during reboot.
#[derive(Debug, thiserror::Error)]
pub enum RebootError<StorageError> {
    /// An invalid extension was provided.
    #[error(transparent)]
    InvalidExtension(#[from] InvalidExtensionError),
    /// An error occurred while creating the new group.
    #[error(transparent)]
    NewGroup(#[from] NewGroupError<StorageError>),
    /// An error occurred while creating the commit.
    #[error(transparent)]
    CreateCommit(#[from] CreateCommitError),
    /// An error occurred while staging the commit.
    #[error(transparent)]
    CommitBuilderStage(#[from] CommitBuilderStageError<StorageError>),
}

/// Defines a method that consumes self, passes it into a closure and returns the output of the
/// closure. Comes in handy in long builder chains.
trait PipeThrough: Sized {
    fn pipe_through<T: Sized, F: FnMut(Self) -> T>(self, mut f: F) -> T {
        f(self)
    }
}

impl<T> PipeThrough for T {}

#[cfg(test)]
mod test {
    use crate::{
        framing::MlsMessageIn,
        group::{
            mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client},
            tests_and_kats::utils::{generate_key_package, CredentialWithKeyAndSigner},
            Extensions, GroupId, StagedWelcome,
        },
    };

    #[openmls_test::openmls_test]
    fn example_reboot() {
        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let charlie_provider = &Provider::default();
        let dave_provider = &Provider::default();

        // Create group with alice and bob
        let (mut alice_group, alice_signer, mut bob_group, bob_signer, alice_cwk, bob_cwk) =
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

        // Now, reboot the group
        let (mut new_alice_group, message_bundle) = alice_group
            .reboot(GroupId::from_slice(b"new group id"))
            .finish(
                Extensions::empty(),
                vec![
                    bob_new_kpb.key_package().clone(),
                    charlie_new_kpb.key_package().clone(),
                ],
                |builder| builder,
                alice_provider,
                &alice_signer,
                alice_cwk.clone(),
            )
            .unwrap();

        let (_commit, welcome, _group_info) = message_bundle.into_messages();
        new_alice_group
            .merge_pending_commit(alice_provider)
            .unwrap();

        // Invite everyone
        let welcome = welcome.unwrap();
        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome.into_welcome().unwrap();
        let ratchet_tree = new_alice_group.export_ratchet_tree();

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

        let alice_comparison = new_alice_group
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
