use crate::group::Member;

mod readd;

mod migrate {

    use openmls_traits::signatures::Signer;

    use crate::{
        credentials::CredentialWithKey,
        extensions::errors::InvalidExtensionError,
        group::{
            commit_builder::{CommitBuilder, CommitMessageBundle, Initial as CommitBuilderInitial},
            group_builder::MlsGroupBuilder,
            CommitBuilderStageError, CreateCommitError, Extensions, GroupId, Member, MlsGroup,
            NewGroupError,
        },
        prelude::KeyPackage,
        storage::OpenMlsProvider,
    };

    impl MlsGroup {
        pub fn reboot(&self, group_id: GroupId) -> RebootContext<Initial<'_>> {
            let group_builder = MlsGroup::builder()
                .with_wire_format_policy(self.configuration().wire_format_policy)
                .padding_size(self.configuration().padding_size)
                .max_past_epochs(self.configuration().max_past_epochs)
                .number_of_resumption_psks(self.configuration().number_of_resumption_psks)
                .use_ratchet_tree_extension(self.configuration().use_ratchet_tree_extension)
                .sender_ratchet_configuration(self.configuration().sender_ratchet_configuration)
                .ciphersuite(self.ciphersuite())
                .with_group_id(group_id);

            RebootContext {
                stage: Initial {
                    group: self,
                    group_builder,
                },
            }
        }

        pub fn migrate<'a>(
            &self,
            new_group: &'a mut MlsGroup,
        ) -> CommitBuilder<'a, RebootExpectKeyPackages> {
            let members = self.members().collect();
            let stage = RebootExpectKeyPackages { members };

            new_group.commit_builder().into_stage(stage)
        }
    }

    pub struct RebootExpectKeyPackages {
        members: Vec<Member>,
    }

    pub struct RebootContext<Stage> {
        stage: Stage,
    }

    pub struct Initial<'a> {
        group: &'a MlsGroup,
        group_builder: MlsGroupBuilder,
    }

    pub struct GroupBuilderPrepFinished<'a> {
        group: &'a MlsGroup,
        group_builder: MlsGroupBuilder,
    }

    pub struct NewGroupBuilt<'a> {
        group: &'a MlsGroup,
        new_group: MlsGroup,
    }

    impl<'a> RebootContext<Initial<'a>> {
        pub fn old_group_context_extensions(&self) -> &Extensions {
            self.stage.group.context().extensions()
        }

        pub fn refine_group_builder(
            self,
            mut f: impl FnMut(MlsGroupBuilder) -> MlsGroupBuilder,
        ) -> Self {
            Self {
                stage: Initial {
                    group: self.stage.group,
                    group_builder: f(self.stage.group_builder),
                },
            }
        }

        pub fn group_context_extensions(
            self,
            extensions: Extensions,
        ) -> Result<RebootContext<GroupBuilderPrepFinished<'a>>, InvalidExtensionError> {
            let group_builder = self
                .stage
                .group_builder
                .with_group_context_extensions(extensions)?;

            Ok(RebootContext {
                stage: GroupBuilderPrepFinished {
                    group: self.stage.group,
                    group_builder,
                },
            })
        }
    }

    impl<'a> RebootContext<GroupBuilderPrepFinished<'a>> {
        pub fn build_new_group<Provider: OpenMlsProvider>(
            self,
            provider: &Provider,
            signer: &impl Signer,
            credential_with_key: CredentialWithKey,
        ) -> Result<RebootContext<NewGroupBuilt<'a>>, NewGroupError<Provider::StorageError>>
        {
            let new_group =
                self.stage
                    .group_builder
                    .build(provider, signer, credential_with_key)?;

            Ok(RebootContext {
                stage: NewGroupBuilt {
                    group: self.stage.group,
                    new_group,
                },
            })
        }
    }

    impl<'a> RebootContext<NewGroupBuilt<'a>> {
        pub fn members(&self) -> impl Iterator<Item = Member> + 'a {
            self.stage.group.members()
        }

        pub fn readd<Provider: OpenMlsProvider>(
            mut self,
            provider: &Provider,
            signer: &impl Signer,
            key_packages: Vec<KeyPackage>,
        ) -> Result<(MlsGroup, CommitMessageBundle), RebootError<Provider::StorageError>> {
            let commit_builder = self.stage.new_group.commit_builder();
            commit_builder
                .propose_adds(key_packages)
                .load_psks(provider.storage())
                .map_err(RebootError::CreateCommit)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(RebootError::CreateCommit)?
                .stage_commit(provider)
                .map_err(RebootError::CommitBuilderStage)
                .map(|message_bundle| (self.stage.new_group, message_bundle))
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum RebootError<StorageError> {
        #[error(transparent)]
        CreateCommit(CreateCommitError),
        #[error(transparent)]
        CommitBuilderStage(CommitBuilderStageError<StorageError>),
    }

    impl<'a> CommitBuilder<'a, RebootExpectKeyPackages> {
        pub fn members(&self) -> &[Member] {
            self.stage().members.as_slice()
        }

        pub fn provide_key_packages(
            self,
            new_key_packages: Vec<KeyPackage>,
        ) -> CommitBuilder<'a, CommitBuilderInitial> {
            let (_, builder) = self.replace_stage(CommitBuilderInitial::default());

            builder.propose_adds(new_key_packages)
        }
    }
}

// NOTE: If we require that the list of LeafNodeIndex is ordered, we can make this O(n) instead
// of (n^2).
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
            Extensions, GroupId, StagedWelcome,
        },
    };

    #[openmls_test::openmls_test]
    fn example_reboot() {
        let alice_provider_ = Provider::default();
        let bob_provider_ = Provider::default();
        let charlie_provider_ = Provider::default();
        let dave_provider_ = Provider::default();

        let alice_provider = &alice_provider_;
        let bob_provider = &bob_provider_;
        let charlie_provider = &charlie_provider_;
        let dave_provider = &dave_provider_;

        // Create group with alice and bob
        let (mut alice_group, alice_signer, mut bob_group, bob_signer, alice_cwk, bob_cwk) =
            setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

        let (charlie_cwk, charlie_kpb, charlie_signer, _charlie_sig_pk) =
            setup_client("Charlie", ciphersuite, charlie_provider);

        let (_dave_cwk, dave_kpb, dave_signer, _dave_sig_pk) =
            setup_client("Dave", ciphersuite, dave_provider);

        let alice_cwkas = CredentialWithKeyAndSigner {
            credential_with_key: alice_cwk.clone(),
            signer: alice_signer.clone(),
        };

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
        let alice_new_kpb = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            alice_provider,
            alice_cwkas,
        );
        let bob_new_kpb =
            generate_key_package(ciphersuite, Extensions::empty(), bob_provider, bob_cwkas);
        let charlie_new_kpb = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            charlie_provider,
            charlie_cwkas,
        );

        let (mut new_group_alice, message_bundle) = alice_group
            .reboot(GroupId::from_slice(b"new group id"))
            .group_context_extensions(Extensions::empty())
            .unwrap()
            .build_new_group(alice_provider, &alice_signer, alice_cwk.clone())
            .unwrap()
            .readd(
                alice_provider,
                &alice_signer,
                vec![
                    bob_new_kpb.key_package().clone(),
                    charlie_new_kpb.key_package().clone(),
                ],
            )
            .unwrap();

        let (commit, welcome, group_info) = message_bundle.into_messages();

        new_group_alice
            .merge_pending_commit(alice_provider)
            .unwrap();

        let welcome = welcome.unwrap();
        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome.into_welcome().unwrap();
        let ratchet_tree = alice_group.export_ratchet_tree();

        let new_group_bob = StagedWelcome::new_from_welcome(
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

        let alice_comparison = new_group_alice
            .export_secret(alice_provider, "comparison", b"", 32)
            .unwrap();

        let bob_comparison = new_group_bob
            .export_secret(bob_provider, "comparison", b"", 32)
            .unwrap();

        let charlie_comparison = new_group_charlie
            .export_secret(charlie_provider, "comparison", b"", 32)
            .unwrap();

        assert_eq!(alice_comparison, bob_comparison);
        assert_eq!(alice_comparison, charlie_comparison);
    }
}
