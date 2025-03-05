use crate::group::Member;

mod readd;

mod migrate {

    use openmls_traits::signatures::Signer;

    use crate::{
        credentials::CredentialWithKey,
        extensions::errors::InvalidExtensionError,
        group::{
            commit_builder::{CommitBuilder, Initial as CommitBuilderInitial},
            group_builder::MlsGroupBuilder,
            Extensions, GroupId, Member, MlsGroup, MlsGroupCreateConfig, NewGroupError,
        },
        prelude::KeyPackage,
        storage::OpenMlsProvider,
    };

    impl MlsGroup {
        pub fn reboot<'a>(&'a self, group_id: GroupId) -> RebootContext<Initial<'a>> {
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

    // XXX: This is where one core issue lies. We can't have the CommitBuilder take a reference to
    // the new_group field without pinning it, and that would be very painful. We could first
    // return the group and then work with the normal commit builder, but it seems like that
    // wouldn't be a lot more ergonomic than doing everything by hand.
    // In general, rebooting the group takes a lot of steps and I am not sure the builder makes
    // this much simpler - especially if we have to return the empty group first.
    pub struct CommitBuilderPrepared<'a> {
        group: &'a MlsGroup,
        new_group: MlsGroup, // 'b
                             //commit_builder: CommitBuilder<'b, Initial>,
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

        pub fn readd(
            self,
            key_packages: Vec<KeyPackage>,
        ) -> RebootContext<CommitBuilderPrepared<'a>> {
            todo!()
        }
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
