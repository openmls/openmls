use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::SignatureScheme};
pub use openmls_traits::{
    storage::StorageProvider as StorageProviderTrait,
    types::{Ciphersuite, HpkeKeyPair},
    OpenMlsProvider,
};

pub use crate::utils::*;
use crate::{
    credentials::CredentialWithKey,
    key_packages::KeyPackageBuilder,
    prelude::{commit_builder::*, *},
};

use crate::test_utils::storage_state::GroupStorageState;

mod assertions;

mod errors;
pub use errors::GroupError;
use errors::*;

use std::collections::HashMap;

// type alias for &'static str
type Name = &'static str;

// TODO: only define this once
pub(crate) fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.storage()).unwrap();

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

// TODO: only define this once
pub(crate) fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions,
    provider: &impl crate::storage::OpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}

/// Struct representing a party's global state
pub struct CorePartyState<Provider> {
    pub name: Name,
    pub provider: Provider,
}

impl<Provider: Default> CorePartyState<Provider> {
    pub fn new(name: Name) -> Self {
        Self {
            name,
            provider: Provider::default(),
        }
    }
}

/// Struct representing a party's state before joining a group
pub struct PreGroupPartyState<'a, Provider> {
    pub credential_with_key: CredentialWithKey,
    // TODO: regenerate?
    pub key_package_bundle: KeyPackageBundle,
    pub signer: SignatureKeyPair,
    pub core_state: &'a CorePartyState<Provider>,
}

impl<Provider: OpenMlsProvider> CorePartyState<Provider> {
    /// Generates the pre-group state for a `CorePartyState`
    pub fn generate_pre_group(&self, ciphersuite: Ciphersuite) -> PreGroupPartyState<'_, Provider> {
        let (credential_with_key, signer) = generate_credential(
            self.name.into(),
            ciphersuite.signature_algorithm(),
            &self.provider,
        );

        let key_package_bundle = generate_key_package(
            ciphersuite,
            credential_with_key.clone(),
            Extensions::default(), // TODO: provide as argument?
            &self.provider,
            &signer,
        );

        PreGroupPartyState {
            credential_with_key,
            key_package_bundle,
            signer,
            core_state: self,
        }
    }
}

/// Represents a group member's `MlsGroup` instance and pre-group state
pub struct MemberState<'a, Provider> {
    pub party: PreGroupPartyState<'a, Provider>,
    pub group: MlsGroup,
}

impl<Provider: OpenMlsProvider> MemberState<'_, Provider> {
    /// Get member's `SignatureKeyPair` if available
    pub fn get_storage_signature_key_pair(&self) -> Option<SignatureKeyPair> {
        let ciphersuite = self
            .party
            .key_package_bundle
            .key_package()
            .ciphersuite()
            .into();

        SignatureKeyPair::read(
            self.party.core_state.provider.storage(),
            self.party.signer.public(),
            ciphersuite,
        )
    }
    /// Get the `GroupStorageState` for this group
    pub fn group_storage_state(&self) -> GroupStorageState {
        let storage_provider = self.party.core_state.provider.storage();
        let group_id = self.group.group_id();

        GroupStorageState::from_storage(storage_provider, group_id)
    }
    /// Deliver_and_apply a message to this member's `MlsGroup`
    pub fn deliver_and_apply(&mut self, message: MlsMessageIn) -> Result<(), GroupError<Provider>> {
        let message = message.try_into_protocol_message()?;

        // process message
        let processed_message = self
            .group
            .process_message(&self.party.core_state.provider, message)?;

        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(_) => todo!(),
            ProcessedMessageContent::ProposalMessage(_) => todo!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => todo!(),
            ProcessedMessageContent::StagedCommitMessage(m) => self
                .group
                .merge_staged_commit(&self.party.core_state.provider, *m)?,
        };

        Ok(())
    }
}

impl<'commit_builder, 'b: 'commit_builder, 'a: 'b, Provider> MemberState<'a, Provider>
where
    Provider: openmls_traits::OpenMlsProvider,
{
    /// Build and stage a commit, using the provided closure to add proposals
    pub fn build_commit_and_stage(
        &'b mut self,
        f: impl FnOnce(
            CommitBuilder<'commit_builder, Initial>,
        ) -> CommitBuilder<'commit_builder, Initial>,
    ) -> Result<CommitMessageBundle, GroupError<Provider>> {
        let commit_builder = f(self.group.commit_builder());

        let provider = &self.party.core_state.provider;

        // TODO: most of the steps here cannot be done via the closure (yet)
        let bundle = commit_builder
            .load_psks(provider.storage())?
            .build(
                provider.rand(),
                provider.crypto(),
                &self.party.signer,
                |_| true,
            )?
            .stage_commit(provider)?;

        Ok(bundle)
    }
}

impl<'a, Provider: OpenMlsProvider> MemberState<'a, Provider> {
    /// Create a `MemberState` from a `PreGroupPartyState`. This creates a new `MlsGroup` with one
    /// member
    pub fn create_from_pre_group(
        party: PreGroupPartyState<'a, Provider>,
        mls_group_create_config: MlsGroupCreateConfig,
        group_id: GroupId,
    ) -> Result<Self, GroupError<Provider>> {
        // initialize MlsGroup
        let group = MlsGroup::new_with_group_id(
            &party.core_state.provider,
            &party.signer,
            &mls_group_create_config,
            group_id,
            party.credential_with_key.clone(),
        )?;

        Ok(Self { party, group })
    }
    /// Create a `MemberState` from a `Welcome`, which creates a new `MlsGroup` using a `Welcome`
    /// invitation from an existing group
    pub fn join_from_pre_group(
        party: PreGroupPartyState<'a, Provider>,
        mls_group_join_config: MlsGroupJoinConfig,
        welcome: Welcome,
        tree: Option<RatchetTreeIn>,
    ) -> Result<Self, GroupError<Provider>> {
        let staged_join = StagedWelcome::new_from_welcome(
            &party.core_state.provider,
            &mls_group_join_config,
            welcome,
            tree,
        )?;

        let group = staged_join.into_group(&party.core_state.provider)?;

        Ok(Self { party, group })
    }
}

/// All of the state for a group and its members
pub struct GroupState<'a, Provider> {
    group_id: GroupId,
    members: HashMap<Name, MemberState<'a, Provider>>,
}

impl<'a, Provider: OpenMlsProvider> GroupState<'a, Provider> {
    /// Create a new `GroupState` from a single party
    pub fn new_from_party(
        group_id: GroupId,
        pre_group_state: PreGroupPartyState<'a, Provider>,
        mls_group_create_config: MlsGroupCreateConfig,
    ) -> Result<Self, GroupError<Provider>> {
        let mut members = HashMap::new();

        let name = pre_group_state.core_state.name;
        let member_state = MemberState::create_from_pre_group(
            pre_group_state,
            mls_group_create_config,
            group_id.clone(),
        )?;

        members.insert(name, member_state);

        Ok(Self { group_id, members })
    }

    /// Get mutable references to specified `MemberState`s as a fixed-size array,
    /// in the order of the names provided in `names`.
    /// At least one member must be requested.
    pub fn members_mut<const N: usize>(
        &mut self,
        names: &[Name; N],
    ) -> [&mut MemberState<'a, Provider>; N] {
        assert!(N > 0, "must request at least one member");
        assert!(
            N <= self.members.len(),
            "cannot request more members than available"
        );

        // map each member in `self.members` to its name's index in `names`
        let mut members: [(_, _); N] = self
            .members
            .iter_mut()
            .filter_map(|(member_name, member)| {
                // Find the index of the member's name in `names`
                // NOTE: the list of names provided to this method will generally be short,
                // so not many comparisons are made here.
                let index = names.iter().position(|name| name == member_name)?;

                Some((index, member))
            })
            // collect into Vec, then into fixed-size array
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .expect("At least one requested member not found");

        // sort by index
        members.sort_by_key(|(pos, _member)| *pos);

        members.map(|(_pos, member)| member)
    }

    /// Deliver_and_apply a message to all parties
    pub fn deliver_and_apply(&mut self, message: MlsMessageIn) -> Result<(), GroupError<Provider>> {
        self.deliver_and_apply_if(message, |_| true)
    }
    /// Deliver_and_apply a message to all parties if a provided condition is met
    pub fn deliver_and_apply_if(
        &mut self,
        message: MlsMessageIn,
        condition: impl Fn(&MemberState<'a, Provider>) -> bool,
    ) -> Result<(), GroupError<Provider>> {
        self.members
            .values_mut()
            .filter(|member| condition(member))
            .try_for_each(|member| member.deliver_and_apply(message.clone()))?;

        Ok(())
    }

    /// Deliver_and_apply a welcome to a single party, and initialize a group for that party
    pub fn deliver_and_apply_welcome(
        &mut self,
        recipient: PreGroupPartyState<'a, Provider>,
        mls_group_join_config: MlsGroupJoinConfig,
        welcome: Welcome,
        tree: Option<RatchetTreeIn>,
    ) -> Result<(), GroupError<Provider>> {
        // create new group
        let name = recipient.core_state.name;

        let member_state =
            MemberState::join_from_pre_group(recipient, mls_group_join_config, welcome, tree)?;

        // insert after success
        self.members.insert(name, member_state);

        Ok(())
    }

    /// Drop a member from the internal hashmap. This does not delete the member from any
    /// `MlsGroup`
    pub fn untrack_member(&mut self, name: Name) {
        let _ = self.members.remove(&name);
    }

    pub fn add_member(
        &mut self,
        add_config: AddMemberConfig<'a, Provider>,
    ) -> Result<(), GroupError<Provider>> {
        let adder = self
            .members
            .get_mut(add_config.adder)
            .ok_or(TestError::NoSuchMember)?;

        let key_packages: Vec<_> = add_config
            .addees
            .iter()
            .map(|addee| addee.key_package_bundle.key_package.clone())
            .collect();

        let (commit, welcome, _) = adder.group.add_members(
            &adder.party.core_state.provider,
            &adder.party.signer,
            &key_packages,
        )?;

        // Deliver_and_apply to all members but adder
        self.deliver_and_apply_if(commit.into(), |member| {
            member.party.core_state.name != add_config.adder
        })?;

        // Deliver_and_apply welcome to addee
        let welcome = match welcome.body() {
            MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
            _ => panic!("No welcome returned"),
        };

        for addee in add_config.addees.into_iter() {
            self.deliver_and_apply_welcome(
                addee,
                add_config.join_config.clone(),
                welcome.clone(),
                None,
            )?;
        }

        let adder = self
            .members
            .get_mut(add_config.adder)
            .ok_or(TestError::NoSuchMember)?;

        let staged_commit = adder.group.pending_commit().unwrap().clone();

        adder
            .group
            .merge_staged_commit(&adder.party.core_state.provider, staged_commit)?;

        Ok(())
    }

    /// Returns a copy of the GroupId
    pub fn group_id(&self) -> GroupId {
        self.group_id.clone()
    }
}

impl MlsGroupCreateConfig {
    /// Default config for test framework
    pub fn test_default_from_ciphersuite(ciphersuite: Ciphersuite) -> Self {
        MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build()
    }
}

pub struct AddMemberConfig<'a, Provider> {
    pub adder: Name,
    pub addees: Vec<PreGroupPartyState<'a, Provider>>,
    pub join_config: MlsGroupJoinConfig,
    pub tree: Option<RatchetTreeIn>,
}

#[cfg(test)]
mod test {

    use super::*;
    use openmls_test::openmls_test;

    #[openmls_test]
    fn test_members_mut() {
        let alice_party = CorePartyState::<Provider>::new("alice");
        let bob_party = CorePartyState::<Provider>::new("bob");
        let charlie_party = CorePartyState::<Provider>::new("charlie");
        let dave_party = CorePartyState::<Provider>::new("dave");

        let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
        let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
        let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
        let dave_pre_group = dave_party.generate_pre_group(ciphersuite);

        // Create config
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();

        // Join config
        let mls_group_join_config = mls_group_create_config.join_config().clone();

        // Initialize the group state
        let group_id = GroupId::from_slice(b"test");
        let mut group_state =
            GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

        group_state
            .add_member(AddMemberConfig {
                adder: "alice",
                addees: vec![bob_pre_group, charlie_pre_group, dave_pre_group],
                join_config: mls_group_join_config.clone(),
                tree: None,
            })
            .expect("Could not add member");

        // test different orderings
        let [alice, bob, charlie, dave] =
            group_state.members_mut(&["alice", "bob", "charlie", "dave"]);
        assert_eq!(alice.party.core_state.name, "alice");
        assert_eq!(bob.party.core_state.name, "bob");
        assert_eq!(charlie.party.core_state.name, "charlie");
        assert_eq!(dave.party.core_state.name, "dave");

        let [dave, charlie, bob, alice] =
            group_state.members_mut(&["dave", "charlie", "bob", "alice"]);
        assert_eq!(alice.party.core_state.name, "alice");
        assert_eq!(bob.party.core_state.name, "bob");
        assert_eq!(charlie.party.core_state.name, "charlie");
        assert_eq!(dave.party.core_state.name, "dave");

        let [dave, bob, charlie, alice] =
            group_state.members_mut(&["dave", "bob", "charlie", "alice"]);
        assert_eq!(alice.party.core_state.name, "alice");
        assert_eq!(bob.party.core_state.name, "bob");
        assert_eq!(charlie.party.core_state.name, "charlie");
        assert_eq!(dave.party.core_state.name, "dave");

        let [dave, bob] = group_state.members_mut(&["dave", "bob"]);
        assert_eq!(bob.party.core_state.name, "bob");
        assert_eq!(dave.party.core_state.name, "dave");

        let [alice, charlie] = group_state.members_mut(&["alice", "charlie"]);
        assert_eq!(alice.party.core_state.name, "alice");
        assert_eq!(charlie.party.core_state.name, "charlie");
    }
    #[openmls_test]
    pub fn simpler_example() {
        let alice_party = CorePartyState::<Provider>::new("alice");
        let bob_party = CorePartyState::<Provider>::new("bob");
        let charlie_party = CorePartyState::<Provider>::new("charlie");
        let dave_party = CorePartyState::<Provider>::new("dave");

        let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
        let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
        let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
        let dave_pre_group = dave_party.generate_pre_group(ciphersuite);

        // Create config
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();

        // Join config
        let mls_group_join_config = mls_group_create_config.join_config().clone();

        // Initialize the group state
        let group_id = GroupId::from_slice(b"test");
        let mut group_state =
            GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

        group_state
            .add_member(AddMemberConfig {
                adder: "alice",
                addees: vec![bob_pre_group, charlie_pre_group],
                join_config: mls_group_join_config.clone(),
                tree: None,
            })
            .expect("Could not add member");

        group_state.assert_membership();

        group_state
            .add_member(AddMemberConfig {
                adder: "bob",
                addees: vec![dave_pre_group],
                join_config: mls_group_join_config,
                tree: None,
            })
            .expect("Could not add member");

        group_state.assert_membership();
    }

    #[openmls_test]
    pub fn simple_example() {
        let alice_party = CorePartyState::<Provider>::new("alice");
        let bob_party = CorePartyState::<Provider>::new("bob");

        let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
        let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

        // Get the key package for Bob
        // TODO: should key package be regenerated each time?
        let bob_key_package = bob_pre_group.key_package_bundle.key_package.clone();

        // Create config
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();

        // Join config
        let mls_group_join_config = mls_group_create_config.join_config().clone();

        // Initialize the group state
        let group_id = GroupId::from_slice(b"test");
        let mut group_state =
            GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

        // Get a mutable reference to Alice's group representation
        let [alice] = group_state.members_mut(&["alice"]);

        // Build a commit with a single add proposal
        let bundle = alice
            .build_commit_and_stage(move |builder| {
                let add_proposal = Proposal::Add(AddProposal {
                    key_package: bob_key_package,
                });

                // ...add more proposals here...

                builder
                    .consume_proposal_store(false)
                    .add_proposal(add_proposal)
            })
            .expect("Could not stage commit");

        // Deliver and apply welcome to Bob
        let welcome = bundle.welcome().unwrap().clone();
        group_state
            .deliver_and_apply_welcome(bob_pre_group, mls_group_join_config, welcome, None)
            .expect("Error delivering and applying welcome");

        let [alice] = group_state.members_mut(&["alice"]);

        let staged_commit = alice.group.pending_commit().unwrap().clone();

        alice
            .group
            .merge_staged_commit(&alice.party.core_state.provider, staged_commit)
            .expect("Error merging staged commit");

        group_state.assert_membership();
    }
}
