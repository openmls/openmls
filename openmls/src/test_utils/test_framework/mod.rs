//! This crate provides a framework to set up clients and groups using the
//! OpenMLS mls_group API. To use the framework, start by creating a new
//! `TestSetup` with a number of clients. After that, `create_clients` has to be
//! called before the the `TestSetup` can be used.
//!
//! Note that due to lifetime issues, no new clients can be created after
//! initialization.
//!
//! After initialization, the `TestSetup` enables the creation of groups using
//! `create_group`, which simply creates a one-member group, or
//! `create_random_group`, which creates a group of the given size with random
//! clients.
//!
//! Existing groups are represented by the `groups` field of the `TestSetup` and
//! initial members can be instructed to either propose or commit adds, removes
//! or updates via the corresponding functions of `TestSetup`. Note, that these
//! functions require a `&Group` reference, which can be obtained via the
//! `groups` field. When using these functions, the `TestSetup` fills the role
//! of the DS and automatically distributes the required KeyPackages and
//! resulting mls messages to the individual clients. Alternatively, the clients
//! can be manipulated manually via the `Client` struct, which contains their
//! group states.

#![allow(dead_code)]
use crate::framing::MlsMessageIn;
/// We allow dead code here due to the following issue:
/// https://github.com/rust-lang/rust/issues/46379, which would otherwise create
/// a lot of unused code warnings.
use crate::{config::*, prelude::*, tree::node::Node};
use ::rand::{rngs::OsRng, RngCore};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;
use std::{cell::RefCell, collections::HashMap};

pub mod client;
pub mod errors;
pub mod messages;

use self::client::*;
use self::errors::*;

#[derive(Clone)]
/// The `Group` struct represents the "global" shared state of the group. Note,
/// that this state is only consistent if operations are conducted as per spec
/// and messages are distributed correctly to all clients via the
/// `distribute_to_members` function of `TestSetup`, which also updates the
/// `public_tree` field.
pub struct Group {
    pub group_id: GroupId,
    pub members: Vec<(usize, Vec<u8>)>,
    pub ciphersuite: Ciphersuite,
    pub group_config: MlsGroupConfig,
    pub public_tree: Vec<Option<Node>>,
    pub exporter_secret: Vec<u8>,
}

impl Group {
    /// Return the identity of a random member of the group.
    pub fn random_group_member(&self) -> Vec<u8> {
        let index = (OsRng.next_u32() as usize) % self.members.len();
        // We can unwrap here, because the index is scoped with the size of the
        // HashSet.
        let (_, identity) = self.members[index].clone();
        identity
    }
}

#[derive(Debug)]
pub enum ActionType {
    Commit,
    Proposal,
}

#[derive(Debug, PartialEq)]
pub enum CodecUse {
    SerializedMessages,
    StructMessages,
}

/// `MlsGroupTestSetup` is the main struct of the framework. It contains the
/// state of all clients, as well as the global `KeyStore` containing the
/// clients' `CredentialBundles`. The `waiting_for_welcome` field acts as a
/// temporary store for `KeyPackage`s that are used to add new members to
/// groups. Note, that the `MlsGroupTestSetup` can only be initialized with a
/// fixed number of clients and that `create_clients` has to be called before it
/// can be otherwise used.
pub struct MlsGroupTestSetup {
    // The clients identity is its position in the vector in be_bytes.
    pub clients: RefCell<HashMap<Vec<u8>, RefCell<Client>>>,
    pub groups: RefCell<HashMap<GroupId, Group>>,
    // This maps key package hashes to client ids.
    pub waiting_for_welcome: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    pub default_mgc: MlsGroupConfig,
    /// Flag to indicate if messages should be serialized and de-serialized as
    /// part of message distribution
    pub use_codec: CodecUse,
}

// Some notes regarding the layout of the `MlsGroupTestSetup` implementation
// below: The references to the credentials in the MlsGroups (in the
// clients) are essentially references to the keystore, which in turns means
// they are references to the top-level object, i.e. the setup.
//
// As a result, we can't have mutable references to the setup, because we have
// living (immutable) references to the keystore floating around. As a follow-up
// result, we need to populate the keystore _completely_ before distributing the
// references, as we can't mutably reference the keystore.
//
//   * Note, that (to my knowledge) we can't have the keystore live in a
//   refcell, because then the references are based on the local `borrow()`ed
//   object and won't live long enough.
//
// Finally, this means we have to initialize the KeyStore before we create the
// MlsGroupTestSetup object and we can create the clients (which contain the
// references to the KeyStore) only after we do that. This has to happen in the
// context that the `MlsGroupTestSetup` lives in, because otherwise the
// references don't live long enough.

impl MlsGroupTestSetup {
    /// Create a new `MlsGroupTestSetup` with the given default
    /// `MlsGroupConfig` and the given number of clients. For lifetime
    /// reasons, `create_clients` has to be called in addition with the same
    /// number of clients.
    pub fn new(default_mgc: MlsGroupConfig, number_of_clients: usize, use_codec: CodecUse) -> Self {
        let mut clients = HashMap::new();
        for i in 0..number_of_clients {
            let identity = i.to_be_bytes().to_vec();
            // For now, everyone supports all ciphersuites.
            let crypto = OpenMlsRustCrypto::default();
            let mut credentials = HashMap::new();
            for ciphersuite in Config::supported_ciphersuite_names() {
                let cb = CredentialBundle::new(
                    identity.clone(),
                    CredentialType::Basic,
                    SignatureScheme::from(*ciphersuite),
                    &crypto,
                )
                .expect("An unexpected error occurred.");
                let credential = cb.credential().clone();
                crypto
                    .key_store()
                    .store(cb.credential().signature_key(), &cb)
                    .expect("An unexpected error occurred.");
                credentials.insert(*ciphersuite, credential);
            }
            let client = Client {
                identity: identity.clone(),
                credentials,
                crypto,
                groups: RefCell::new(HashMap::new()),
            };
            clients.insert(identity, RefCell::new(client));
        }
        let groups = RefCell::new(HashMap::new());
        let waiting_for_welcome = RefCell::new(HashMap::new());
        MlsGroupTestSetup {
            clients: RefCell::new(clients),
            groups,
            waiting_for_welcome,
            default_mgc,
            use_codec,
        }
    }

    /// Create a fresh `KeyPackage` for client `client` for use when adding it
    /// to a group. The `KeyPackageBundle` will be fetched automatically when
    /// delivering the `Welcome` via `deliver_welcome`. This function throws an
    /// error if the client does not support the given ciphersuite.
    pub fn get_fresh_key_package(
        &self,
        client: &Client,
        ciphersuite: &Ciphersuite,
    ) -> Result<KeyPackage, SetupError> {
        let key_package = client.get_fresh_key_package(&[ciphersuite.name()])?;
        self.waiting_for_welcome
            .borrow_mut()
            .insert(key_package.hash(&client.crypto)?, client.identity.clone());
        Ok(key_package)
    }

    /// Deliver a Welcome message to the intended recipients. It uses the given
    /// group `group` to obtain the current public tree of the group. Note, that
    /// this tree only exists if `distribute_to_members` was previously used to
    /// distribute the commit adding the members to the group. This function
    /// will throw an error if no key package was previously created for the
    /// client by `get_fresh_key_package`.
    pub fn deliver_welcome(&self, welcome: Welcome, group: &Group) -> Result<(), SetupError> {
        // Serialize and de-serialize the Welcome if the bit was set.
        let welcome = match self.use_codec {
            CodecUse::SerializedMessages => {
                let serialized_welcome = welcome
                    .tls_serialize_detached()
                    .map_err(ClientError::TlsCodecError)?;
                Welcome::tls_deserialize(&mut serialized_welcome.as_slice())
                    .map_err(ClientError::TlsCodecError)?
            }
            CodecUse::StructMessages => welcome,
        };
        if self.use_codec == CodecUse::SerializedMessages {}
        let clients = self.clients.borrow();
        for egs in welcome.secrets() {
            let client_id = self
                .waiting_for_welcome
                .borrow_mut()
                .remove(egs.key_package_hash.as_slice())
                .ok_or(SetupError::NoFreshKeyPackage)?;
            let client = clients
                .get(&client_id)
                .expect("An unexpected error occurred.")
                .borrow();
            client.join_group(
                group.group_config.clone(),
                welcome.clone(),
                Some(group.public_tree.clone()),
            )?;
        }
        Ok(())
    }

    /// Distribute a set of messages sent by the sender with identity
    /// `sender_id` to their intended recipients in group `Group`. This function
    /// also verifies that all members of that group agree on the public tree.
    pub fn distribute_to_members(
        &self,
        // We need the sender to know a group member that we know can not have
        // been removed from the group.
        sender_id: &[u8],
        group: &mut Group,
        message: &MlsMessageOut,
    ) -> Result<(), ClientError> {
        // Test serialization if mandated by config
        let message = match self.use_codec {
            CodecUse::SerializedMessages => {
                let serialized_message =
                    MlsMessageIn::from(message.clone()).tls_serialize_detached()?;
                MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())?
            }
            CodecUse::StructMessages => MlsMessageIn::from(message.clone()),
        };
        let clients = self.clients.borrow();
        // Distribute message to all members.
        for (_index, member_id) in &group.members {
            let member = clients
                .get(member_id)
                .expect("An unexpected error occurred.")
                .borrow();
            member.receive_messages_for_group(&message)?;
        }
        // Get the current tree and figure out who's still in the group.
        let sender = clients
            .get(sender_id)
            .expect("An unexpected error occurred.")
            .borrow();
        let sender_groups = sender.groups.borrow();
        let sender_group = sender_groups
            .get(&group.group_id)
            .expect("An unexpected error occurred.");
        group.members = sender
            .get_members_of_group(&group.group_id)?
            .iter()
            .map(|(index, cred)| (*index, cred.identity().to_vec()))
            .collect();
        group.public_tree = sender_group.export_ratchet_tree();
        group.exporter_secret = sender_group.export_secret(&sender.crypto, "test", &[], 32)?;
        Ok(())
    }

    /// Check if the public tree and the exporter secret with label "test" and
    /// length of the given group is the same for each group member. It also has
    /// each group member encrypt an application message and delivers all of
    /// these messages to all other members. This function panics if any of the
    /// above tests fail.
    pub fn check_group_states(&self, group: &mut Group) {
        let clients = self.clients.borrow();
        let mut messages = Vec::new();
        for (_, m_id) in &group.members {
            let m = clients
                .get(m_id)
                .expect("An unexpected error occurred.")
                .borrow();
            let mut group_states = m.groups.borrow_mut();
            // Some group members may not have received their welcome messages yet.
            if let Some(group_state) = group_states.get_mut(&group.group_id) {
                assert_eq!(group_state.export_ratchet_tree(), group.public_tree);
                assert_eq!(
                    group_state
                        .export_secret(&m.crypto, "test", &[], 32)
                        .expect("An unexpected error occurred."),
                    group.exporter_secret
                );
                let message = group_state
                    .create_message(&m.crypto, "Hello World!".as_bytes())
                    .expect("Error composing message while checking group states.");
                messages.push((m_id.clone(), message));
            };
        }
        drop(clients);
        for (sender_id, message) in messages {
            self.distribute_to_members(&sender_id, group, &message)
                .expect("Error sending messages to clients while checking group states.");
        }
    }

    /// Get `number_of_members` new members for the given group `group` for use
    /// with the `add_members` function. If not enough clients are left that are
    /// not already members of this group, this function will return an error.
    /// TODO #310: Make this function ensure that the given members support the
    /// ciphersuite of the group.
    pub fn random_new_members_for_group(
        &self,
        group: &Group,
        number_of_members: usize,
    ) -> Result<Vec<Vec<u8>>, SetupError> {
        let clients = self.clients.borrow();
        if number_of_members + group.members.len() > clients.len() {
            return Err(SetupError::NotEnoughClients);
        }
        let mut new_member_ids: Vec<Vec<u8>> = Vec::new();

        for _ in 0..number_of_members {
            let is_in_new_members = |client_id| {
                new_member_ids
                    .iter()
                    .any(|new_member_id| client_id == new_member_id)
            };
            let is_in_group = |client_id| {
                group
                    .members
                    .iter()
                    .any(|(_, member_id)| client_id == member_id)
            };
            // We can unwrap here, because we checked that enough eligible
            // members exist.
            let new_member_id = clients
                .keys()
                .find(|&client_id| !is_in_group(client_id) && !is_in_new_members(client_id))
                .expect("An unexpected error occurred.");
            new_member_ids.push(new_member_id.clone());
        }
        Ok(new_member_ids)
    }

    /// Have a random client create a new group with ciphersuite `ciphersuite`
    /// and return the `GroupId`. Only works reliably if all clients support all
    /// ciphersuites, as it will throw an error if the randomly chosen client
    /// does not support the given ciphersuite. TODO #310: Fix to always work
    /// reliably, probably by introducing a mapping from ciphersuite to the set
    /// of client ids supporting it.
    pub fn create_group(&self, ciphersuite: &Ciphersuite) -> Result<GroupId, SetupError> {
        // Pick a random group creator.
        let clients = self.clients.borrow();
        let group_creator_id = ((OsRng.next_u32() as usize) % clients.len())
            .to_be_bytes()
            .to_vec();
        let group_creator = clients
            .get(&group_creator_id)
            .expect("An unexpected error occurred.")
            .borrow();
        let mut groups = self.groups.borrow_mut();
        let group_id = GroupId::from_slice(&groups.len().to_string().into_bytes());

        group_creator.create_group(group_id.clone(), self.default_mgc.clone(), ciphersuite)?;
        let creator_groups = group_creator.groups.borrow();
        let group = creator_groups
            .get(&group_id)
            .expect("An unexpected error occurred.");
        let public_tree = group.export_ratchet_tree();
        let exporter_secret = group.export_secret(&group_creator.crypto, "test", &[], 32)?;
        let member_ids = vec![(0, group_creator_id)];
        let group = Group {
            group_id: group_id.clone(),
            members: member_ids,
            ciphersuite: ciphersuite.clone(),
            group_config: self.default_mgc.clone(),
            public_tree,
            exporter_secret,
        };
        groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    /// Create a random group of size `group_size` and return the `GroupId`
    pub fn create_random_group(
        &self,
        target_group_size: usize,
        ciphersuite: &Ciphersuite,
    ) -> Result<GroupId, SetupError> {
        // Create the initial group.
        let group_id = self.create_group(ciphersuite)?;

        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("An unexpected error occurred.");

        // Get new members to add to the group.
        let mut new_members = self.random_new_members_for_group(group, target_group_size - 1)?;

        // Add new members bit by bit.
        while !new_members.is_empty() {
            // Pick a random adder.
            let adder_id = group.random_group_member();
            // Add between 1 and 5 new members.
            let number_of_adds = ((OsRng.next_u32() as usize) % 5 % new_members.len()) + 1;
            let members_to_add = new_members.drain(0..number_of_adds).collect();
            self.add_clients(ActionType::Commit, group, &adder_id, members_to_add)?;
        }
        Ok(group_id)
    }

    /// Have the client with identity `client_id` either propose or commit
    /// (depending on `action_type`) a self update in group `group`. Will throw
    /// an error if the client is not actually a member of group `group`.
    pub fn self_update(
        &self,
        action_type: ActionType,
        group: &mut Group,
        client_id: &[u8],
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let client = clients
            .get(client_id)
            .ok_or(SetupError::UnknownClientId)?
            .borrow();
        let (messages, welcome_option) =
            client.self_update(action_type, &group.group_id, key_package_bundle_option)?;
        self.distribute_to_members(&client.identity, group, &messages)?;
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// Has the `adder` either propose or commit (depending on the
    /// `action_type`) an add of the `addee` to the Group `group`. Returns an
    /// error if
    /// * the `adder` is not part of the group
    /// * the `addee` is already part of the group
    /// * the `addee` doesn't support the group's ciphersuite.
    pub fn add_clients(
        &self,
        action_type: ActionType,
        group: &mut Group,
        adder_id: &[u8],
        addees: Vec<Vec<u8>>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let adder = clients
            .get(adder_id)
            .ok_or(SetupError::UnknownClientId)?
            .borrow();
        if group
            .members
            .iter()
            .any(|(_, id)| addees.iter().any(|client_id| client_id == id))
        {
            return Err(SetupError::ClientAlreadyInGroup);
        }
        let mut key_packages = Vec::new();
        for addee_id in &addees {
            let addee = clients
                .get(addee_id)
                .ok_or(SetupError::UnknownClientId)?
                .borrow();
            let key_package = self.get_fresh_key_package(&addee, &group.ciphersuite)?;
            key_packages.push(key_package);
        }
        let (messages, welcome_option) =
            adder.add_members(action_type, &group.group_id, &key_packages)?;
        for message in &messages {
            self.distribute_to_members(adder_id, group, message)?;
        }
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// Has the `remover` propose or commit (depending on the `action_type`) the
    /// removal the members in in the given leaf indices in the tree from the
    /// Group `group`. If the `remover` or one of the `target_members` is not
    /// part of the group, it returns an error.
    pub fn remove_clients_by_index(
        &self,
        action_type: ActionType,
        group: &mut Group,
        remover_id: &[u8],
        target_indices: &[usize],
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let remover = clients
            .get(remover_id)
            .ok_or(SetupError::UnknownClientId)?
            .borrow();
        let client_in_group = group.members.iter().any(|(member_index, _)| {
            target_indices
                .iter()
                .any(|target_index| target_index == member_index)
        });
        if !client_in_group {
            return Err(SetupError::ClientNotInGroup);
        }
        let (messages, welcome_option) =
            remover.remove_members(action_type, &group.group_id, target_indices)?;
        for message in &messages {
            self.distribute_to_members(remover_id, group, message)?;
        }
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// Has the `remover` propose or commit (depending on the `action_type`) the
    /// removal the `target_members` from the Group `group`. If the `remover` or
    /// one of the `target_members` is not part of the group, it returns an
    /// error.
    pub fn remove_clients(
        &self,
        action_type: ActionType,
        group: &mut Group,
        remover_id: &[u8],
        target_members: Vec<Vec<u8>>,
    ) -> Result<(), SetupError> {
        let mut target_indices = Vec::new();
        for target in &target_members {
            let (index, _) = group
                .members
                .iter()
                .find(|(_, identity)| identity == target)
                .ok_or(SetupError::ClientNotInGroup)?;
            target_indices.push(*index);
        }
        self.remove_clients_by_index(action_type, group, remover_id, &target_indices)?;
        Ok(())
    }

    /// This function picks a random member of group `group` and has them
    /// perform a random commit- or proposal action. TODO #133: This won't work
    /// yet due to the missing proposal validation.
    pub fn perform_random_operation(&self, group: &mut Group) -> Result<(), SetupError> {
        // Who's going to do it?
        let member_id = group.random_group_member();
        println!("Member performing the operation: {:?}", member_id);

        // TODO: Do both things.
        let action_type = match (OsRng.next_u32() as usize) % 2 {
            0 => ActionType::Proposal,
            1 => ActionType::Commit,
            _ => return Err(SetupError::Unknown),
        };

        // TODO: Do multiple things.
        let operation_type = (OsRng.next_u32() as usize) % 3;
        match operation_type {
            0 => {
                println!(
                    "Perfoming a self-update with action type: {:?}",
                    action_type
                );
                self.self_update(action_type, group, &member_id, None)?;
            }
            1 => {
                // If it's a single-member group, don't remove anyone.
                if group.members.len() > 1 {
                    // How many members?
                    let number_of_removals =
                        (((OsRng.next_u32() as usize) % group.members.len()) % 5) + 1;

                    let (own_index, _) = group
                        .members
                        .iter()
                        .find(|(_, identity)| identity == &member_id)
                        .expect("An unexpected error occurred.")
                        .clone();
                    println!(
                        "Index of the member performing the {:?}: {:?}",
                        action_type, own_index
                    );

                    let mut target_member_ids = Vec::new();
                    // Get the client references, as opposed to just the member indices.
                    println!("Removing members:");
                    for _ in 0..number_of_removals {
                        // Get a random index.
                        let mut member_list_index =
                            (OsRng.next_u32() as usize) % group.members.len();
                        // Re-sample until the index is not our own index and
                        // not one that is not already being removed.
                        let (mut leaf_index, mut identity) =
                            group.members[member_list_index].clone();
                        while leaf_index == own_index || target_member_ids.contains(&identity) {
                            member_list_index = (OsRng.next_u32() as usize) % group.members.len();
                            let (new_leaf_index, new_identity) =
                                group.members[member_list_index].clone();
                            leaf_index = new_leaf_index;
                            identity = new_identity;
                        }
                        target_member_ids.push(identity);
                    }
                    self.remove_clients(action_type, group, &member_id, target_member_ids)?
                };
            }
            2 => {
                // First, figure out if there are clients left to add.
                let clients_left = self.clients.borrow().len() - group.members.len();
                if clients_left > 0 {
                    let number_of_adds = (((OsRng.next_u32() as usize) % clients_left) % 5) + 1;
                    let new_member_ids = self
                        .random_new_members_for_group(group, number_of_adds)
                        .expect("An unexpected error occurred.");
                    println!(
                        "{:?}: Adding new clients: {:?}",
                        action_type, new_member_ids
                    );
                    // Have the adder add them to the group.
                    self.add_clients(action_type, group, &member_id, new_member_ids)?;
                }
            }
            _ => return Err(SetupError::Unknown),
        };
        Ok(())
    }
}
