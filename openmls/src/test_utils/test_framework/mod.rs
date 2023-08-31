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

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{hash_ref::KeyPackageRef, *},
    credentials::*,
    framing::*,
    group::*,
    key_packages::*,
    messages::*,
    treesync::{node::Node, LeafNode, RatchetTree, RatchetTreeIn},
};
use ::rand::{rngs::OsRng, RngCore};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::OpenMlsKeyStore,
    types::{Ciphersuite, HpkeKeyPair, SignatureScheme},
    OpenMlsProvider,
};
use rayon::prelude::*;
use std::{collections::HashMap, sync::RwLock};
use tls_codec::*;

pub mod client;
pub mod errors;

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
    pub public_tree: RatchetTree,
    pub exporter_secret: Vec<u8>,
}

impl Group {
    /// Return the identity of a random member of the group.
    pub fn random_group_member(&self) -> (u32, Vec<u8>) {
        let index = (OsRng.next_u32() as usize) % self.members.len();
        let (i, identity) = self.members[index].clone();
        (i as u32, identity)
    }
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn members(&self) -> impl Iterator<Item = (u32, Vec<u8>)> + '_ {
        self.members
            .clone()
            .into_iter()
            .map(|(index, id)| (index as u32, id))
    }
}

#[derive(Debug)]
pub enum ActionType {
    Commit,
    Proposal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodecUse {
    SerializedMessages,
    StructMessages,
}

/// `MlsGroupTestSetup` is the main struct of the framework. It contains the
/// state of all clients. The `waiting_for_welcome` field acts as a temporary
/// store for `KeyPackage`s that are used to add new members to groups. Note,
/// that the `MlsGroupTestSetup` can only be initialized with a fixed number of
/// clients and that `create_clients` has to be called before it can be
/// otherwise used.
pub struct MlsGroupTestSetup {
    // The clients identity is its position in the vector in be_bytes.
    pub clients: RwLock<HashMap<Vec<u8>, RwLock<Client>>>,
    pub groups: RwLock<HashMap<GroupId, Group>>,
    // This maps key package hashes to client ids.
    pub waiting_for_welcome: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
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
            for ciphersuite in crypto.crypto().supported_ciphersuites().iter() {
                let credential = Credential::new(identity.clone(), CredentialType::Basic).unwrap();
                let signature_keys =
                    SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                signature_keys.store(crypto.key_store()).unwrap();
                let signature_key = OpenMlsSignaturePublicKey::new(
                    signature_keys.public().into(),
                    signature_keys.signature_scheme(),
                )
                .unwrap();

                credentials.insert(
                    *ciphersuite,
                    CredentialWithKey {
                        credential,
                        signature_key: signature_key.into(),
                    },
                );
            }
            let client = Client {
                identity: identity.clone(),
                credentials,
                crypto,
                groups: RwLock::new(HashMap::new()),
            };
            clients.insert(identity, RwLock::new(client));
        }
        let groups = RwLock::new(HashMap::new());
        let waiting_for_welcome = RwLock::new(HashMap::new());
        MlsGroupTestSetup {
            clients: RwLock::new(clients),
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
        ciphersuite: Ciphersuite,
    ) -> Result<KeyPackage, SetupError> {
        let key_package = client.get_fresh_key_package(ciphersuite)?;
        self.waiting_for_welcome
            .write()
            .expect("An unexpected error occurred.")
            .insert(
                key_package
                    .hash_ref(client.crypto.crypto())?
                    .as_slice()
                    .to_vec(),
                client.identity.clone(),
            );
        Ok(key_package)
    }

    /// Convert an index in the tree into the corresponding identity.
    pub fn identity_by_index(&self, index: usize, group: &Group) -> Option<Vec<u8>> {
        let (_, id) = group
            .members
            .iter()
            .find(|(leaf_index, _)| index == *leaf_index)
            .expect("Couldn't find member at leaf index");
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let client = clients
            .get(id)
            .expect("An unexpected error occurred.")
            .read()
            .expect("An unexpected error occurred.");
        client.identity(&group.group_id)
    }

    /// Convert an identity in the tree into the corresponding key package reference.
    pub fn identity_by_id(&self, id: &[u8], group: &Group) -> Option<Vec<u8>> {
        let (_, id) = group
            .members
            .iter()
            .find(|(_, leaf_id)| id == leaf_id)
            .expect("Couldn't find member at leaf index");
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let client = clients
            .get(id)
            .expect("An unexpected error occurred.")
            .read()
            .expect("An unexpected error occurred.");
        client.identity(&group.group_id)
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
        let clients = self.clients.read().expect("An unexpected error occurred.");
        for egs in welcome.secrets() {
            let client_id = self
                .waiting_for_welcome
                .write()
                .expect("An unexpected error occurred.")
                .remove(egs.new_member().as_slice())
                .ok_or(SetupError::NoFreshKeyPackage)?;
            let client = clients
                .get(&client_id)
                .expect("An unexpected error occurred.")
                .read()
                .expect("An unexpected error occurred.");
            client.join_group(
                group.group_config.clone(),
                welcome.clone(),
                Some(group.public_tree.clone().into()),
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
        message: &MlsMessageIn,
    ) -> Result<(), ClientError> {
        // Test serialization if mandated by config
        let message: ProtocolMessage = match self.use_codec {
            CodecUse::SerializedMessages => {
                let mls_message_out: MlsMessageOut = message.clone().into();
                let serialized_message = mls_message_out.tls_serialize_detached()?;

                MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())?
            }
            CodecUse::StructMessages => message.clone(),
        }
        .into_protocol_message()
        .expect("Unexptected message type.");
        let clients = self.clients.read().expect("An unexpected error occurred.");
        // Distribute message to all members, except to the sender in the case of application messages
        let results: Result<Vec<_>, _> = group
            .members
            .par_iter()
            .filter_map(|(_index, member_id)| {
                if message.content_type() == ContentType::Application && member_id == sender_id {
                    None
                } else {
                    Some(member_id)
                }
            })
            .map(|member_id| {
                let member = clients
                    .get(member_id)
                    .expect("An unexpected error occurred.")
                    .read()
                    .expect("An unexpected error occurred.");
                member.receive_messages_for_group(&message, sender_id)
            })
            .collect();

        // Check if we received an error
        results?;
        // Get the current tree and figure out who's still in the group.
        let sender = clients
            .get(sender_id)
            .expect("An unexpected error occurred.")
            .read()
            .expect("An unexpected error occurred.");
        let sender_groups = sender.groups.read().expect("An unexpected error occurred.");
        let sender_group = sender_groups
            .get(&group.group_id)
            .expect("An unexpected error occurred.");
        group.members = sender
            .get_members_of_group(&group.group_id)?
            .iter()
            .map(
                |Member {
                     index, credential, ..
                 }| { (index.usize(), credential.identity().to_vec()) },
            )
            .collect();
        group.public_tree = sender_group.export_ratchet_tree();
        group.exporter_secret =
            sender_group.export_secret(sender.crypto.crypto(), "test", &[], 32)?;
        Ok(())
    }

    /// Check if the public tree and the exporter secret with label "test" and
    /// length of the given group is the same for each group member. It also has
    /// each group member encrypt an application message and delivers all of
    /// these messages to all other members. This function panics if any of the
    /// above tests fail.
    pub fn check_group_states(&self, group: &mut Group) {
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let messages = group
            .members
            .par_iter()
            .filter_map(|(_, m_id)| {
                let m = clients
                    .get(m_id)
                    .expect("An unexpected error occurred.")
                    .read()
                    .expect("An unexpected error occurred.");
                let mut group_states = m.groups.write().expect("An unexpected error occurred.");
                // Some group members may not have received their welcome messages yet.
                if let Some(group_state) = group_states.get_mut(&group.group_id) {
                    assert_eq!(group_state.export_ratchet_tree(), group.public_tree);
                    assert_eq!(
                        group_state
                            .export_secret(m.crypto.crypto(), "test", &[], 32)
                            .expect("An unexpected error occurred."),
                        group.exporter_secret
                    );
                    // Get the signature public key to read the signer from the
                    // key store.
                    let signature_pk = group_state.own_leaf().unwrap().signature_key();
                    let signer = SignatureKeyPair::read(
                        m.crypto.key_store(),
                        signature_pk.as_slice(),
                        group_state.ciphersuite().signature_algorithm(),
                    )
                    .unwrap();
                    let message = group_state
                        .create_message(&m.crypto, &signer, "Hello World!".as_bytes())
                        .expect("Error composing message while checking group states.");
                    Some((m_id.to_vec(), message))
                } else {
                    None
                }
            })
            .collect::<Vec<(Vec<u8>, MlsMessageOut)>>();
        drop(clients);
        for (sender_id, message) in messages {
            self.distribute_to_members(&sender_id, group, &message.into())
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
        let clients = self.clients.read().expect("An unexpected error occurred.");
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
    pub fn create_group(&self, ciphersuite: Ciphersuite) -> Result<GroupId, SetupError> {
        // Pick a random group creator.
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let group_creator_id = ((OsRng.next_u32() as usize) % clients.len())
            .to_be_bytes()
            .to_vec();
        let group_creator = clients
            .get(&group_creator_id)
            .expect("An unexpected error occurred.")
            .read()
            .expect("An unexpected error occurred.");
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group_id = group_creator.create_group(self.default_mgc.clone(), ciphersuite)?;
        let creator_groups = group_creator
            .groups
            .read()
            .expect("An unexpected error occurred.");
        let group = creator_groups
            .get(&group_id)
            .expect("An unexpected error occurred.");
        let public_tree = group.export_ratchet_tree();
        let exporter_secret =
            group.export_secret(group_creator.crypto.crypto(), "test", &[], 32)?;
        let member_ids = vec![(0, group_creator_id)];
        let group = Group {
            group_id: group_id.clone(),
            members: member_ids,
            ciphersuite,
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
        ciphersuite: Ciphersuite,
    ) -> Result<GroupId, SetupError> {
        // Create the initial group.
        let group_id = self.create_group(ciphersuite)?;

        let mut groups = self.groups.write().expect("An unexpected error occurred.");
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
            self.add_clients(ActionType::Commit, group, &adder_id.1, members_to_add)?;
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
        leaf_node: Option<LeafNode>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let client = clients
            .get(client_id)
            .ok_or(SetupError::UnknownClientId)?
            .read()
            .expect("An unexpected error occurred.");
        let (messages, welcome_option, _) =
            client.self_update(action_type, &group.group_id, leaf_node)?;
        self.distribute_to_members(&client.identity, group, &messages.into())?;
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
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let adder = clients
            .get(adder_id)
            .ok_or(SetupError::UnknownClientId)?
            .read()
            .expect("An unexpected error occurred.");
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
                .read()
                .expect("An unexpected error occurred.");
            let key_package = self.get_fresh_key_package(&addee, group.ciphersuite)?;
            key_packages.push(key_package);
        }
        let (messages, welcome_option, _) =
            adder.add_members(action_type, &group.group_id, &key_packages)?;
        for message in messages {
            self.distribute_to_members(adder_id, group, &message.into())?;
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
        target_members: &[LeafNodeIndex],
    ) -> Result<(), SetupError> {
        let clients = self.clients.read().expect("An unexpected error occurred.");
        let remover = clients
            .get(remover_id)
            .ok_or(SetupError::UnknownClientId)?
            .read()
            .expect("An unexpected error occurred.");
        let (messages, welcome_option, _) =
            remover.remove_members(action_type, &group.group_id, target_members)?;
        for message in messages {
            self.distribute_to_members(remover_id, group, &message.into())?;
        }
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// This function picks a random member of group `group` and has them
    /// perform a random commit- or proposal action. TODO #133: This won't work
    /// yet due to the missing proposal validation.
    pub fn perform_random_operation(&self, group: &mut Group) -> Result<(), SetupError> {
        // Who's going to do it?
        let member_id = group.random_group_member();
        println!("Member performing the operation: {member_id:?}");

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
                println!("Performing a self-update with action type: {action_type:?}");
                self.self_update(action_type, group, &member_id.1, None)?;
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
                        .find(|(_, identity)| identity == &member_id.1)
                        .expect("An unexpected error occurred.")
                        .clone();
                    println!("Index of the member performing the {action_type:?}: {own_index:?}");

                    let mut target_member_leaf_indices = Vec::new();
                    let mut target_member_identities = Vec::new();
                    let clients = self.clients.read().expect("An unexpected error occurred.");
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
                        while leaf_index == own_index
                            || target_member_identities.contains(&identity)
                        {
                            member_list_index = (OsRng.next_u32() as usize) % group.members.len();
                            let (new_leaf_index, new_identity) =
                                group.members[member_list_index].clone();
                            leaf_index = new_leaf_index;
                            identity = new_identity;
                        }
                        let client = clients
                            .get(&identity)
                            .expect("An unexpected error occurred.")
                            .read()
                            .expect("An unexpected error occurred.");
                        let client_group =
                            client.groups.read().expect("An unexpected error occurred.");
                        let client_group = client_group
                            .get(&group.group_id)
                            .expect("An unexpected error occurred.");
                        target_member_leaf_indices.push(client_group.own_leaf_index());
                        target_member_identities.push(identity);
                    }
                    self.remove_clients(
                        action_type,
                        group,
                        &member_id.1,
                        &target_member_leaf_indices,
                    )?
                };
            }
            2 => {
                // First, figure out if there are clients left to add.
                let clients_left = self
                    .clients
                    .read()
                    .expect("An unexpected error occurred.")
                    .len()
                    - group.members.len();
                if clients_left > 0 {
                    let number_of_adds = (((OsRng.next_u32() as usize) % clients_left) % 5) + 1;
                    let new_member_ids = self
                        .random_new_members_for_group(group, number_of_adds)
                        .expect("An unexpected error occurred.");
                    println!("{action_type:?}: Adding new clients: {new_member_ids:?}");
                    // Have the adder add them to the group.
                    self.add_clients(action_type, group, &member_id.1, new_member_ids)?;
                }
            }
            _ => return Err(SetupError::Unknown),
        };
        Ok(())
    }
}
