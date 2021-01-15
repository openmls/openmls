#![allow(dead_code)]
/// We allow dead code here due to the following issue:
/// https://github.com/rust-lang/rust/issues/46379, which would otherwise create
/// a lot of unused code warnings.
use openmls::prelude::{node::Node, *};
use rand::{rngs::OsRng, RngCore};
use std::{cell::RefCell, collections::HashMap};

pub mod client;
pub mod default_callbacks;
pub mod errors;

use self::client::*;
use self::errors::*;

#[derive(Debug)]
pub struct KeyStore {
    // Maps a client Id and a ciphersuite to a CredentialBundle.
    credential_bundles: HashMap<(Vec<u8>, CiphersuiteName), CredentialBundle>,
}

impl<'ks> KeyStore {
    pub(crate) fn store_credentials(
        &mut self,
        client_id: Vec<u8>,
        credential_bundles: Vec<(CiphersuiteName, CredentialBundle)>,
    ) {
        for (cn, cb) in credential_bundles {
            self.credential_bundles.insert((client_id.clone(), cn), cb);
        }
    }

    pub(crate) fn get_credential(
        &self,
        client_id: &Vec<u8>,
        ciphersuite_name: CiphersuiteName,
    ) -> Option<&CredentialBundle> {
        let key = &(client_id.clone(), ciphersuite_name);
        self.credential_bundles.get(key)
    }
}

#[derive(Clone)]
pub struct Group {
    pub group_id: GroupId,
    pub members: Vec<(usize, Vec<u8>)>,
    pub ciphersuite: Ciphersuite,
    pub group_config: ManagedGroupConfig,
    pub public_tree: Vec<Option<Node>>,
}

impl Group {
    pub fn random_group_member(&self) -> Vec<u8> {
        let index = (OsRng.next_u32() as usize) % self.members.len();
        // We can unwrap here, because the index is scoped with the size of the
        // HashSet.
        let (_, identity) = self.members.iter().nth(index).unwrap().clone();
        identity
    }
}

pub enum ActionType {
    Commit,
    Proposal,
}

pub enum OperationType {
    Update,
    Add,
    Remove,
}

pub struct ManagedTestSetup<'client_lifetime> {
    pub number_of_clients: usize,
    // The clients identity is its position in the vector in be_bytes.
    pub clients: RefCell<HashMap<Vec<u8>, RefCell<Client<'client_lifetime>>>>,
    pub groups: RefCell<HashMap<GroupId, Group>>,
    pub key_store: KeyStore,
    // This maps key package hashes to client ids.
    pub waiting_for_welcome: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    pub default_mgc: ManagedGroupConfig,
}

// Some notes regarding the layout of the `ManagedTestSetup` implementation
// below: The references to the credentials in the ManagedGroups (in the
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
// ManagedTestSetup object and we can create the clients (which contain the
// references to the KeyStore) only after we do that. This has to happen in the
// context that the `ManagedTestSetup` lives in, because otherwise the
// references don't live long enough.

impl<'ks> ManagedTestSetup<'ks> {
    /// Create a new `ManagedTestSetup` with the given default
    /// `ManagedGroupConfig` and the given number of clients. For lifetime
    /// reasons, `create_clients` has to be called in addition with the same
    /// number of clients.
    pub fn new(default_mgc: ManagedGroupConfig, number_of_clients: usize) -> Self {
        let mut key_store = KeyStore {
            credential_bundles: HashMap::new(),
        };
        // Create credentials first to avoid borrowing issues.
        for i in 0..number_of_clients {
            let identity = i.to_be_bytes().to_vec();
            // For now, everyone supports all ciphersuites.
            let mut credential_bundles = Vec::new();
            for ciphersuite in &Config::supported_ciphersuite_names() {
                let credential_bundle =
                    CredentialBundle::new(identity.clone(), CredentialType::Basic, *ciphersuite)
                        .unwrap();
                credential_bundles.push((*ciphersuite, credential_bundle));
            }
            key_store.store_credentials(identity.clone(), credential_bundles);
        }
        let clients = RefCell::new(HashMap::new());
        let groups = RefCell::new(HashMap::new());
        let waiting_for_welcome = RefCell::new(HashMap::new());
        ManagedTestSetup {
            number_of_clients,
            clients,
            groups,
            key_store,
            waiting_for_welcome,
            default_mgc,
        }
    }

    pub fn create_clients(&'ks self) {
        for i in 0..self.number_of_clients {
            let identity = i.to_be_bytes().to_vec();
            // For now, everyone supports all ciphersuites.
            let _ciphersuites = Config::supported_ciphersuite_names();
            let mut credential_bundles = Vec::new();
            let key_package_bundles = RefCell::new(HashMap::new());
            let client = Client {
                identity: identity.clone(),
                _ciphersuites,
                key_store: &self.key_store,
                key_package_bundles,
                groups: RefCell::new(HashMap::new()),
            };
            for ciphersuite in &Config::supported_ciphersuite_names() {
                let credential_bundle =
                    CredentialBundle::new(identity.clone(), CredentialType::Basic, *ciphersuite)
                        .unwrap();
                credential_bundles.push((*ciphersuite, credential_bundle));
            }
            let mut clients = self.clients.borrow_mut();
            clients.insert(identity, RefCell::new(client));
            drop(clients);
        }
    }

    /// Create a fresh `KeyPackage` for client `client` for use when adding it
    /// to a group. The `KeyPackageBundle` will be fetched automatically when
    /// delivering the `Welcome` via `deliver_welcome`.
    pub fn get_fresh_key_package(&self, client: &Client, ciphersuite: &Ciphersuite) -> KeyPackage {
        let key_package = client.get_fresh_key_package(ciphersuite);
        println!("Storing key package with hash: {:?}", key_package.hash());
        self.waiting_for_welcome
            .borrow_mut()
            .insert(key_package.hash(), client.identity.clone());
        key_package
    }

    /// Deliver a Welcome message to group `group` to the intended recipients.
    pub fn deliver_welcome(&self, welcome: Welcome, group: &Group) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        for egs in welcome.secrets() {
            println!(
                "Trying to get key package with hash: {:?}",
                egs.key_package_hash
            );
            let client_id = match self
                .waiting_for_welcome
                .borrow_mut()
                .remove(&egs.key_package_hash)
            {
                Some(id) => id,
                None => return Err(SetupError::NoFreshKeyPackage),
            };
            let client = clients.get(&client_id).unwrap().borrow();
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
        sender_id: &Vec<u8>,
        group: &mut Group,
        messages: Vec<MLSMessage>,
    ) -> Result<(), ClientError> {
        let clients = self.clients.borrow();
        println!("Distributing and processing messages...");
        // Distribute message to all members.
        for (index, member_id) in &group.members {
            println!("Index: {:?}, Id: {:?}", index, member_id);
            let member = clients.get(member_id).unwrap().borrow();
            member.receive_messages_for_group(&group.group_id, messages.clone())?;
        }
        // Get the current tree and figure out who's still in the group.
        let sender = clients.get(sender_id).unwrap().borrow();
        let sender_groups = sender.groups.borrow();
        let sender_group = sender_groups.get(&group.group_id).unwrap();
        group.members = sender
            .get_members_of_group(&group.group_id)?
            .iter()
            .map(|(index, cred)| (index.clone(), cred.identity().clone()))
            .collect();
        group.public_tree = sender_group.export_ratchet_tree();
        drop(sender_group);
        drop(sender_groups);
        println!("Group members after distribution:");
        // Check that the group states of all members match.
        for (index, m_id) in &group.members {
            println!("Id: {:?}, Index: {:?}", m_id, index);
            let m = clients.get(m_id).unwrap().borrow();
            let group_states = m.groups.borrow_mut();
            // Some group members may not have received their welcome messages yet.
            if let Some(group_state) = group_states.get(&group.group_id) {
                assert_eq!(group_state.export_ratchet_tree(), group.public_tree);
            };
            drop(group_states);
        }
        Ok(())
    }

    /// Get `number_of_members` new members for the given group `group` for use
    /// with the `add_members` function.
    pub fn random_new_members_for_group(
        &self,
        group: &Group,
        number_of_members: usize,
    ) -> Result<Vec<Vec<u8>>, SetupError> {
        let clients = self.clients.borrow();
        if number_of_members + group.members.len() >= clients.len() {
            return Err(SetupError::NotEnoughClients);
        }
        let mut new_member_ids = Vec::new();
        for _ in 0..number_of_members {
            let new_member_id = clients
                .keys()
                .find(|&client_id| {
                    (group
                        .members
                        .iter()
                        .find(|&(_, member_id)| client_id == member_id)
                        .is_none())
                        && (new_member_ids
                            .iter()
                            .find(|&member_id| member_id == client_id)
                            .is_none())
                })
                .unwrap();
            new_member_ids.push(new_member_id.clone());
        }
        drop(clients);
        Ok(new_member_ids)
    }

    /// Have a random client create a new group with ciphersuite `ciphersuite`
    /// and return the `GroupId`.
    pub fn create_group(&self, ciphersuite: &Ciphersuite) -> GroupId {
        // Pick a random group creator.
        let clients = self.clients.borrow();
        let group_creator_id = ((OsRng.next_u32() as usize) % clients.len())
            .to_be_bytes()
            .to_vec();
        let group_creator = clients.get(&group_creator_id).unwrap().borrow();
        let mut groups = self.groups.borrow_mut();
        let group_id = GroupId {
            value: groups.len().to_string().into_bytes(),
        };

        let public_tree =
            group_creator.create_group(group_id.clone(), self.default_mgc.clone(), ciphersuite);
        let mut member_ids = Vec::new();
        member_ids.push((0, group_creator_id));
        let group = Group {
            group_id: group_id.clone(),
            members: member_ids,
            ciphersuite: ciphersuite.clone(),
            group_config: self.default_mgc.clone(),
            public_tree,
        };
        groups.insert(group_id.clone(), group);
        group_id
    }

    /// Create a random group of size `group_size` and return the `GroupId`
    pub fn create_random_group(
        &self,
        target_group_size: usize,
        ciphersuite: &Ciphersuite,
    ) -> Result<GroupId, SetupError> {
        let group_id = self.create_group(ciphersuite);

        let mut groups = self.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let new_members = self.random_new_members_for_group(group, target_group_size - 1)?;

        let mut key_packages = Vec::new();
        let clients = self.clients.borrow();
        for member_id in &new_members {
            let member = clients.get(member_id).unwrap().borrow();
            key_packages.push(self.get_fresh_key_package(&member, ciphersuite));
        }

        while !key_packages.is_empty() {
            // Pick a random adder.
            let adder_id = group.random_group_member();
            let adder = clients.get(&adder_id).unwrap().borrow();
            let mut adder_group_states = adder.groups.borrow_mut();
            let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();
            // Add between 1 and 5 new members.
            let number_of_adds = ((OsRng.next_u32() as usize) % 5 % key_packages.len()) + 1;
            let key_packages_to_add = key_packages.drain(0..number_of_adds);
            let (mls_messages, welcome) = adder_group_state
                .add_members(key_packages_to_add.as_slice())
                .unwrap();
            drop(adder_group_state);
            drop(adder_group_states);
            drop(adder);
            self.distribute_to_members(&adder_id, group, mls_messages)?;
            self.deliver_welcome(welcome, group)?;
        }
        Ok(group_id)
    }

    pub fn self_update(
        &self,
        action_type: ActionType,
        group: &mut Group,
        client_id: &Vec<u8>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let client = match clients.get(client_id) {
            Some(client) => client,
            None => return Err(SetupError::UnknownClientId),
        }
        .borrow();
        let mut member_groups = client.groups.borrow_mut();
        let member_group_state = match member_groups.get_mut(&group.group_id) {
            Some(group_state) => group_state,
            None => return Err(SetupError::ClientNotInGroup),
        };
        let (messages, welcome_option) = match action_type {
            ActionType::Commit => {
                // Let the function generate the key package bundle.
                member_group_state.self_update(None)?
            }
            ActionType::Proposal => (member_group_state.propose_self_update(None)?, None),
        };
        drop(member_group_state);
        drop(member_groups);
        self.distribute_to_members(&client.identity, group, messages)?;
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// Has the `adder` add the `addee` to the Group `group`. If the `adder` is
    /// not part of the group, or the `addee` is already part of the group, it
    /// returns an error.
    pub fn add_clients(
        &self,
        action_type: ActionType,
        group: &mut Group,
        adder_id: &Vec<u8>,
        addees: Vec<Vec<u8>>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let adder = match clients.get(adder_id) {
            Some(client) => client,
            None => return Err(SetupError::UnknownClientId),
        }
        .borrow();
        if group
            .members
            .iter()
            .find(|(_, id)| addees.iter().find(|&client_id| &client_id == &id).is_some())
            .is_some()
        {
            return Err(SetupError::ClientAlreadyInGroup);
        }
        let mut adder_groups = adder.groups.borrow_mut();
        let adder_group_state = match adder_groups.get_mut(&group.group_id) {
            Some(group_state) => group_state,
            None => return Err(SetupError::ClientNotInGroup),
        };
        let mut key_packages = Vec::new();
        for addee_id in &addees {
            let addee = match clients.get(addee_id) {
                Some(client) => client,
                None => return Err(SetupError::UnknownClientId),
            }
            .borrow();
            let key_package = self.get_fresh_key_package(&addee, &group.ciphersuite);
            key_packages.push(key_package);
        }
        let (messages, welcome_option) = match action_type {
            ActionType::Commit => {
                let (messages, welcome) = adder_group_state.add_members(&key_packages)?;
                (messages, Some(welcome))
            }
            ActionType::Proposal => (adder_group_state.propose_add_members(&key_packages)?, None),
        };
        drop(adder_group_state);
        drop(adder_groups);
        drop(adder);
        drop(clients);
        self.distribute_to_members(&adder_id, group, messages)?;
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    /// Has the `remover` remove the `target_members` from the Group `group`. If
    /// the `remover` or one of the `target_members` is not part of the group,
    /// it returns an error.
    pub fn remove_clients(
        &self,
        action_type: ActionType,
        group: &mut Group,
        remover_id: &Vec<u8>,
        target_members: Vec<Vec<u8>>,
    ) -> Result<(), SetupError> {
        let clients = self.clients.borrow();
        let remover = match clients.get(remover_id) {
            Some(client) => client,
            None => return Err(SetupError::UnknownClientId),
        }
        .borrow();
        if group
            .members
            .iter()
            .find(|(_, id)| {
                target_members
                    .iter()
                    .find(|&client_id| client_id == id)
                    .is_some()
            })
            .is_none()
        {
            return Err(SetupError::ClientNotInGroup);
        }
        let members = remover.get_members_of_group(&group.group_id)?;
        let mut target_indices = Vec::new();
        for target in &target_members {
            let (index, _) = members
                .iter()
                .find(|(_, credential)| credential.identity() == target)
                .unwrap();
            target_indices.push(*index);
        }
        let mut remover_groups = remover.groups.borrow_mut();
        let remover_group_state = match remover_groups.get_mut(&group.group_id) {
            Some(group_state) => group_state,
            None => return Err(SetupError::ClientNotInGroup),
        };
        let (messages, welcome_option) = match action_type {
            ActionType::Commit => remover_group_state.remove_members(target_indices.as_slice())?,
            ActionType::Proposal => {
                let messages =
                    remover_group_state.propose_remove_members(target_indices.as_slice())?;
                (messages, None)
            }
        };
        drop(remover_group_state);
        drop(remover_groups);
        drop(remover);
        drop(clients);
        self.distribute_to_members(&remover_id, group, messages)?;
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group)?;
        }
        Ok(())
    }

    pub fn perform_random_operation(&self, group: &mut Group) -> Result<(), SetupError> {
        // Who's going to do it?
        let member_id = group.random_group_member();
        println!("Member performing the operation: {:?}", member_id);

        // Should we propose or commit?
        // 0: Propose,
        // 1: Commit,
        // TODO: 2: Both.
        let action_type = match (OsRng.next_u32() as usize) % 2 {
            0 => ActionType::Proposal,
            1 => ActionType::Commit,
            _ => return Err(SetupError::Unknown),
        };

        // Let's do something.
        // 0: Update,
        // 1: Remove,
        // 2: Add,
        // TODO: 3: All of the above,
        let operation_type = match (OsRng.next_u32() as usize) % 3 {
            0 => OperationType::Update,
            1 => OperationType::Add,
            2 => OperationType::Remove,
            _ => return Err(SetupError::Unknown),
        };
        match operation_type {
            OperationType::Update => {
                self.self_update(action_type, group, &member_id)?;
            }
            OperationType::Remove => {
                // If it's a single-member group, don't remove anyone.
                if group.members.len() > 1 {
                    // How many members?
                    let number_of_removals =
                        (((OsRng.next_u32() as usize) % group.members.len()) % 5) + 1;

                    let (own_index, _) = group
                        .members
                        .iter()
                        .find(|(_, identity)| identity == &member_id)
                        .unwrap()
                        .clone();
                    println!(
                        "Index of the member performing the operation: {:?}",
                        own_index
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
                        println!("Index: {:?}, Identity: {:?}", leaf_index, identity,);
                        target_member_ids.push(identity);
                    }
                    self.remove_clients(action_type, group, &member_id, target_member_ids)?
                };
            }
            OperationType::Add => {
                // First, figure out if there are clients left to add.
                let clients_left = self.number_of_clients - group.members.len();
                if clients_left > 0 {
                    let number_of_adds = (((OsRng.next_u32() as usize) % clients_left) % 5) + 1;
                    let new_member_ids = self
                        .random_new_members_for_group(group, number_of_adds)
                        .unwrap();
                    // Have the adder add them to the group.
                    self.add_clients(action_type, group, &member_id, new_member_ids)?;
                }
            }
        };
        Ok(())
    }
}
