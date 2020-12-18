use openmls::prelude::{node::Node, *};
use rand::{rngs::OsRng, RngCore};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

/// Errors that can occur when processing messages with the client.
#[derive(Debug)]
pub enum ClientError {
    NoMatchingKeyPackage,
    NoMatchingCredential,
    NoMatchingGroup,
    FailedToJoinGroup(WelcomeError),
    InvalidMessage(GroupError),
    ManagedGroupError(ManagedGroupError),
    GroupError(GroupError),
    Unknown,
}

impl From<WelcomeError> for ClientError {
    fn from(e: WelcomeError) -> Self {
        ClientError::FailedToJoinGroup(e)
    }
}

impl From<ManagedGroupError> for ClientError {
    fn from(e: ManagedGroupError) -> Self {
        ClientError::ManagedGroupError(e)
    }
}

impl From<GroupError> for ClientError {
    fn from(e: GroupError) -> Self {
        ClientError::GroupError(e)
    }
}

#[derive(Debug)]
struct Client<'a> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) _ciphersuites: Vec<CiphersuiteName>,
    credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
    credential_bundle_refs: Vec<&'a CredentialBundle>,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
    //pub(crate) key_packages: HashMap<CiphersuiteName, KeyPackage>,
    pub(crate) groups: RefCell<HashMap<GroupId, ManagedGroup<'a>>>,
}

impl<'a> Client<'a> {
    pub fn get_fresh_key_package(&self, ciphersuite: &Ciphersuite) -> KeyPackage {
        // We unwrap here for now, because all ciphersuites are supported by all
        // clients.
        let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
        let mandatory_extensions = Vec::new();
        let key_package_bundle: KeyPackageBundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let key_package = key_package_bundle.key_package().clone();
        self.key_package_bundles
            .borrow_mut()
            .insert(key_package_bundle.key_package().hash(), key_package_bundle);
        key_package
    }

    pub fn create_group(
        &'a self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) -> Vec<Option<Node>> {
        let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
        let mandatory_extensions = Vec::new();
        let key_package_bundle: KeyPackageBundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let group_state = ManagedGroup::new(
            credential_bundle,
            &managed_group_config,
            group_id.clone(),
            key_package_bundle,
        )
        .unwrap();
        let tree = group_state.export_ratchet_tree();
        self.groups.borrow_mut().insert(group_id, group_state);
        tree
    }

    pub fn join_group(
        self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let ciphersuite = welcome.ciphersuite();
        let credential_bundles = &self.credential_bundles;
        let credential_bundle = credential_bundles
            .get(&ciphersuite.name())
            .ok_or(ClientError::NoMatchingCredential)?;
        let key_package_bundle = match welcome.secrets().iter().find(|egs| {
            self.key_package_bundles
                .borrow()
                .contains_key(&egs.key_package_hash)
        }) {
            // We can unwrap here, because we just checked that this kpb exists.
            // Also, we should be fine just removing the KeyPackageBundle here,
            // because it shouldn't be used again anyway.
            Some(egs) => Ok(self
                .key_package_bundles
                .borrow_mut()
                .remove(&egs.key_package_hash)
                .unwrap()),
            None => Err(ClientError::NoMatchingKeyPackage),
        }?;
        let new_group: ManagedGroup<'a> = ManagedGroup::new_from_welcome(
            credential_bundle,
            &managed_group_config,
            welcome,
            ratchet_tree,
            key_package_bundle,
        )?;
        self.groups
            .borrow_mut()
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    pub fn receive_messages_for_group(
        &self,
        group_id: &GroupId,
        messages: Vec<MLSMessage>,
    ) -> Result<(), ClientError> {
        let mut group_states = self.groups.borrow_mut();
        let group_state = match group_states.get_mut(group_id) {
            Some(group_state) => group_state,
            None => return Err(ClientError::NoMatchingGroup),
        };
        Ok(group_state.process_messages(messages)?)
    }
}

#[derive(Clone)]
struct Group {
    group_id: GroupId,
    members: HashSet<Vec<u8>>,
    ciphersuite: Ciphersuite,
    group_config: ManagedGroupConfig,
    public_tree: Vec<Option<Node>>,
}

#[derive(Debug)]
pub enum SetupError {
    UnknownGroupId,
}

struct ManagedTestSetup<'a> {
    // The clients identity is its position in the vector in be_bytes.
    clients: HashMap<Vec<u8>, Client<'a>>,
    groups: HashMap<GroupId, Group>,
    // This maps key package hashes to client ids.
    waiting_for_welcome: HashMap<Vec<u8>, Vec<u8>>,
    default_mgc: ManagedGroupConfig,
}

impl<'a> ManagedTestSetup<'a> {
    pub fn new(number_of_clients: usize, default_mgc: ManagedGroupConfig) -> Self {
        let mut clients = HashMap::new();
        for i in 0..number_of_clients {
            let identity = i.to_string().into_bytes();
            // For now, everyone supports all ciphersuites.
            let _ciphersuites = Config::supported_ciphersuite_names();
            let mut credential_bundles = HashMap::new();
            let mut credential_bundle_refs = Vec::new();
            for ciphersuite in &_ciphersuites {
                let credential_bundle =
                    CredentialBundle::new(identity.clone(), CredentialType::Basic, *ciphersuite)
                        .unwrap();
                credential_bundles = add_to_map(
                    credential_bundle,
                    *ciphersuite,
                    credential_bundles,
                    &mut credential_bundle_refs,
                );
                //credential_bundles.insert(*ciphersuite, credential_bundle);
                //let credential_bundle_ref = credential_bundles.get(ciphersuite).unwrap();
                //credential_bundle_refs.push(credential_bundle_ref);
            }
            let key_package_bundles = RefCell::new(HashMap::new());
            let client = Client {
                identity: identity.clone(),
                _ciphersuites,
                credential_bundles,
                key_package_bundles,
                groups: RefCell::new(HashMap::new()),
                credential_bundle_refs,
            };
            clients.insert(identity, client);
        }
        let groups = HashMap::new();
        let waiting_for_welcome = HashMap::new();
        ManagedTestSetup {
            clients,
            groups,
            waiting_for_welcome,
            default_mgc,
        }
    }

    pub fn get_fresh_key_package(
        &mut self,
        client_id: &Vec<u8>,
        ciphersuite: &Ciphersuite,
    ) -> KeyPackage {
        let client = self.clients.get(client_id).unwrap();
        let key_package = client.get_fresh_key_package(ciphersuite);
        self.waiting_for_welcome
            .insert(key_package.hash(), client_id.clone());
        key_package
    }

    pub fn deliver_welcome(&mut self, welcome: Welcome, group_id: GroupId) {
        for egs in welcome.secrets() {
            let client_id = self
                .waiting_for_welcome
                .remove(&egs.key_package_hash)
                .unwrap();
            let client = self.clients.get(&client_id).unwrap();
            let group = self.groups.get_mut(&group_id).unwrap();
            client
                .join_group(
                    group.group_config.clone(),
                    welcome.clone(),
                    Some(group.public_tree.clone()),
                )
                .unwrap();
        }
    }

    pub fn distribute_to_members(
        &mut self,
        group_id: &GroupId,
        messages: Vec<MLSMessage>,
    ) -> Result<(), ClientError> {
        let mut group = self.groups.get_mut(group_id).unwrap();
        // Distribute message to all members.
        for member_id in &group.members {
            let member = self.clients.get(member_id).unwrap();
            member.receive_messages_for_group(&group.group_id, messages.clone())?;
        }
        // Get the current tree from one of the up-to-date members.
        let random_member_id = group.members.iter().find(|_| true).unwrap();
        let random_member = self.clients.get(random_member_id).unwrap();
        let random_member_groups = random_member.groups.borrow();
        let random_member_group = random_member_groups.get(group_id).unwrap();
        group.public_tree = random_member_group.export_ratchet_tree();
        drop(random_member_group);
        drop(random_member_groups);
        for m_id in &group.members {
            let m = self.clients.get(m_id).unwrap();
            let group_states = m.groups.borrow_mut();
            let group_state = group_states.get(&group.group_id).unwrap();
            assert_eq!(group_state.export_ratchet_tree(), group.public_tree);
            drop(group_states);
        }
        let mut current_members = HashSet::new();
        for index in 0..group.public_tree.len() {
            // Is it a leaf?
            if index % 2 == 0 && group.public_tree[index].is_some() {
                match group.public_tree[index] {
                    Some(ref leaf) => {
                        let identity = leaf.key_package().unwrap().credential().identity();
                        current_members.insert(identity.clone());
                    }
                    None => {}
                };
            }
        }
        group.members = current_members;
        Ok(())
    }

    pub fn random_new_members_for_group(
        &self,
        group_id: &GroupId,
        number_of_members: usize,
    ) -> Result<Vec<Vec<u8>>, SetupError> {
        let group = match self.groups.get(group_id) {
            Some(group) => group,
            None => return Err(SetupError::UnknownGroupId),
        };
        let mut new_member_ids = Vec::new();
        for _ in 0..number_of_members {
            let new_member_id = self
                .clients
                .keys()
                .find(|&client_id| {
                    (group
                        .members
                        .iter()
                        .find(|&member_id| client_id == member_id)
                        .is_none())
                        && (new_member_ids
                            .iter()
                            .find(|&member_id| member_id == client_id)
                            .is_none())
                })
                .unwrap();
            new_member_ids.push(new_member_id.clone());
        }
        drop(group);
        Ok(new_member_ids)
    }

    /// Create a random group of size `group_size` and return the `GroupId`
    pub fn create_random_group(
        &'a mut self,
        target_group_size: usize,
        ciphersuite: &Ciphersuite,
    ) -> GroupId {
        if target_group_size > self.clients.len() {
            panic!("Not enough members to create a group this large.");
        }

        // Pick a random group creator.
        let group_creator_id = ((OsRng.next_u32() as usize) % self.clients.len())
            .to_be_bytes()
            .to_vec();
        let clients = &self.clients;
        let group_creator = clients.get(&group_creator_id).unwrap();
        let group_id = GroupId {
            value: self.groups.len().to_string().into_bytes(),
        };

        let public_tree =
            group_creator.create_group(group_id.clone(), self.default_mgc.clone(), ciphersuite);
        let mut member_references = HashSet::new();
        member_references.insert(group_creator_id);
        let group = Group {
            group_id: group_id.clone(),
            members: member_references,
            ciphersuite: ciphersuite.clone(),
            group_config: self.default_mgc.clone(),
            public_tree,
        };
        self.groups.insert(group_id.clone(), group);
        let mut current_group_size = 1;
        while current_group_size < target_group_size {
            // Get a random group member.
            //let adder = group.members.get(&adder_id).unwrap();
            let number_of_members =
                (OsRng.next_u32() as usize) % (target_group_size - current_group_size) + 1;
            self.increase_group_size(group_id.clone(), number_of_members);
            current_group_size += number_of_members;
        }
        group_id
    }

    /// Have the given member of the given group add `number_of_members` to the group.
    fn increase_group_size(&mut self, group_id: GroupId, number_of_members: usize) {
        let group = self.groups.get(&group_id).unwrap();
        let ciphersuite = group.ciphersuite.clone();
        drop(group);
        let new_members = self
            .random_new_members_for_group(&group_id, number_of_members)
            .expect("Error when getting new members for group size increase.");

        let mut key_packages = Vec::new();
        for member_id in &new_members {
            let fresh_key_package = self.get_fresh_key_package(member_id, &ciphersuite);
            key_packages.push(fresh_key_package);
        }
        let group = self.groups.get_mut(&group_id).unwrap();
        // Pick a random adder.
        let adder_id = group.members.iter().find(|_| true).unwrap();
        let adder = self.clients.get(adder_id).unwrap();
        let mut adder_group_states = adder.groups.borrow_mut();
        let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();

        let (mls_messages, welcome) = adder_group_state
            .add_members(key_packages.as_slice())
            .unwrap();
        drop(adder_group_state);
        drop(adder_group_states);
        self.distribute_to_members(&group_id, mls_messages)
            .expect("Error distributing messages to group members while creating a new group.");
        self.deliver_welcome(welcome, group_id);
    }

    pub fn perform_random_operation(&'a mut self, group_id: GroupId) -> Result<(), ClientError> {
        let group = match self.groups.get_mut(&group_id) {
            Some(group) => group,
            None => return Err(ClientError::NoMatchingGroup),
        };

        // Who's going to do it?
        let member_id = group.members.iter().find(|_| true).unwrap();
        let member = self.clients.get(member_id).unwrap();

        let mut groups = member.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        // Should we propose or commit?
        // 0: Propose,
        // 1: Commit,
        // TODO: 2: Both.
        // TODO: For now hardcode it to 0
        let action_type = (OsRng.next_u32() as usize) % 3;
        //let action_type = 1;

        // Let's propose something.
        // 0: Update,
        // 1: Remove,
        // 2: Add,
        // TODO: 3: All of the above,
        // TODO: For now hardcode it to 0
        let proposal_type = (OsRng.next_u32() as usize) % 3;
        //let proposal_type = 2;
        let (messages, welcome_option) = match proposal_type {
            0 => {
                let messages = if action_type == 0 {
                    (group.propose_self_update(None).unwrap(), None)
                } else {
                    group.self_update(None).unwrap()
                };
                drop(group);
                drop(groups);
                messages
            }
            1 => {
                if group.members().len() == 1 {
                    (Vec::new(), None)
                } else {
                    // How many members?
                    // TODO: Hard-code this to 1 for now.
                    let number_of_removals = 1;
                    //(((OsRng.next_u32() as usize) % group.members().len()) % 5) + 1;
                    let mut target_members = Vec::new();

                    let own_index = group
                        .members()
                        .iter()
                        .position(|cred| cred.identity() == &member.identity)
                        .unwrap();

                    // Get the client references, as opposed to just the member indices.
                    for _ in 0..number_of_removals {
                        let mut index = (OsRng.next_u32() as usize) % group.members().len();
                        while index == own_index || target_members.contains(&index) {
                            index = (OsRng.next_u32() as usize) % group.members().len();
                        }
                        target_members.push(index);
                    }
                    let (messages, welcome_option) = if action_type == 0 {
                        (group.propose_remove_members(&target_members).unwrap(), None)
                    } else {
                        group.remove_members(&target_members).unwrap()
                    };
                    drop(group);
                    drop(groups);
                    (messages, welcome_option)
                }
            }
            2 => {
                let number_of_adds = ((OsRng.next_u32() as usize) % 5) + 1;
                let new_members = self
                    .random_new_members_for_group(&group_id, number_of_adds)
                    .unwrap();
                let mut key_packages = Vec::new();
                for member in &new_members {
                    let fresh_key_package = self.get_fresh_key_package(member, group.ciphersuite());
                    key_packages.push(fresh_key_package);
                }
                // Have the adder add them to the group.
                if action_type == 0 {
                    let messages = group.propose_add_members(&key_packages).unwrap();
                    drop(group);
                    drop(groups);
                    (messages, None)
                } else {
                    let (messages, welcome) = group.add_members(&key_packages).unwrap();
                    drop(group);
                    drop(groups);
                    //println!("Setup group members: {:?}", setup_group.members);
                    (messages, Some(welcome))
                }
            }
            _ => return Err(ClientError::Unknown),
        };
        self.distribute_to_members(&group_id, messages);
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group_id);
        }

        Ok(())
    }
}

#[test]
fn test_randomized_setup() {
    use std::str;
    // Callbacks
    fn member_added(
        managed_group: &ManagedGroup,
        _aad: &[u8],
        sender: &Credential,
        added_member: &Credential,
    ) {
        println!(
            "AddProposal received in group '{}' by '{}': '{}' added '{}'",
            str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
            str::from_utf8(&managed_group.credential().identity()).unwrap(),
            str::from_utf8(sender.identity()).unwrap(),
            str::from_utf8(added_member.identity()).unwrap(),
        );
    }
    fn invalid_message_received(managed_group: &ManagedGroup, error: InvalidMessageError) {
        match error {
            InvalidMessageError::InvalidCiphertext(aad) => {
                println!(
                    "Invalid ciphertext message received in group '{}' by '{}' with AAD {:?}",
                    str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
                    str::from_utf8(&managed_group.credential().identity()).unwrap(),
                    aad
                );
            }
            InvalidMessageError::CommitError(e) => {
                println!("An error occured when applying a Commit message: {:?}", e);
            }
            InvalidMessageError::CommitWithInvalidProposals(e) => {
                println!(
                    "A Commit message with one ore more invalid proposals was received: {:?}",
                    e
                );
            }
            InvalidMessageError::GroupError(e) => {
                println!("An error in the managed group occurred: {:?}", e);
            }
        }
    }
    fn error_occured(managed_group: &ManagedGroup, error: ManagedGroupError) {
        println!(
            "Error occured in group {}: {:?}",
            str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
            error
        );
    }

    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::new()
        .with_member_added(member_added)
        .with_invalid_message_received(invalid_message_received)
        .with_error_occured(error_occured);
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, callbacks);
    let setup = ManagedTestSetup::new(20, managed_group_config);

    for ciphersuite in Config::supported_ciphersuites() {
        let group_id = setup.create_random_group(10, ciphersuite);
        println!("Done creating group. Performing ten random operations.");
        for i in 0..10 {
            println!("Operation {:?}", i);
            setup.perform_random_operation(group_id.clone()).unwrap();
        }
    }
}
