use openmls::prelude::{node::Node, *};
use rand::{rngs::OsRng, RngCore};
use std::{cell::RefCell, collections::HashMap};

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
        &'a self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let ciphersuite = welcome.ciphersuite();
        let credential_bundle: &'a CredentialBundle = self
            .credential_bundles
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
struct Group<'a> {
    group_id: GroupId,
    members: Vec<&'a Client<'a>>,
    ciphersuite: Ciphersuite,
    group_config: ManagedGroupConfig,
    public_tree: Vec<Option<Node>>,
}

impl<'a> Group<'a> {
    pub fn distribute_to_members(&mut self, messages: Vec<MLSMessage>) -> Result<(), ClientError> {
        // Distribute message to all members.
        for member in &self.members {
            member.receive_messages_for_group(&self.group_id, messages.clone())?;
        }
        // Get the current tree from one of the up-to-date members.
        let groups = self.members[0].groups.borrow();
        let public_tree = groups.get(&self.group_id).unwrap().export_ratchet_tree();
        self.public_tree = public_tree;
        drop(groups);
        for m in &self.members {
            let group_states = m.groups.borrow_mut();
            let group_state = group_states.get(&self.group_id).unwrap();
            assert_eq!(group_state.export_ratchet_tree(), self.public_tree);
            drop(group_states);
        }
        Ok(())
    }

    pub fn join_group(
        &mut self,
        client: &'a Client<'a>,
        welcome: Welcome,
    ) -> Result<(), ClientError> {
        client.join_group(
            self.group_config.clone(),
            welcome,
            Some(self.public_tree.clone()),
        )?;
        self.members.push(client);
        Ok(())
    }
}

#[derive(Debug)]
pub enum SetupError {
    UnknownGroupId,
}

struct ManagedTestSetup<'a> {
    // The clients identity is its position in the vector in be_bytes.
    clients: Vec<Client<'a>>,
    groups: RefCell<HashMap<GroupId, Group<'a>>>,
}

impl<'a> ManagedTestSetup<'a> {
    pub fn new(number_of_clients: usize) -> Self {
        let mut clients = Vec::new();
        for i in 0..number_of_clients {
            let identity = i.to_string().into_bytes();
            // For now, everyone supports all ciphersuites.
            let _ciphersuites = Config::supported_ciphersuite_names();
            let mut credential_bundles = HashMap::new();
            for ciphersuite in &_ciphersuites {
                let credential_bundle =
                    CredentialBundle::new(identity.clone(), CredentialType::Basic, *ciphersuite)
                        .unwrap();
                credential_bundles.insert(*ciphersuite, credential_bundle);
            }
            let key_package_bundles = RefCell::new(HashMap::new());
            let client = Client {
                identity,
                _ciphersuites,
                credential_bundles,
                key_package_bundles,
                groups: RefCell::new(HashMap::new()),
            };
            clients.push(client)
        }
        let groups = RefCell::new(HashMap::new());
        ManagedTestSetup { clients, groups }
    }

    pub fn random_new_members_for_group(
        &'a self,
        group_id: &GroupId,
        number_of_members: usize,
    ) -> Result<(Vec<&'a Client<'a>>, Vec<KeyPackage>), SetupError> {
        let groups = self.groups.borrow();
        let group = match groups.get(group_id) {
            Some(group) => group,
            None => return Err(SetupError::UnknownGroupId),
        };
        let mut new_members: Vec<&'a Client<'a>> = Vec::new();
        let mut key_packages = Vec::new();
        for _ in 0..number_of_members {
            let new_member = self
                .clients
                .iter()
                .find(|client| {
                    (group
                        .members
                        .iter()
                        .find(|member| member.identity == client.identity)
                        .is_none())
                        && (new_members
                            .iter()
                            .find(|member| member.identity == client.identity)
                            .is_none())
                })
                .unwrap();
            key_packages.push(new_member.get_fresh_key_package(&group.ciphersuite));
            new_members.push(new_member);
        }
        Ok((new_members, key_packages))
    }

    /// Create a random group of size `group_size` and return the `GroupId`
    pub fn create_random_group(
        &'a self,
        target_group_size: usize,
        ciphersuite: &Ciphersuite,
        managed_group_config: ManagedGroupConfig,
    ) -> GroupId {
        let mut groups = self.groups.borrow_mut();
        if target_group_size > self.clients.len() {
            panic!("Not enough members to create a group this large.");
        }

        // Pick a random group creator.
        let group_creator_id = (OsRng.next_u32() as usize) % self.clients.len();
        let group_creator = &self.clients[group_creator_id];
        let group_id = GroupId {
            value: groups.len().to_string().into_bytes(),
        };
        let public_tree =
            group_creator.create_group(group_id.clone(), managed_group_config.clone(), ciphersuite);
        let member_references = vec![group_creator];
        let group = Group {
            group_id: group_id.clone(),
            members: member_references,
            ciphersuite: ciphersuite.clone(),
            group_config: managed_group_config,
            public_tree,
        };
        groups.insert(group_id.clone(), group);
        let group = groups.get_mut(&group_id).unwrap();
        let mut current_group_size = group.members.len();
        drop(group);
        drop(groups);
        while current_group_size < target_group_size {
            let mut groups = self.groups.borrow_mut();
            let group = groups.get_mut(&group_id).unwrap();
            // Get a random group member.
            let adder_id = (OsRng.next_u32() as usize) % group.members.len();
            let adder = group.members[adder_id];
            let number_of_members =
                (OsRng.next_u32() as usize) % (target_group_size - current_group_size) + 1;
            drop(group);
            drop(groups);
            self.increase_group_size(adder, group_id.clone(), number_of_members);
            current_group_size += number_of_members;
        }
        group_id
    }

    /// Have the given member of the given group add `number_of_members` to the group.
    fn increase_group_size(
        &'a self,
        adder: &'a Client,
        group_id: GroupId,
        number_of_members: usize,
    ) {
        let (new_members, new_member_key_packages) = self
            .random_new_members_for_group(&group_id, number_of_members)
            .expect("Error when getting new members for group size increase.");

        let mut groups = self.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();
        let mut adder_group_states = adder.groups.borrow_mut();
        let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();

        let (mls_messages, welcome) = adder_group_state
            .add_members(new_member_key_packages.as_slice())
            .unwrap();
        drop(adder_group_state);
        drop(adder_group_states);
        group
            .distribute_to_members(mls_messages)
            .expect("Error distributing messages to group members while creating a new group.");
        for new_member in &new_members {
            group
                .join_group(new_member, welcome.clone())
                .expect("Error while processing Welcome messages by new group members.");
        }
    }

    pub fn perform_random_operation(&'a self, group_id: GroupId) -> Result<(), ClientError> {
        let mut setup_groups = self.groups.borrow_mut();
        let setup_group = match setup_groups.get_mut(&group_id) {
            Some(group) => group,
            None => return Err(ClientError::NoMatchingGroup),
        };

        // Who's going to do it?
        let member_id = (OsRng.next_u32() as usize) % setup_group.members.len();
        let member = setup_group.members[member_id];

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
        let messages = match proposal_type {
            0 => {
                let messages = if action_type == 0 {
                    group.propose_self_update(None).unwrap()
                } else {
                    group.self_update(None).unwrap()
                };
                drop(group);
                drop(groups);
                messages
            }
            1 => {
                if group.members().len() == 1 {
                    Vec::new()
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
                    let mut target_clients = Vec::new();
                    for member_index in &target_members {
                        let member_cred: &Credential = &group.members()[member_index.to_owned()];
                        let member_identity = member_cred.identity();
                        println!("Member identity: {:?}", member_identity);
                        let client: &'a Client = setup_group
                            .members
                            .iter()
                            .find(|client| &client.identity == member_identity)
                            .unwrap();
                        target_clients.push(client);
                    }
                    let messages = if action_type == 0 {
                        group.propose_remove_members(&target_members).unwrap()
                    } else {
                        group.remove_members(&target_members).unwrap()
                    };
                    drop(group);
                    drop(groups);
                    for client in target_clients {
                        let pos = setup_group
                            .members
                            .iter()
                            .position(|&mem| mem.identity == client.identity)
                            .unwrap();
                        setup_group.members.remove(pos);
                    }
                    messages
                }
            }
            2 => {
                let number_of_adds = ((OsRng.next_u32() as usize) % 5) + 1;
                let mut new_members: Vec<&Client<'a>> = Vec::new();
                let mut new_member_key_packages = Vec::new();
                for _ in 0..number_of_adds {
                    let new_member = self
                        .clients
                        .iter()
                        .find(|client| {
                            (setup_group
                                .members
                                .iter()
                                .find(|member| member.identity == client.identity)
                                .is_none())
                                && (new_members
                                    .iter()
                                    .find(|member| member.identity == client.identity)
                                    .is_none())
                        })
                        .unwrap();
                    // Get a fresh key package from each of them.
                    let key_package = new_member.get_fresh_key_package(&setup_group.ciphersuite);
                    new_members.push(new_member);
                    new_member_key_packages.push(key_package);
                }
                // Have the adder add them to the group.
                if action_type == 0 {
                    let messages = group.propose_add_members(&new_member_key_packages).unwrap();
                    drop(group);
                    drop(groups);
                    messages
                } else {
                    let (messages, welcome) = group.add_members(&new_member_key_packages).unwrap();
                    drop(group);
                    drop(groups);
                    //println!("Setup group members: {:?}", setup_group.members);
                    debug_assert!(setup_group
                        .members
                        .iter()
                        .find(|mem| mem.identity == member.identity)
                        .is_some());
                    setup_group
                        .distribute_to_members(messages.clone())
                        .expect("Error while distributing messages after random add operation.");
                    for new_member in &new_members {
                        setup_group
                            .join_group(new_member, welcome.clone())
                            .expect("Error while joining after random add operation.")
                    }
                    Vec::new()
                }
            }
            _ => return Err(ClientError::Unknown),
        };
        if !messages.is_empty() {
            setup_group
                .distribute_to_members(messages)
                .expect("Error while distributing messages after random group operation.");
        };
        Ok(())

        //group
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

    let setup = ManagedTestSetup::new(20);
    for ciphersuite in Config::supported_ciphersuites() {
        let handshake_message_format = HandshakeMessageFormat::Plaintext;
        let update_policy = UpdatePolicy::default();
        let callbacks = ManagedGroupCallbacks::new()
            .with_member_added(member_added)
            .with_invalid_message_received(invalid_message_received)
            .with_error_occured(error_occured);
        let managed_group_config =
            ManagedGroupConfig::new(handshake_message_format, update_policy, callbacks);
        let group_id = setup.create_random_group(10, ciphersuite, managed_group_config);
        println!("Done creating group. Performing ten random operations.");
        for i in 0..10 {
            println!("Operation {:?}", i);
            setup.perform_random_operation(group_id.clone()).unwrap();
        }
    }
}
