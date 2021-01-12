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
struct KeyStore {
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

#[derive(Debug)]
struct Client<'managed_group_lifetime> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) _ciphersuites: Vec<CiphersuiteName>,
    key_store: &'managed_group_lifetime KeyStore,
    //credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
    //pub(crate) key_packages: HashMap<CiphersuiteName, KeyPackage>,
    pub(crate) groups: RefCell<HashMap<GroupId, ManagedGroup<'managed_group_lifetime>>>,
}

impl<'managed_group_lifetime> Client<'managed_group_lifetime> {
    pub fn get_fresh_key_package(&self, ciphersuite: &Ciphersuite) -> KeyPackage {
        // We unwrap here for now, because all ciphersuites are supported by all
        // clients.
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite.name())
            .unwrap();
        //let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
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
        &self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) -> Vec<Option<Node>> {
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite.name())
            .unwrap();
        //let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
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
        &self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let ciphersuite = welcome.ciphersuite();
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite.name())
            .unwrap();
        //let credential_bundles = &self.credential_bundles;
        //let credential_bundle = credential_bundles
        //    .get(&ciphersuite.name())
        //    .ok_or(ClientError::NoMatchingCredential)?;
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
        let new_group: ManagedGroup<'managed_group_lifetime> = ManagedGroup::new_from_welcome(
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
    members: Vec<(usize, Vec<u8>)>,
    ciphersuite: Ciphersuite,
    group_config: ManagedGroupConfig,
    public_tree: Vec<Option<Node>>,
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

#[derive(Debug)]
pub enum SetupError {
    UnknownGroupId,
    NotEnoughClients,
}

struct ManagedTestSetup<'client_lifetime> {
    // The clients identity is its position in the vector in be_bytes.
    clients: RefCell<HashMap<Vec<u8>, RefCell<Client<'client_lifetime>>>>,
    groups: RefCell<HashMap<GroupId, Group>>,
    key_store: KeyStore,
    // This maps key package hashes to client ids.
    waiting_for_welcome: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    default_mgc: ManagedGroupConfig,
}

impl<'ks> ManagedTestSetup<'ks> {
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
        let mts = ManagedTestSetup {
            clients,
            groups,
            key_store,
            waiting_for_welcome,
            default_mgc,
        };
        mts
    }

    pub fn create_clients(&'ks self, number_of_clients: usize) {
        for i in 0..number_of_clients {
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

    pub fn get_fresh_key_package(
        &self,
        client_id: &Vec<u8>,
        ciphersuite: &Ciphersuite,
    ) -> KeyPackage {
        let clients = self.clients.borrow();
        let client = clients.get(client_id).unwrap().borrow();
        let key_package = client.get_fresh_key_package(ciphersuite);
        println!("Storing key package with hash: {:?}", key_package.hash());
        self.waiting_for_welcome
            .borrow_mut()
            .insert(key_package.hash(), client_id.clone());
        key_package
    }

    pub fn deliver_welcome(&'ks self, welcome: Welcome, group: &Group) {
        let clients = self.clients.borrow();
        for egs in welcome.secrets() {
            println!(
                "Trying to get key package with hash: {:?}",
                egs.key_package_hash
            );
            let client_id = self
                .waiting_for_welcome
                .borrow_mut()
                .remove(&egs.key_package_hash)
                .unwrap();
            let client = clients.get(&client_id).unwrap().borrow();
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
        group.members = sender_group
            .members()
            .iter()
            .map(|(index, cred)| (index.clone(), cred.identity().clone()))
            .collect();
        group.public_tree = sender_group.export_ratchet_tree();
        drop(sender_group);
        drop(sender_groups);
        // Figure out if someone was removed and update the member list.
        println!("Group members after distribution:");
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

    pub fn create_group(&'ks self, ciphersuite: &Ciphersuite) -> GroupId {
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
        &'ks self,
        target_group_size: usize,
        ciphersuite: &Ciphersuite,
    ) -> GroupId {
        let group_id = self.create_group(ciphersuite);

        let mut groups = self.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        let new_members = self
            .random_new_members_for_group(group, target_group_size - 1)
            .expect("Error when getting new members for group size increase.");

        let mut key_packages = Vec::new();
        for member_id in &new_members {
            key_packages.push(self.get_fresh_key_package(member_id, ciphersuite));
        }

        let clients = self.clients.borrow();
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
            self.distribute_to_members(&adder_id, group, mls_messages)
                .expect("Error distributing messages to group members while creating a new group.");
            self.deliver_welcome(welcome, group);
        }
        group_id
    }

    /// Have the given member of the given group add between 1 and 5 members to the group.
    //fn perform_random_add(
    //    &'ks self,
    //    client: &Client,
    //    group: &mut Group,
    //) -> Result<(Vec<MLSMessage>, Welcome), SetupError> {
    //    let number_of_adds = ((OsRng.next_u32() as usize) % 5) + 1;
    //    let new_members = self.random_new_members_for_group(group, number_of_adds)?;

    //    let mut key_packages = Vec::new();
    //    for member_id in &new_members {
    //        let fresh_key_package = self.get_fresh_key_package(member_id, &group.ciphersuite);
    //        key_packages.push(fresh_key_package);
    //    }

    //    let mut adder_group_states = client.groups.borrow_mut();
    //    let adder_group_state = adder_group_states.get_mut(&group.group_id).unwrap();

    //    let messages = adder_group_state
    //        .add_members(key_packages.as_slice())
    //        .unwrap();
    //    drop(adder_group_state);
    //    drop(adder_group_states);
    //    Ok(messages)
    //}

    pub fn perform_random_operation(&'ks self, group: &mut Group) -> Result<(), ClientError> {
        let clients = self.clients.borrow();
        // Who's going to do it?
        let member_id = group.random_group_member();
        println!("Member performing the operation: {:?}", member_id);
        let member = clients.get(&member_id).unwrap().borrow();

        let mut groups = member.groups.borrow_mut();
        let member_group_state = groups.get_mut(&group.group_id).unwrap();

        // Should we propose or commit?
        // 0: Propose,
        // 1: Commit,
        // TODO: 2: Both.
        // TODO: For now hardcode it to 0
        //let action_type = (OsRng.next_u32() as usize) % 3;
        let action_type = 1;

        // Let's do something.
        // 0: Update,
        // 1: Remove,
        // 2: Add,
        // TODO: 3: All of the above,
        // TODO: For now hardcode it to 0
        //let group_operation = (OsRng.next_u32() as usize) % 3;
        let group_operation = 1;
        let (messages, welcome_option) = match group_operation {
            0 => {
                // Issue a self-update.
                let messages = if action_type == 0 {
                    // Proposal
                    (member_group_state.propose_self_update(None).unwrap(), None)
                } else {
                    // Commit
                    member_group_state.self_update(None).unwrap()
                };
                drop(member_group_state);
                drop(groups);
                messages
            }
            1 => {
                // If it's a single-member group, don't remove anyone.
                if member_group_state.members().len() == 1 {
                    (Vec::new(), None)
                } else {
                    // How many members?
                    // TODO: Hard-code this to 1 for now.
                    let number_of_removals = 1;
                    //(((OsRng.next_u32() as usize) % group.members().len()) % 5) + 1;

                    let (own_index, _) = member_group_state
                        .members()
                        .iter()
                        .find(|(_, cred)| cred.identity() == &member.identity)
                        .unwrap()
                        .clone();
                    println!(
                        "Index of the member performing the operation: {:?}",
                        own_index
                    );

                    let mut target_members = Vec::new();
                    // Get the client references, as opposed to just the member indices.
                    println!("Removing members:");
                    for _ in 0..number_of_removals {
                        // Get a random index.
                        let mut member_list_index =
                            (OsRng.next_u32() as usize) % member_group_state.members().len();
                        // Re-sample until the index is not our own index and
                        // not one that is not already being removed.
                        let (mut leaf_index, mut leaf_credential) =
                            member_group_state.members()[member_list_index].clone();
                        while leaf_index == own_index || target_members.contains(&member_list_index)
                        {
                            member_list_index =
                                (OsRng.next_u32() as usize) % member_group_state.members().len();
                            let (new_leaf_index, new_leaf_credential) =
                                member_group_state.members()[member_list_index].clone();
                            leaf_index = new_leaf_index;
                            leaf_credential = new_leaf_credential;
                        }
                        println!(
                            "Index: {:?}, Identity: {:?}",
                            leaf_index,
                            leaf_credential.identity(),
                        );
                        target_members.push(leaf_index);
                    }
                    let (messages, welcome_option) = if action_type == 0 {
                        (
                            member_group_state
                                .propose_remove_members(&target_members)
                                .unwrap(),
                            None,
                        )
                    } else {
                        member_group_state.remove_members(&target_members).unwrap()
                    };
                    drop(member_group_state);
                    drop(groups);
                    (messages, welcome_option)
                }
            }
            2 => {
                // First, figure out if there are clients left to add.
                let clients_left = clients.len() - group.members.len();
                if clients_left == 0 {
                    (Vec::new(), None)
                } else {
                    let number_of_adds = (((OsRng.next_u32() as usize) % clients_left) % 5) + 1;
                    let new_members = self
                        .random_new_members_for_group(group, number_of_adds)
                        .unwrap();
                    let mut key_packages = Vec::new();
                    for member in &new_members {
                        let fresh_key_package =
                            self.get_fresh_key_package(member, member_group_state.ciphersuite());
                        key_packages.push(fresh_key_package);
                    }
                    // Have the adder add them to the group.
                    if action_type == 0 {
                        let messages = member_group_state
                            .propose_add_members(&key_packages)
                            .unwrap();
                        drop(member_group_state);
                        drop(groups);
                        (messages, None)
                    } else {
                        let (messages, welcome) =
                            member_group_state.add_members(&key_packages).unwrap();
                        drop(member_group_state);
                        drop(groups);
                        (messages, Some(welcome))
                    }
                }
            }
            _ => return Err(ClientError::Unknown),
        };
        self.distribute_to_members(&member_id, group, messages)
            .unwrap();
        if let Some(welcome) = welcome_option {
            self.deliver_welcome(welcome, group);
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
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(managed_group_config, number_of_clients);
    // The `create` function can't be in `new`, because within it, lots of
    // references to the key store are made. That means that `setup` is
    // immutably borrowed for the rest of the lifetime of `setup`. That's also
    // the reason why everything is a refcell.
    setup.create_clients(number_of_clients);

    for ciphersuite in Config::supported_ciphersuites() {
        let group_id = setup.create_random_group(10, ciphersuite);
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();
        println!("Done creating group. Performing ten random operations.");
        for i in 0..10 {
            println!("Operation {:?}", i);
            setup.perform_random_operation(group).unwrap();
        }
    }
}

// Lifetime lessons (based on the current setup): The references to the
// credentials are references to the keystore, which in turns means they are
// references to the top-level object, i.e. the setup.
//
// * Result: We can't have mutable references to the setup, because we have
// living (immutable) references to the keystore floating around. As a follow-up
// result, we need to populate the keystore _completely_ before distributing the
// references, as we can't mutably reference the keystore.
//
//   * Note, that (to my knowledge) we can't have the keystore live in a
//   refcell, because then the references are based on the local `borrow()`ed
//   object and won't live long enough.
