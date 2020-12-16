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

/// This struct models a client that can be used for testing functions of the
/// Managed Group API.
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
    /// Get a fresh key package for this client.
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

    /// Have the client create a fresh group with the given `GroupId`.
    pub fn create_group(
        &'a self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) {
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
        self.groups.borrow_mut().insert(group_id, group_state);
    }

    /// Have the client join a group given a `Welcome` message.
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

    /// Have the client receive messages for the group with group ID `group_id`.
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

/// This struct contains the global state of a test setup. The `groups` field
/// currently only serves as a counter to generate `GroupId`s for new groups.
struct ManagedTestSetup<'a> {
    // The clients identity is its position in the vector in be_bytes.
    clients: Vec<Client<'a>>,
    groups: Vec<GroupId>,
}

impl<'a> ManagedTestSetup<'a> {
    /// Create a new `ManagedTestSetup` with a given number of clients.
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
        let groups = Vec::new();
        ManagedTestSetup { clients, groups }
    }

    /// Create a random group of size `group_size` and return the `GroupId`. The
    /// group is created by an initial creator client and is then subsequently
    /// extended by random group members, who add a random number of clients
    /// until the desired group size is reached.
    pub fn create_random_group(
        &'a self,
        group_size: usize,
        ciphersuite: &Ciphersuite,
        managed_group_config: ManagedGroupConfig,
    ) -> GroupId {
        if group_size > self.clients.len() {
            panic!("Not enough members to create a group this large.");
        }

        // Pick a random group creator.
        let group_creator_id = (OsRng.next_u32() as usize) % self.clients.len();
        let group_creator = &self.clients[group_creator_id];
        let group_id = GroupId {
            value: self.groups.len().to_string().into_bytes(),
        };
        group_creator.create_group(group_id.clone(), managed_group_config.clone(), ciphersuite);
        let mut members = Vec::new();
        members.push(group_creator);
        while members.len() < group_size {
            // Get a random group member.
            let adder_id = (OsRng.next_u32() as usize) % members.len();
            let adder = members[adder_id];
            let mut adder_group_states = adder.groups.borrow_mut();
            let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();

            // How many members to add at once?
            let members_to_add = (OsRng.next_u32() as usize) % (group_size - members.len()) + 1;

            // Pick a number of clients that are not already members.
            let mut new_members: Vec<&Client<'a>> = Vec::new();
            let mut new_member_key_packages = Vec::new();
            for _ in 0..members_to_add {
                let new_member = self
                    .clients
                    .iter()
                    .find(|client| {
                        (members
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
                let key_package = new_member.get_fresh_key_package(ciphersuite);
                new_members.push(new_member);
                new_member_key_packages.push(key_package);
            }
            println!("KPs: {:?}", new_member_key_packages.len());
            assert_eq!(members_to_add, new_member_key_packages.len());
            // Have the adder add them to the group.
            let (mls_messages, welcome) = adder_group_state
                .add_members(new_member_key_packages.as_slice())
                .unwrap();
            drop(adder_group_states);
            for member in members.iter() {
                member
                    .receive_messages_for_group(&group_id, mls_messages.clone())
                    .unwrap();
            }
            let group_states = members[0].groups.borrow_mut();
            let group_state = group_states.get(&group_id).unwrap();
            let ratchet_tree = group_state.export_ratchet_tree();
            drop(group_states);
            for m in &members {
                let group_states = m.groups.borrow_mut();
                let group_state = group_states.get(&group_id).unwrap();
                assert_eq!(group_state.export_ratchet_tree(), ratchet_tree);
                drop(group_states);
            }
            for new_member in new_members.iter() {
                new_member
                    .join_group(
                        managed_group_config.clone(),
                        welcome.clone(),
                        Some(ratchet_tree.clone()),
                    )
                    .unwrap();
            }
            members.extend(new_members);
        }
        group_id
    }
}

/// A small test that creates a `ManagedTestSetup` with a number of users and a
/// group with a subset of those users. As the group is created by adding
/// multiple members at a time (with high probability), this serves as a basic
/// test for the ordering of the ProposalQueue. If the ProposalQueue was not
/// ordered deterministically, the state of the individual members would diverge
/// and adding a new member would fail, as the `confirmation_tag` would differ.
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

    // Create a sufficiently large `ManagedTestSetup`.
    let setup = ManagedTestSetup::new(30);
    for ciphersuite in Config::supported_ciphersuites() {
        let handshake_message_format = HandshakeMessageFormat::Plaintext;
        let update_policy = UpdatePolicy::default();
        let callbacks = ManagedGroupCallbacks::new()
            .with_member_added(member_added)
            .with_invalid_message_received(invalid_message_received)
            .with_error_occured(error_occured);
        let managed_group_config =
            ManagedGroupConfig::new(handshake_message_format, update_policy, callbacks);
        // Create a sufficiently large group.
        setup.create_random_group(20, ciphersuite, managed_group_config);
    }
}
