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
    InvalidMessage,
    GroupError(ManagedGroupError),
}

impl From<WelcomeError> for ClientError {
    fn from(e: WelcomeError) -> Self {
        ClientError::FailedToJoinGroup(e)
    }
}

impl From<ManagedGroupError> for ClientError {
    fn from(e: ManagedGroupError) -> Self {
        ClientError::GroupError(e)
    }
}

struct Client<'a> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) _ciphersuites: Vec<CiphersuiteName>,
    credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
    //pub(crate) key_packages: HashMap<CiphersuiteName, KeyPackage>,
    pub(crate) group_states: RefCell<HashMap<GroupId, ManagedGroup<'a>>>,
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
    ) {
        let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
        let key_package = self.get_fresh_key_package(ciphersuite);
        let key_package_bundle = self
            .key_package_bundles
            .borrow_mut()
            .remove(&key_package.hash())
            .unwrap();
        let group_state = ManagedGroup::new(
            credential_bundle,
            &managed_group_config,
            group_id.clone(),
            key_package_bundle,
        )
        .unwrap();
        self.group_states.borrow_mut().insert(group_id, group_state);
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
        self.group_states
            .borrow_mut()
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    pub fn receive_messages_for_group(
        &self,
        group_id: &GroupId,
        messages: Vec<MLSMessage>,
    ) -> Result<(), ClientError> {
        let mut group_states = self.group_states.borrow_mut();
        let group_state = match group_states.get_mut(group_id) {
            Some(group_state) => group_state,
            None => return Err(ClientError::NoMatchingGroup),
        };
        Ok(group_state.process_messages(messages)?)
    }
}

struct ManagedTestSetup<'a> {
    // The clients identity is its position in the vector in be_bytes.
    clients: Vec<Client<'a>>,
    groups: Vec<GroupId>,
}

impl<'a> ManagedTestSetup<'a> {
    pub fn new(number_of_clients: usize) -> Self {
        let mut clients = Vec::new();
        for i in 0..number_of_clients {
            let identity = i.to_be_bytes().to_vec();
            // For now, everyone supports all ciphersuites.
            let _ciphersuites = Config::supported_ciphersuite_names();
            let mut credential_bundles = HashMap::new();
            for ciphersuite in &_ciphersuites {
                let credential_bundle = CredentialBundle::new(
                    identity.clone(),
                    CredentialType::Basic,
                    ciphersuite.clone(),
                )
                .unwrap();
                credential_bundles.insert(ciphersuite.clone(), credential_bundle);
            }
            let key_package_bundles = RefCell::new(HashMap::new());
            let client = Client {
                identity,
                _ciphersuites,
                credential_bundles,
                key_package_bundles,
                group_states: RefCell::new(HashMap::new()),
            };
            clients.push(client)
        }
        let groups = Vec::new();
        ManagedTestSetup { clients, groups }
    }

    /// Create a random group of size `group_size` and return the `GroupId`
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
            value: self.groups.len().to_be_bytes().to_vec(),
        };
        group_creator.create_group(group_id.clone(), managed_group_config.clone(), ciphersuite);
        //let creator_group_states = group_creator.group_states.borrow();
        //let creator_group_state = creator_group_states.get(&group_id).unwrap();
        let mut members = Vec::new();
        members.push(group_creator);
        while members.len() < group_size {
            // Get a random group member.
            let adder_id = (OsRng.next_u32() as usize) % members.len();
            println!("adder_id: {:?}", adder_id);
            let adder = members[adder_id];
            let mut adder_group_states = adder.group_states.borrow_mut();
            let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();

            // How many members to add at once?
            let members_to_add = (OsRng.next_u32() as usize) % (group_size - members.len());

            // Pick a number of clients that are not already members.
            let mut new_members: Vec<&Client<'a>> = Vec::new();
            let mut new_member_key_packages = Vec::new();
            for _ in 0..members_to_add {
                let new_member = self
                    .clients
                    .iter()
                    .find(|client| {
                        let identity = client.identity.clone();
                        (!members
                            .iter()
                            .find(|member| member.identity == identity)
                            .is_some())
                            & (!new_members
                                .iter()
                                .find(|member| member.identity == identity)
                                .is_some())
                    })
                    .unwrap();
                // Get a fresh key package from each of them.
                let key_package = new_member.get_fresh_key_package(ciphersuite);
                new_members.push(new_member);
                new_member_key_packages.push(key_package);
            }
            println!("KPs: {:?}", new_member_key_packages.len());
            // Have the adder add them to the group.
            let (mls_messages, welcome) = adder_group_state
                .add_members(new_member_key_packages.as_slice())
                .unwrap();
            drop(adder_group_state);
            drop(adder_group_states);
            let _ = members
                .iter()
                .map(|member| {
                    member
                        .receive_messages_for_group(&group_id, mls_messages.clone())
                        .unwrap();
                })
                .collect::<Vec<_>>();
            let group_states = members[0].group_states.borrow_mut();
            let group_state = group_states.get(&group_id).unwrap();
            let ratchet_tree = group_state.export_ratchet_tree();
            //let mut adder_group_states = adder.group_states.borrow_mut();
            //let adder_group_state = adder_group_states.get_mut(&group_id).unwrap();
            //let ratchet_tree = adder_group_state.export_ratchet_tree();
            //drop(adder_group_state);
            //drop(adder_group_states);
            let _ = new_members
                .iter()
                .map(|nm| {
                    println!("Ratchet Tree: {:?}", ratchet_tree);
                    nm.join_group(
                        managed_group_config.clone(),
                        welcome.clone(),
                        Some(ratchet_tree.clone()),
                    )
                    .unwrap();
                    println!("A member just joined.")
                })
                .collect::<Vec<_>>();
        }
        group_id
    }
}

#[test]
fn test_randomized_setup() {
    let setup = ManagedTestSetup::new(2000);
    for ciphersuite in Config::supported_ciphersuites() {
        let handshake_message_format = HandshakeMessageFormat::Ciphertext;
        let update_policy = UpdatePolicy::default();
        let callbacks = ManagedGroupCallbacks::default();
        let managed_group_config =
            ManagedGroupConfig::new(handshake_message_format, update_policy, callbacks);
        setup.create_random_group(100, ciphersuite, managed_group_config);
    }
}
