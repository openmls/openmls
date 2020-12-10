use openmls::prelude::{node::Node, *};
use rand::{rngs::OsRng, RngCore};
use std::{collections::HashMap, convert::TryInto};

/// Errors that can occur when processing messages with the client.
pub enum ClientError {
    NoMatchingKeyPackage,
    NoMatchingCredential,
    FailedToJoinGroup,
}

impl From<WelcomeError> for ClientError {
    fn from(_: WelcomeError) -> Self {
        ClientError::FailedToJoinGroup
    }
}

struct Client<'a> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) ciphersuites: Vec<CiphersuiteName>,
    credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: HashMap<Vec<u8>, KeyPackageBundle>,
    pub(crate) key_packages: HashMap<CiphersuiteName, KeyPackage>,
    pub(crate) group_states: HashMap<GroupId, ManagedGroup<'a>>,
}

impl<'a> Client<'a> {
    pub fn get_fresh_key_package(&mut self, ciphersuite: &Ciphersuite) -> KeyPackage {
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
            .insert(key_package_bundle.key_package().hash(), key_package_bundle);
        key_package
    }

    pub fn create_group(
        &mut self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) {
        let credential_bundle = self.credential_bundles.get(&ciphersuite.name()).unwrap();
        let key_package = self.get_fresh_key_package(ciphersuite);
        let key_package_bundle = self
            .key_package_bundles
            .remove(&key_package.hash())
            .unwrap();
        let group_state = ManagedGroup::new(
            credential_bundle,
            &managed_group_config,
            group_id,
            key_package_bundle,
        )
        .unwrap();
    }

    pub fn join_group(
        &mut self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let ciphersuite = welcome.ciphersuite();
        let credential_bundle: &'a CredentialBundle = self
            .credential_bundles
            .get(&ciphersuite.name())
            .ok_or(ClientError::NoMatchingCredential)?;
        let key_package_bundle = match welcome
            .secrets()
            .iter()
            .find(|egs| self.key_package_bundles.contains_key(&egs.key_package_hash))
        {
            // We can unwrap here, because we just checked that this kpb exists.
            // Also, we should be fine just removing the KeyPackageBundle here,
            // because it shouldn't be used again anyway.
            Some(egs) => Ok(self
                .key_package_bundles
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
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    // TODO: Write a function that allows a member to simply process a message.
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
            let ciphersuites = Config::supported_ciphersuite_names();
            let mut credential_bundles = HashMap::new();
            let mut key_packages = HashMap::new();
            for ciphersuite in &ciphersuites {
                let credential_bundle = CredentialBundle::new(
                    identity.clone(),
                    CredentialType::Basic,
                    ciphersuite.clone(),
                )
                .unwrap();
                credential_bundles.insert(ciphersuite.clone(), credential_bundle);
            }
            let key_package_bundles = HashMap::new();
            let client = Client {
                identity,
                ciphersuites,
                credential_bundles,
                key_package_bundles,
                key_packages,
                group_states: HashMap::new(),
            };
            clients.push(client)
        }
        let groups = Vec::new();
        ManagedTestSetup { clients, groups }
    }

    /// Create a random group of size `group_size` and return the `GroupId`
    pub fn create_random_group(
        &mut self,
        group_size: usize,
        ciphersuite: &Ciphersuite,
        managed_group_config: ManagedGroupConfig,
    ) -> GroupId {
        if group_size > self.clients.len() {
            panic!("Not enough members to create a group this large.");
        }

        // Pick a random group creator.
        let group_creator_id = (OsRng.next_u32() as usize) % self.clients.len();
        let group_creator = self.clients[group_creator_id];
        let group_id = GroupId {
            value: self.groups.len().to_be_bytes().to_vec(),
        };
        group_creator.create_group(group_id, managed_group_config, ciphersuite);
        let members = vec![group_creator_id];
        for i in 0..group_size {
            // Get a random group member.
            let adder_id = (OsRng.next_u32() as usize) % members.len();
            let adder = self.clients[group_creator_id];
            let adder_group_state = adder.group_states.get(&group_id).unwrap();
            // Pick a client that's not already a member.
            let new_member = self.clients.iter().find(|client| {
                !members
                    .contains(&(u32::from_be_bytes(client.identity.try_into().unwrap()) as usize))
            });
            let key_package = new_member.unwrap().get_fresh_key_package(ciphersuite);
            adder_group_state.add_members(&[key_package]);
        }
        group_id
    }
}

#[test]
fn test_randomized_setup() {
    let setup = ManagedTestSetup::new(2000);
}
