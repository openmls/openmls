use openmls::prelude::*;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;

struct Client<'a> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) ciphersuites: Vec<CiphersuiteName>,
    pub(crate) credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
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
}

// For now, everyone generates 20 KeyPackages.
const KEY_PACKAGE_COUNT: usize = 20;

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
        let group_id = group_creator.create_group(group_id, managed_group_config, ciphersuite);
        let members = vec![group_creator_id];
        let potential_members =
        for i in 0..group_size {
            // Get a random group member.
            let adder_id = (OsRng.next_u32() as usize) % members.len();
            let adder = self.clients[group_creator_id];

        }
        group_id
    }
}

#[test]
fn test_randomized_setup() {
    let setup = ManagedTestSetup::new(2000);
}
