use std::{cell::RefCell, collections::HashMap};

use openmls::prelude::{node::Node, *};

use super::{errors::ClientError, KeyStore};

#[derive(Debug)]
pub struct Client<'managed_group_lifetime> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) _ciphersuites: Vec<CiphersuiteName>,
    pub(crate) key_store: &'managed_group_lifetime KeyStore,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
    pub(crate) groups: RefCell<HashMap<GroupId, ManagedGroup<'managed_group_lifetime>>>,
}

impl<'managed_group_lifetime> Client<'managed_group_lifetime> {
    pub fn get_fresh_key_package(
        &self,
        ciphersuite: &Ciphersuite,
    ) -> Result<KeyPackage, ClientError> {
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite.name())
            .ok_or(ClientError::CiphersuiteNotSupported)?;
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
        Ok(key_package)
    }

    pub fn create_group(
        &self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) -> Result<Vec<Option<Node>>, ClientError> {
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite.name())
            .ok_or(ClientError::CiphersuiteNotSupported)?;
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
        )?;
        let tree = group_state.export_ratchet_tree();
        self.groups.borrow_mut().insert(group_id, group_state);
        Ok(tree)
    }

    pub fn join_group(
        &self,
        managed_group_config: ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let encrypted_group_secret = welcome
            .secrets()
            .iter()
            .find(|egs| {
                self.key_package_bundles
                    .borrow()
                    .contains_key(&egs.key_package_hash)
            })
            .ok_or(ClientError::NoMatchingKeyPackage)?;
        // We can unwrap here, because we just checked that this kpb exists.
        // Also, we should be fine just removing the KeyPackageBundle here,
        // because it shouldn't be used again anyway.
        let key_package_bundle = self
            .key_package_bundles
            .borrow_mut()
            .remove(&encrypted_group_secret.key_package_hash)
            .unwrap();
        let ciphersuite = key_package_bundle.key_package().ciphersuite_name();
        let credential_bundle = self
            .key_store
            .get_credential(&self.identity, ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported)?;
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
        let group_state = group_states
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        Ok(group_state.process_messages(messages)?)
    }

    pub fn get_members_of_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(usize, Credential)>, ClientError> {
        let groups = self.groups.borrow();
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let mut members = vec![];
        let tree = group.export_ratchet_tree();
        for index in 0..tree.len() {
            if index % 2 == 0 {
                let leaf = &tree[index];
                if let Some(leaf_node) = leaf {
                    let key_package = leaf_node.key_package().unwrap();
                    members.push((index / 2, key_package.credential().clone()));
                }
            }
        }
        Ok(members)
    }
}
