//! This module provides the `Client` datastructure, which contains the state
//! associated with a client in the context of MLS, along with functions to have
//! that client perform certain MLS operations.
use std::{cell::RefCell, collections::HashMap};

use openmls::{node::Node, prelude::*};

use super::{errors::ClientError, ActionType, KeyStore};

#[derive(Debug)]
/// The client contains the necessary state for a client in the context of MLS.
/// It contains the group states, as well as a reference to a `KeyStore`
/// containing its `CredentialBundle`s. The `key_package_bundles` field contains
/// generated `KeyPackageBundle`s that are waiting to be used for new groups.
pub struct Client<'key_store_lifetime> {
    /// Name of the client.
    pub(crate) identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub(crate) key_store: &'key_store_lifetime KeyStore,
    // Map from key package hash to the corresponding bundle.
    pub(crate) key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
    pub(crate) groups: RefCell<HashMap<GroupId, ManagedGroup<'key_store_lifetime>>>,
}

impl<'key_store_lifetime> Client<'key_store_lifetime> {
    /// Generate a fresh key package bundle and store it in
    /// `self.key_package_bundles`. The first ciphersuite determines the
    /// credential used to generate the `KeyPackageBundle`. Returns the
    /// corresponding `KeyPackage`.
    pub fn get_fresh_key_package(
        &self,
        ciphersuites: &[CiphersuiteName],
    ) -> Result<KeyPackage, ClientError> {
        if ciphersuites.is_empty() {
            return Err(ClientError::NoCiphersuite);
        }
        let credential_bundle = self
            .key_store
            .get_credential(&(self.identity.clone(), ciphersuites[0]))
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let mandatory_extensions = Vec::new();
        let key_package_bundle: KeyPackageBundle =
            KeyPackageBundle::new(ciphersuites, &credential_bundle, mandatory_extensions).unwrap();
        let key_package = key_package_bundle.key_package().clone();
        self.key_package_bundles
            .borrow_mut()
            .insert(key_package_bundle.key_package().hash(), key_package_bundle);
        Ok(key_package)
    }

    /// Create a group with the given `group_id`, `ciphersuite` and
    /// `managed_group_config`. Throws an error if the client doesn't support
    /// the `ciphersuite`, i.e. if no corresponding `CredentialBundle` exists.
    pub fn create_group(
        &self,
        group_id: GroupId,
        managed_group_config: ManagedGroupConfig,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), ClientError> {
        let credential_bundle = self
            .key_store
            .get_credential(&(self.identity.clone(), ciphersuite.name()))
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
        self.groups.borrow_mut().insert(group_id, group_state);
        Ok(())
    }

    /// Join a group based on the given `welcome` and `ratchet_tree`. The group
    /// is created with the given `ManagedGroupConfig`. Throws an error if no
    /// `KeyPackage` exists matching the `Welcome`, if the client doesn't
    /// support the ciphersuite, or if an error occurs processing the `Welcome`.
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
            .get_credential(&(self.identity.clone(), ciphersuite))
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let new_group: ManagedGroup<'key_store_lifetime> = ManagedGroup::new_from_welcome(
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

    /// Have the client process the given messages. Returns an error if an error
    /// occurs during message processing or if no group exists for one of the
    /// messages.
    pub fn receive_messages_for_group(&self, messages: &[MLSMessage]) -> Result<(), ClientError> {
        let mut group_states = self.groups.borrow_mut();
        for message in messages {
            let group_id = GroupId::from_slice(&message.group_id());
            let group_state = group_states
                .get_mut(&group_id)
                .ok_or(ClientError::NoMatchingGroup)?;
            // Prevent feeding further messages to client after it was removed
            // by one of the messages.
            if !group_state.is_active() {
                return Ok(());
            }
            group_state.process_messages(vec![message.clone()])?;
        }
        Ok(())
    }

    /// Get the credential and the index of each group member of the group with
    /// the given id. Returns an error if no group exists with the given group
    /// id.
    pub fn get_members_of_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(usize, Credential)>, ClientError> {
        let groups = self.groups.borrow();
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let mut members = vec![];
        let tree = group.export_ratchet_tree();
        for (index, leaf) in tree.iter().enumerate() {
            if index % 2 == 0 {
                if let Some(leaf_node) = leaf {
                    let key_package = leaf_node.key_package().unwrap();
                    members.push((index / 2, key_package.credential().clone()));
                }
            }
        }
        Ok(members)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) a self update in the group with the given group id.
    /// Optionally, a `KeyPackageBundle` can be provided, which the client will
    /// update their leaf with. Returns an error if no group with the given
    /// group id can be found or if an error occurs while creating the update.
    pub fn self_update(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => group.self_update(key_package_bundle_option)?,
            ActionType::Proposal => (group.propose_self_update(key_package_bundle_option)?, None),
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) adding the clients with the given `KeyPackage`s to the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// add operation.
    pub fn add_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
        include_path: bool,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => {
                let (messages, welcome) = group.add_members(key_packages, include_path)?;
                (messages, Some(welcome))
            }
            ActionType::Proposal => (group.propose_add_members(key_packages)?, None),
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) removing the clients with the given indices from the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// remove operation.
    pub fn remove_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        target_indices: &[usize],
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => group.remove_members(target_indices)?,
            ActionType::Proposal => (group.propose_remove_members(target_indices)?, None),
        };
        Ok(action_results)
    }
}
