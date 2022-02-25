//! This module provides the `Client` datastructure, which contains the state
//! associated with a client in the context of MLS, along with functions to have
//! that client perform certain MLS operations.
use std::{collections::HashMap, sync::RwLock};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::{
    ciphersuite::hash_ref::KeyPackageRef, credentials::*, extensions::*, framing::MlsMessageIn,
    framing::*, group::*, key_packages::*, messages::*, treesync::node::Node,
};

use super::{errors::ClientError, ActionType};

#[derive(Debug)]
/// The client contains the necessary state for a client in the context of MLS.
/// It contains the group states, as well as a reference to a `KeyStore`
/// containing its `CredentialBundle`s. The `key_package_bundles` field contains
/// generated `KeyPackageBundle`s that are waiting to be used for new groups.
pub struct Client {
    /// Name of the client.
    pub identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub credentials: HashMap<Ciphersuite, Credential>,
    pub crypto: OpenMlsRustCrypto,
    pub groups: RwLock<HashMap<GroupId, MlsGroup>>,
}

impl Client {
    /// Generate a fresh key package bundle and store it in
    /// `self.key_package_bundles`. The first ciphersuite determines the
    /// credential used to generate the `KeyPackageBundle`. Returns the
    /// corresponding `KeyPackage`.
    pub fn get_fresh_key_package(
        &self,
        ciphersuites: &[Ciphersuite],
    ) -> Result<KeyPackage, ClientError> {
        if ciphersuites.is_empty() {
            return Err(ClientError::NoCiphersuite);
        }
        let credential = self
            .credentials
            .get(&ciphersuites[0])
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let mandatory_extensions: Vec<Extension> =
            vec![Extension::LifeTime(LifetimeExtension::new(157788000))]; // 5 years
        let credential_bundle: CredentialBundle = self
            .crypto
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
            )
            .ok_or(ClientError::NoMatchingCredential)?;
        let kpb = KeyPackageBundle::new(
            ciphersuites,
            &credential_bundle,
            &self.crypto,
            mandatory_extensions,
        )
        .expect("An unexpected error occurred.");
        let kp = kpb.key_package().clone();
        self.crypto
            .key_store()
            .store(kp.hash_ref(self.crypto.crypto())?.value(), &kpb)
            .expect("An unexpected error occurred.");
        Ok(kp)
    }

    /// Create a group with the given `group_id`, `ciphersuite` and
    /// `mls_group_config`. Throws an error if the client doesn't support
    /// the `ciphersuite`, i.e. if no corresponding `CredentialBundle` exists.
    pub fn create_group(
        &self,
        group_id: GroupId,
        mls_group_config: MlsGroupConfig,
        ciphersuite: Ciphersuite,
    ) -> Result<(), ClientError> {
        let credential = self
            .credentials
            .get(&ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let mandatory_extensions: Vec<Extension> =
            vec![Extension::LifeTime(LifetimeExtension::new(157788000))]; // 5 years
        let credential_bundle: CredentialBundle = self
            .crypto
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
            )
            .ok_or(ClientError::NoMatchingCredential)?;
        let kpb = KeyPackageBundle::new(
            &[ciphersuite],
            &credential_bundle,
            &self.crypto,
            mandatory_extensions,
        )
        .expect("An unexpected error occurred.");
        let key_package = kpb.key_package().clone();
        self.crypto
            .key_store()
            .store(key_package.hash_ref(self.crypto.crypto())?.value(), &kpb)
            .expect("An unexpected error occurred.");
        let group_state = MlsGroup::new(
            &self.crypto,
            &mls_group_config,
            group_id.clone(),
            key_package.hash_ref(self.crypto.crypto())?.value(),
        )?;
        self.groups
            .write()
            .expect("An unexpected error occurred.")
            .insert(group_id, group_state);
        Ok(())
    }

    /// Join a group based on the given `welcome` and `ratchet_tree`. The group
    /// is created with the given `MlsGroupConfig`. Throws an error if no
    /// `KeyPackage` exists matching the `Welcome`, if the client doesn't
    /// support the ciphersuite, or if an error occurs processing the `Welcome`.
    pub fn join_group(
        &self,
        mls_group_config: MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<(), ClientError> {
        let new_group: MlsGroup =
            MlsGroup::new_from_welcome(&self.crypto, &mls_group_config, welcome, ratchet_tree)?;
        self.groups
            .write()
            .expect("An unexpected error occurred.")
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    /// Have the client process the given messages. Returns an error if an error
    /// occurs during message processing or if no group exists for one of the
    /// messages.
    pub fn receive_messages_for_group(
        &self,
        message: &MlsMessageIn,
        sender_id: &[u8],
    ) -> Result<(), ClientError> {
        let mut group_states = self.groups.write().expect("An unexpected error occurred.");
        let group_id = message.group_id();
        let group_state = group_states
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        if sender_id == self.identity && message.content_type() == ContentType::Commit {
            group_state.merge_pending_commit()?
        } else {
            if message.content_type() == ContentType::Commit {
                // Clear any potential pending commits.
                group_state.clear_pending_commit();
            }
            // Process the message.
            let unverified_message = group_state.parse_message(message.clone(), &self.crypto)?;
            let processed_message =
                group_state.process_unverified_message(unverified_message, None, &self.crypto)?;

            match processed_message {
                ProcessedMessage::ApplicationMessage(_) => {}
                ProcessedMessage::ProposalMessage(staged_proposal) => {
                    group_state.store_pending_proposal(*staged_proposal);
                }
                ProcessedMessage::StagedCommitMessage(staged_commit) => {
                    group_state.merge_staged_commit(*staged_commit)?;
                }
            }
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
        let groups = self.groups.read().expect("An unexpected error occurred.");
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let members = group.indexed_members().expect("error getting members");
        Ok(members
            .into_iter()
            .map(|(index, kp)| (index as usize, kp.credential().clone()))
            .collect())
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
    ) -> Result<(MlsMessageOut, Option<Welcome>), ClientError> {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => group.self_update(&self.crypto, key_package_bundle_option)?,
            ActionType::Proposal => (
                group.propose_self_update(&self.crypto, key_package_bundle_option)?,
                None,
            ),
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
    ) -> Result<(Vec<MlsMessageOut>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => {
                let (messages, welcome) = group.add_members(&self.crypto, key_packages)?;
                (vec![messages], Some(welcome))
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for key_package in key_packages {
                    let message = group.propose_add_member(&self.crypto, key_package)?;
                    messages.push(message);
                }
                (messages, None)
            }
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
        targets: &[KeyPackageRef],
    ) -> Result<(Vec<MlsMessageOut>, Option<Welcome>), ClientError> {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        let action_results = match action_type {
            ActionType::Commit => {
                let (message, welcome_option) = group.remove_members(&self.crypto, targets)?;
                (vec![message], welcome_option)
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for target in targets {
                    let message = group.propose_remove_member(&self.crypto, target)?;
                    messages.push(message);
                }
                (messages, None)
            }
        };
        Ok(action_results)
    }

    /// Get the [`KeyPackageRef`] of this client in the given group.
    pub fn key_package_ref(&self, group_id: &GroupId) -> Option<KeyPackageRef> {
        let groups = self.groups.read().expect("An unexpected error occurred.");
        let group = groups.get(group_id).expect("An unexpected error occurred.");
        group.key_package_ref().cloned()
    }
}
