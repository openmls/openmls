//! This module provides the `Client` datastructure, which contains the state
//! associated with a client in the context of MLS, along with functions to have
//! that client perform certain MLS operations.
use std::{collections::HashMap, sync::RwLock};

use commit_builder::CommitMessageBundle;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    types::{Ciphersuite, HpkeKeyPair, SignatureScheme},
    OpenMlsProvider as _,
};
use tls_codec::{Deserialize, Serialize};

use super::OpenMlsRustCrypto;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::hash_ref::KeyPackageRef,
    credentials::*,
    extensions::*,
    framing::*,
    group::*,
    key_packages::*,
    messages::{group_info::GroupInfo, *},
    storage::OpenMlsProvider,
    treesync::{
        node::{leaf_node::Capabilities, Node},
        LeafNode, LeafNodeParameters, RatchetTree, RatchetTreeIn,
    },
    versions::ProtocolVersion,
};

use super::{errors::ClientError, ActionType};

#[derive(Debug)]
/// The client contains the necessary state for a client in the context of MLS.
/// It contains the group states, as well as a reference to a `KeyStore`
/// containing its `CredentialWithKey`s. The `key_package_bundles` field
/// contains generated `KeyPackageBundle`s that are waiting to be used for new
/// groups.
pub struct Client<Provider: OpenMlsProvider> {
    /// Name of the client.
    pub identity: Vec<u8>,
    /// Ciphersuites supported by the client.
    pub credentials: HashMap<Ciphersuite, CredentialWithKey>,
    pub provider: Provider,
    pub groups: RwLock<HashMap<GroupId, MlsGroup>>,
}

impl<Provider: OpenMlsProvider> Client<Provider> {
    /// Generate a fresh key package and return it.
    /// The first ciphersuite determines the
    /// credential used to generate the `KeyPackage`.
    pub fn get_fresh_key_package(
        &self,
        ciphersuite: Ciphersuite,
    ) -> Result<KeyPackage, ClientError<Provider::StorageError>> {
        let credential_with_key = self
            .credentials
            .get(&ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported)?;
        let keys = SignatureKeyPair::read(
            self.provider.storage(),
            credential_with_key.signature_key.as_slice(),
            ciphersuite.signature_algorithm(),
        )
        .unwrap();

        let key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                &self.provider,
                &keys,
                credential_with_key.clone(),
            )
            .unwrap();

        Ok(key_package.key_package)
    }

    /// Create a group with the given [MlsGroupCreateConfig] and [Ciphersuite], and return the created [GroupId].
    ///
    /// Returns an error if the client doesn't support the `ciphersuite`.
    pub fn create_group(
        &self,
        mls_group_create_config: MlsGroupCreateConfig,
        ciphersuite: Ciphersuite,
    ) -> Result<GroupId, ClientError<Provider::StorageError>> {
        let credential_with_key = self
            .credentials
            .get(&ciphersuite)
            .ok_or(ClientError::CiphersuiteNotSupported);
        let credential_with_key = credential_with_key?;
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            credential_with_key.signature_key.as_slice(),
            ciphersuite.signature_algorithm(),
        )
        .unwrap();

        let group_state = MlsGroup::new(
            &self.provider,
            &signer,
            &mls_group_create_config,
            credential_with_key.clone(),
        )?;
        let group_id = group_state.group_id().clone();
        self.groups
            .write()
            .expect("An unexpected error occurred.")
            .insert(group_state.group_id().clone(), group_state);
        Ok(group_id)
    }

    /// Join a group based on the given `welcome` and `ratchet_tree`. The group
    /// is created with the given `MlsGroupCreateConfig`. Throws an error if no
    /// `KeyPackage` exists matching the `Welcome`, if the client doesn't
    /// support the ciphersuite, or if an error occurs processing the `Welcome`.
    pub fn join_group(
        &self,
        mls_group_config: MlsGroupJoinConfig,
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<(), ClientError<Provider::StorageError>> {
        let staged_join = StagedWelcome::new_from_welcome(
            &self.provider,
            &mls_group_config,
            welcome,
            ratchet_tree,
        )?;
        let new_group = staged_join.into_group(&self.provider)?;
        self.groups
            .write()
            .expect("An unexpected error occurred.")
            .insert(new_group.group_id().to_owned(), new_group);
        Ok(())
    }

    /// Have the client process the given messages. Returns an error if an error
    /// occurs during message processing or if no group exists for one of the
    /// messages.
    pub fn receive_messages_for_group<AS: Fn(&Credential) -> bool>(
        &self,
        message: &ProtocolMessage,
        sender_id: &[u8],
        authentication_service: &AS,
    ) -> Result<(), ClientError<Provider::StorageError>> {
        let mut group_states = self.groups.write().expect("An unexpected error occurred.");
        let group_id = message.group_id();
        let group_state = group_states
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        if sender_id == self.identity && message.content_type() == ContentType::Commit {
            group_state.merge_pending_commit(&self.provider)?
        } else {
            if message.content_type() == ContentType::Commit {
                // Clear any potential pending commits.
                group_state.clear_pending_commit(self.provider.storage())?;
            }
            // Process the message.
            let processed_message = group_state
                .process_message(&self.provider, message.clone())
                .map_err(ClientError::ProcessMessageError)?;

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => {}
                ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                    group_state
                        .store_pending_proposal(self.provider.storage(), *staged_proposal)?;
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(staged_proposal) => {
                    group_state
                        .store_pending_proposal(self.provider.storage(), *staged_proposal)?;
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    for credential in staged_commit.credentials_to_verify() {
                        if !authentication_service(credential) {
                            println!(
                                "authentication service callback denied credential {credential:?}"
                            );
                            return Err(ClientError::NoMatchingCredential);
                        }
                    }
                    group_state.merge_staged_commit(&self.provider, *staged_commit)?;
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
    ) -> Result<Vec<Member>, ClientError<Provider::StorageError>> {
        let groups = self.groups.read().expect("An unexpected error occurred.");
        let group = groups.get(group_id).ok_or(ClientError::NoMatchingGroup)?;
        let members = group.members().collect();
        Ok(members)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) a self update in the group with the given group id.
    /// Optionally, a `HpkeKeyPair` can be provided, which the client will
    /// update their leaf with. Returns an error if no group with the given
    /// group id can be found or if an error occurs while creating the update.
    #[allow(clippy::type_complexity)]
    pub fn self_update(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<
        (MlsMessageOut, Option<Welcome>, Option<GroupInfo>),
        ClientError<Provider::StorageError>,
    > {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            signature_pk.as_slice(),
            group.ciphersuite().signature_algorithm(),
        )
        .unwrap();
        let (msg, welcome_option, group_info) = match action_type {
            ActionType::Commit => {
                let bundle =
                    group.self_update(&self.provider, &signer, LeafNodeParameters::default())?;

                let welcome = bundle.to_welcome_msg();
                let (msg, _, group_info) = bundle.into_contents();

                (msg, welcome, group_info)
            }
            ActionType::Proposal => {
                let (msg, _) =
                    group.propose_self_update(&self.provider, &signer, leaf_node_parameters)?;

                (msg, None, None)
            }
        };
        Ok((
            msg,
            welcome_option.map(|w| w.into_welcome().expect("Unexpected message type.")),
            group_info,
        ))
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) adding the clients with the given `KeyPackage`s to the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// add operation.
    #[allow(clippy::type_complexity)]
    pub fn add_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
    ) -> Result<
        (Vec<MlsMessageOut>, Option<Welcome>, Option<GroupInfo>),
        ClientError<Provider::StorageError>,
    > {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            signature_pk.as_slice(),
            group.ciphersuite().signature_algorithm(),
        )
        .unwrap();
        let action_results = match action_type {
            ActionType::Commit => {
                let (messages, welcome_message, group_info) =
                    group.add_members(&self.provider, &signer, key_packages)?;
                (
                    vec![messages],
                    Some(
                        welcome_message
                            .into_welcome()
                            .expect("Unexpected message type."),
                    ),
                    group_info,
                )
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for key_package in key_packages {
                    let message = group
                        .propose_add_member(&self.provider, &signer, key_package)
                        .map(|(out, _)| out)?;
                    messages.push(message);
                }
                (messages, None, None)
            }
        };
        Ok(action_results)
    }

    /// Have the client either propose or commit (depending on the
    /// `action_type`) removing the clients with the given indices from the
    /// group with the given group id. Returns an error if no group with the
    /// given group id can be found or if an error occurs while performing the
    /// remove operation.
    #[allow(clippy::type_complexity)]
    pub fn remove_members(
        &self,
        action_type: ActionType,
        group_id: &GroupId,
        targets: &[LeafNodeIndex],
    ) -> Result<
        (Vec<MlsMessageOut>, Option<Welcome>, Option<GroupInfo>),
        ClientError<Provider::StorageError>,
    > {
        let mut groups = self.groups.write().expect("An unexpected error occurred.");
        let group = groups
            .get_mut(group_id)
            .ok_or(ClientError::NoMatchingGroup)?;
        // Get the signature public key to read the signer from the
        // key store.
        let signature_pk = group.own_leaf().unwrap().signature_key();
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            signature_pk.as_slice(),
            group.ciphersuite().signature_algorithm(),
        )
        .unwrap();
        let action_results = match action_type {
            ActionType::Commit => {
                let (message, welcome_option, group_info) =
                    group.remove_members(&self.provider, &signer, targets)?;
                (
                    vec![message],
                    welcome_option.map(|w| w.into_welcome().expect("Unexpected message type.")),
                    group_info,
                )
            }
            ActionType::Proposal => {
                let mut messages = Vec::new();
                for target in targets {
                    let message = group
                        .propose_remove_member(&self.provider, &signer, *target)
                        .map(|(out, _)| out)?;
                    messages.push(message);
                }
                (messages, None, None)
            }
        };
        Ok(action_results)
    }

    /// Get the identity of this client in the given group.
    pub fn identity(&self, group_id: &GroupId) -> Option<Vec<u8>> {
        let groups = self.groups.read().unwrap();
        let group = groups.get(group_id).unwrap();
        let leaf = group.own_leaf();
        leaf.map(|l| {
            let credential = BasicCredential::try_from(l.credential().clone()).unwrap();
            credential.identity().to_vec()
        })
    }
}
