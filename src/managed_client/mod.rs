//! A client struct, combining the functionality of `ManagedGroup` and `KeyStore`.
//!
//! Assumptions (for now):
//! - Only one `Credential` per `SignatureScheme`, i.e. no per-group credentials.
//! - The first entry in `supported_ciphersuites` is used as default ciphersuite for new groups.
//!
//! TODO:
//! - Move parts of `Config` into the `ManagedClientConfig`, such as default `KeyPackage` lifetime.
//! - Implement `Copy` trait for GroupId?
//! - Move RwLocked fields into their own structs to better control locking.
//! - Move key package generation into ManagedGroup::new()
//! - Refactor `self_update` to use the KeyStore.
//! - Refactor to use a better strategy regarding interior mutability of the client (and probably for the KeyStore as well)
//!   - We need interior mutability
//!   - We want to be able to obtain locks on groups individually.
//!   - We need a strategy to make group operations available, ideally by handing out group handles.
//!   - Once we have that, we might be able to get rid of the `clone`s, e.g. for resumption secret

use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::RwLock,
};

pub mod errors;
pub mod group_handle;
pub mod groups;

pub use errors::ManagedClientError;
use groups::Groups;

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName, SignatureScheme},
    config::Config,
    credentials::{Credential, CredentialType},
    group::{
        GroupEpoch, GroupId, HandshakeMessageFormat, MLSMessage, ManagedGroup,
        ManagedGroupCallbacks, ManagedGroupConfig, UpdatePolicy,
    },
    key_packages::KeyPackage,
    key_store::KeyStore,
    messages::Welcome,
    node::Node,
    prelude::{KeyPackageBundle, MLSPlaintext},
    schedule::ResumptionSecret,
};

#[derive(Clone)]
pub struct ManagedClientConfig {
    default_managed_group_config: ManagedGroupConfig,
    supported_ciphersuites: Vec<CiphersuiteName>,
    default_credential_type: CredentialType,
}

impl Default for ManagedClientConfig {
    fn default() -> Self {
        let default_managed_group_config = ManagedGroupConfig {
            handshake_message_format: HandshakeMessageFormat::Ciphertext,
            update_policy: UpdatePolicy::default(),
            padding_size: 10,
            number_of_resumption_secrets: 0,
            callbacks: ManagedGroupCallbacks::default(),
        };
        let supported_ciphersuites = Config::supported_ciphersuite_names().to_vec();
        let default_credential_type = CredentialType::Basic;
        ManagedClientConfig {
            default_managed_group_config,
            supported_ciphersuites,
            default_credential_type,
        }
    }
}

impl ManagedClientConfig {
    // TODO: Allow this only for tests and interop testing.
    pub fn default_tests() -> Self {
        let mut config = ManagedClientConfig::default();
        config.default_managed_group_config.handshake_message_format =
            HandshakeMessageFormat::Plaintext;
        config
    }

    pub fn new(
        default_managed_group_config: ManagedGroupConfig,
        supported_ciphersuites: Vec<CiphersuiteName>,
        default_credential_type: CredentialType,
    ) -> Result<Self, ManagedClientError> {
        // Check that at least one ciphersuite is supported.
        if supported_ciphersuites.is_empty() {
            // Fix Error type. This one's for KeyPackage generation.
            return Err(ManagedClientError::NoCiphersuiteProvided);
        }
        Ok(ManagedClientConfig {
            default_managed_group_config,
            supported_ciphersuites,
            default_credential_type,
        })
    }
}

pub struct ManagedClient {
    identity: Vec<u8>,
    key_store: KeyStore,
    groups: Groups,
    credentials: RwLock<HashMap<SignatureScheme, Credential>>,
    managed_client_config: ManagedClientConfig,
}

impl ManagedClient {
    pub fn new(identity: Vec<u8>, managed_client_config: ManagedClientConfig) -> Self {
        ManagedClient {
            identity,
            key_store: KeyStore::default(),
            groups: Groups::default(),
            credentials: RwLock::new(HashMap::new()),
            managed_client_config,
        }
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub fn group_exists(&self, group_id: &GroupId) -> Result<bool, ManagedClientError> {
        self.groups.contains_group(group_id)
    }

    /// Generate a KeyPackage. If no `Credential` matching the ciphersuite is
    /// available in the `KeyStore`, a fresh one is generated. TODO: Pass in
    /// extension(s) or make parameters configurable via ManagedClientConfig.
    pub fn generate_key_package(
        &self,
        ciphersuites: &[CiphersuiteName],
    ) -> Result<KeyPackage, ManagedClientError> {
        // Check if the chosen ciphersuites is supported by the current OpenMLS
        // configuration.
        for ciphersuite in ciphersuites {
            if !Config::supported_ciphersuite_names().contains(&ciphersuite) {
                return Err(ManagedClientError::UnsupportedCiphersuite);
            }
        }
        // Take the input ciphersuite or else the default one.
        let ciphersuite = ciphersuites.first().unwrap_or(
            self.managed_client_config
                .supported_ciphersuites
                .first()
                .unwrap(),
        );
        let signature_scheme = SignatureScheme::from(*ciphersuite);
        // Take an existing credential from the KeyStore or else generate one.
        let mut credentials = self
            .credentials
            .write()
            .map_err(|_| ManagedClientError::PoisonError)?;
        let credential =
            credentials
                .entry(signature_scheme)
                .or_insert(self.key_store.generate_credential(
                    self.identity.clone(),
                    self.managed_client_config.default_credential_type,
                    signature_scheme,
                )?);
        let key_package =
            self.key_store
                .generate_key_package(&[*ciphersuite], &credential, Vec::new())?;
        Ok(key_package)
    }

    /// Create a new group. If a `ManagedGroupConfig` and/or a `CiphersuiteName`
    /// are given, they are used in the creation of the group. Otherwise the
    /// defaults are used. If no `Credential` matching the ciphersuite is
    /// available in the `KeyStore`, a fresh one is generated.
    pub fn create_group(
        &self,
        group_id: GroupId,
        managed_group_config_option: Option<&ManagedGroupConfig>,
        ciphersuite_option: Option<CiphersuiteName>,
    ) -> Result<(), ManagedClientError> {
        if self.groups.contains_group(&group_id)? {
            return Err(ManagedClientError::DuplicateGroupId);
        }

        let ciphersuites = match ciphersuite_option {
            Some(ciphersuite) => vec![ciphersuite],
            None => vec![],
        };
        let key_package = self.generate_key_package(&ciphersuites)?;
        // Take the input managed_group_config or else use the default.
        let managed_group_config = managed_group_config_option
            .unwrap_or(&self.managed_client_config.default_managed_group_config);
        let new_group = ManagedGroup::new(
            &self.key_store,
            managed_group_config,
            group_id.clone(),
            &key_package.hash(),
        )?;
        self.groups.insert(group_id, new_group)?;
        Ok(())
    }

    // Functions passed through to ManagedGroup
    pub fn process_welcome(
        &self,
        managed_group_config_option: Option<&ManagedGroupConfig>,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<GroupId, ManagedClientError> {
        // Take the input managed_group_config or else use the default.
        let managed_group_config = managed_group_config_option
            .unwrap_or(&self.managed_client_config.default_managed_group_config);
        let group = ManagedGroup::new_from_welcome(
            &self.key_store,
            managed_group_config,
            welcome,
            ratchet_tree,
        )?;
        let group_id = group.group_id().clone();
        self.groups.insert(group.group_id().clone(), group)?;
        Ok(group_id)
    }

    // === Membership management ===

    /// Adds members to the group
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and a
    /// [`Welcome`](crate::prelude::Welcome) message.
    pub fn add_members(
        &self,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.add_members(&self.key_store, key_packages)?)
    }

    /// Removes members from the group
    ///
    /// Members are removed by providing the index of their leaf in the tree.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and an optional
    /// [`Welcome`](crate::prelude::Welcome) message if there were add proposals
    /// in the queue of pending proposals.
    pub fn remove_members(
        &self,
        group_id: &GroupId,
        members: &[usize],
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.remove_members(&self.key_store, members)?)
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &self,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
    ) -> Result<Vec<MLSMessage>, ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.propose_add_members(&self.key_store, key_packages)?)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &self,
        group_id: &GroupId,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.propose_remove_members(&self.key_store, members)?)
    }

    /// Leave the group
    pub fn leave_group(&self, group_id: &GroupId) -> Result<Vec<MLSMessage>, ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.leave_group(&self.key_store)?)
    }

    /// Gets the current list of members
    pub fn members(&self, group_id: &GroupId) -> Result<Vec<Credential>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.members())
    }

    // === Process messages ===

    /// Processes any incoming messages from the DS (MLSPlaintext &
    /// MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_messages(
        &self,
        group_id: &GroupId,
        messages: Vec<MLSMessage>,
    ) -> Result<(), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.process_messages(messages)?)
    }

    // === Application messages ===

    /// Creates an application message.
    /// Returns `ManagedClientError::UseAfterEviction(UseAfterEviction::Error)`
    /// if the member is no longer part of the group.
    /// Returns `ManagedClientError::PendingProposalsExist` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(
        &self,
        group_id: &GroupId,
        message: &[u8],
    ) -> Result<MLSMessage, ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.create_message(&self.key_store, message)?)
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &self,
        group_id: &GroupId,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.process_pending_proposals(&self.key_store)?)
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.export_secret(label, context, key_length)?)
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self, group_id: &GroupId) -> Result<Vec<u8>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.authentication_secret())
    }

    /// Returns a resumption secret for a given epoch. If no resumption secret
    /// is available `None` is returned.
    pub fn get_resumption_secret<'a>(
        &'a self,
        group_id: &'a GroupId,
        epoch: GroupEpoch,
    ) -> Result<Option<ResumptionSecret>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.get_resumption_secret(epoch).map(|rs| rs.clone()))
    }

    // === Configuration ===

    /// Gets the configuration
    pub fn configuration<'a>(
        &'a self,
        group_id: &'a GroupId,
    ) -> Result<ManagedGroupConfig, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.configuration().clone())
    }

    /// Sets the configuration
    pub fn set_configuration(
        &self,
        group_id: &GroupId,
        managed_group_config: &ManagedGroupConfig,
    ) -> Result<(), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.set_configuration(managed_group_config))
    }

    /// Gets the AAD used in the framing
    pub fn aad<'a>(&'a self, group_id: &'a GroupId) -> Result<Vec<u8>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.aad().to_vec())
    }

    /// Sets the AAD used in the framing
    pub fn set_aad(&self, group_id: &GroupId, aad: &[u8]) -> Result<(), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.set_aad(aad))
    }

    // === Advanced functions ===

    /// Returns the group's ciphersuite
    pub fn ciphersuite<'a>(
        &'a self,
        group_id: &'a GroupId,
    ) -> Result<Ciphersuite, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.ciphersuite().clone())
    }

    /// Returns whether the own client is still a member of the group or if it
    /// was already evicted
    pub fn is_active(&self, group_id: &GroupId) -> Result<bool, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.is_active())
    }

    /// Returns own credential. If the group is inactive, it returns a
    /// `UseAfterEviction` error.
    pub fn credential(&self, group_id: &GroupId) -> Result<Credential, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.credential()?)
    }

    /// Updates the own leaf node
    ///
    /// A [`KeyPackageBundle`](crate::prelude::KeyPackageBundle) can optionally
    /// be provided. If not, a new one will be created on the fly.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and an optional
    /// [`Welcome`](crate::prelude::Welcome) message if there were add proposals
    /// in the queue of pending proposals.
    pub fn self_update(
        &self,
        group_id: &GroupId,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.self_update(&self.key_store, key_package_bundle_option)?)
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &self,
        group_id: &GroupId,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<Vec<MLSMessage>, ManagedClientError> {
        let mut group = self.groups.get_mut(group_id)?;
        Ok(group.propose_self_update(&self.key_store, key_package_bundle_option)?)
    }

    /// Returns a list of proposal
    pub fn pending_proposals<'a>(
        &'a self,
        group_id: &'a GroupId,
    ) -> Result<Vec<MLSPlaintext>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.pending_proposals().to_vec())
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load<R: Read>(
        &self,
        reader: R,
        callbacks: &ManagedGroupCallbacks,
    ) -> Result<(), ManagedClientError> {
        let group =
            ManagedGroup::load(reader, callbacks).map_err(|_| ManagedClientError::ReadError)?;
        self.groups.insert(group.group_id().clone(), group)?;
        Ok(())
    }

    /// Persists the state
    pub fn save<W: Write>(
        &self,
        group_id: &GroupId,
        writer: &mut W,
    ) -> Result<(), ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group
            .save(writer)
            .map_err(|_| ManagedClientError::WriteError)?)
    }

    // === Extensions ===

    /// Export the Ratchet Tree
    pub fn export_ratchet_tree(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<Option<Node>>, ManagedClientError> {
        let group = self.groups.get(group_id)?;
        Ok(group.export_ratchet_tree())
    }
}
