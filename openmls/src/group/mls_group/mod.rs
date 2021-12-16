//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

use log::{debug, trace};
use psk::PskSecret;

mod apply_proposals;
pub mod create_commit;
pub mod create_commit_params;
mod new_from_welcome;
pub mod past_secrets;
pub mod process;
pub mod proposals;
pub mod staged_commit;
#[cfg(test)]
mod test_create_commit_params;
#[cfg(test)]
mod test_duplicate_extension;
#[cfg(test)]
mod test_mls_group;
#[cfg(test)]
mod test_past_secrets;
#[cfg(test)]
mod test_proposals;
pub mod validation;

use crate::ciphersuite::signable::{Signable, Verifiable};
use crate::config::{check_required_capabilities_support, Config};
use crate::credentials::{Credential, CredentialBundle, CredentialError};
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::public_group_state::{PublicGroupState, PublicGroupStateTbs};
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::treesync::node::Node;
use crate::treesync::*;
use crate::{ciphersuite::*, config::ProtocolVersion};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io::{Error, Read, Write};

use tls_codec::Serialize as TlsSerializeTrait;

use super::errors::{
    ExporterError, FramingValidationError, MlsGroupError, ProposalValidationError,
};

pub type CreateCommitResult =
    Result<(MlsPlaintext, Option<Welcome>, Option<KeyPackageBundle>), MlsGroupError>;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MlsGroup {
    ciphersuite: &'static Ciphersuite,
    group_context: GroupContext,
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    tree: TreeSync,
    interim_transcript_hash: Vec<u8>,
    // Group config.
    // Set to true if the ratchet tree extension is added to the `GroupInfo`.
    // Defaults to `false`.
    use_ratchet_tree_extension: bool,
    // The MLS protocol version used in this group.
    mls_version: ProtocolVersion,
}

implement_persistence!(
    MlsGroup,
    group_context,
    group_epoch_secrets,
    message_secrets,
    tree,
    interim_transcript_hash,
    use_ratchet_tree_extension,
    mls_version
);

/// Builder for [`MlsGroup`].
pub struct MlsGroupBuilder {
    key_package_bundle: KeyPackageBundle,
    group_id: GroupId,
    config: Option<MlsGroupConfig>,
    psk_ids: Vec<PreSharedKeyId>,
    version: Option<ProtocolVersion>,
    required_capabilities: Option<RequiredCapabilitiesExtension>,
}

impl MlsGroupBuilder {
    /// Create a new [`MlsGroupBuilder`].
    pub fn new(group_id: GroupId, key_package_bundle: KeyPackageBundle) -> Self {
        Self {
            key_package_bundle,
            group_id,
            config: None,
            psk_ids: vec![],
            version: None,
            required_capabilities: None,
        }
    }
    /// Set the [`MlsGroupConfig`] of the [`MlsGroup`].
    pub fn with_config(mut self, config: MlsGroupConfig) -> Self {
        self.config = Some(config);
        self
    }
    /// Set the [`Vec<PreSharedKeyId>`] of the [`MlsGroup`].
    pub fn with_psk(mut self, psk_ids: Vec<PreSharedKeyId>) -> Self {
        self.psk_ids = psk_ids;
        self
    }
    /// Set the [`ProtocolVersion`] of the [`MlsGroup`].
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = Some(version);
        self
    }
    /// Set the [`RequiredCapabilitiesExtension`] of the [`MlsGroup`].
    pub fn with_required_capabilities(
        mut self,
        required_capabilities: RequiredCapabilitiesExtension,
    ) -> Self {
        self.required_capabilities = Some(required_capabilities);
        self
    }

    /// Build the [`MlsGroup`].
    /// Any values that haven't been set in the builder are set to their default
    /// values (which might be random).
    ///
    /// This function performs cryptographic operations and there requires an
    /// [`OpenMlsCryptoProvider`].
    pub fn build(self, backend: &impl OpenMlsCryptoProvider) -> Result<MlsGroup, MlsGroupError> {
        let ciphersuite = self.key_package_bundle.key_package().ciphersuite();
        let config = self.config.unwrap_or_default();
        let required_capabilities = self.required_capabilities.unwrap_or_default();
        let version = self.version.unwrap_or_default();

        debug!("Created group {:x?}", self.group_id);
        trace!(" >>> with {:?}, {:?}", ciphersuite, config);
        let (tree, commit_secret) = TreeSync::new(backend, self.key_package_bundle)?;

        check_required_capabilities_support(&required_capabilities)?;
        let required_capabilities = &[Extension::RequiredCapabilities(required_capabilities)];

        let group_context = GroupContext::create_initial_group_context(
            ciphersuite,
            self.group_id,
            tree.tree_hash().to_vec(),
            required_capabilities,
        )?;
        // Derive an initial joiner secret based on the commit secret.
        // Derive an epoch secret from the joiner secret.
        // We use a random `InitSecret` for initialization.
        let joiner_secret = JoinerSecret::new(
            backend,
            commit_secret,
            &InitSecret::random(ciphersuite, backend, version)?,
        )?;

        let serialized_group_context = group_context.tls_serialize_detached()?;

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(ciphersuite, backend, &self.psk_ids)?;

        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;
        key_schedule.add_context(backend, &serialized_group_context)?;

        let epoch_secrets = key_schedule.epoch_secrets(backend, true)?;

        let (group_epoch_secrets, message_secrets) =
            epoch_secrets.split_secrets(serialized_group_context, 1u32);

        let interim_transcript_hash = vec![];

        Ok(MlsGroup {
            ciphersuite,
            group_context,
            group_epoch_secrets,
            message_secrets,
            tree,
            interim_transcript_hash,
            use_ratchet_tree_extension: config.add_ratchet_tree_extension,
            mls_version: version,
        })
    }
}

/// Public [`MlsGroup`] functions.
impl MlsGroup {
    /// Get a builder for [`MlsGroup`].
    pub fn builder(group_id: GroupId, key_package_bundle: KeyPackageBundle) -> MlsGroupBuilder {
        MlsGroupBuilder::new(group_id, key_package_bundle)
    }

    // Join a group from a welcome message
    pub fn new_from_welcome(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        kpb: KeyPackageBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, MlsGroupError> {
        Ok(Self::new_from_welcome_internal(
            welcome,
            nodes_option,
            kpb,
            backend,
        )?)
    }

    // === Create handshake messages ===
    // TODO: share functionality between these.

    // 11.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    pub fn create_add_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        joiner_key_package: KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        joiner_key_package.validate_required_capabilities(self.required_capabilities())?;
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        MlsPlaintext::member_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.2. Update
    // struct {
    //     KeyPackage key_package;
    // } Update;
    pub fn create_update_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        key_package: KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let update_proposal = UpdateProposal { key_package };
        let proposal = Proposal::Update(update_proposal);
        MlsPlaintext::member_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.3. Remove
    // struct {
    //     uint32 removed;
    // } Remove;
    pub fn create_remove_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        removed_index: LeafIndex,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let remove_proposal = RemoveProposal {
            removed: removed_index,
        };
        let proposal = Proposal::Remove(remove_proposal);
        MlsPlaintext::member_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.4. PreSharedKey
    // struct {
    //     PreSharedKeyID psk;
    // } PreSharedKey;
    pub fn create_presharedkey_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        psk: PreSharedKeyId,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let presharedkey_proposal = PreSharedKeyProposal::new(psk);
        let proposal = Proposal::PreSharedKey(presharedkey_proposal);
        MlsPlaintext::member_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    /// Create a `GroupContextExtensions` proposal.
    pub fn create_group_context_ext_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        extensions: &[Extension],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        // Ensure that the group supports all the extensions that are wanted.
        let required_extension = extensions
            .iter()
            .find(|extension| extension.extension_type() == ExtensionType::RequiredCapabilities);
        if let Some(required_extension) = required_extension {
            let required_capabilities = required_extension.as_required_capabilities_extension()?;
            // Ensure we support all the capabilities.
            check_required_capabilities_support(required_capabilities)?;
            self.treesync()
                .own_leaf_node()?
                .key_package()
                .validate_required_capabilities(required_capabilities)?;
            // Ensure that all other key packages support all the required
            // extensions as well.
            for (_index, key_package) in self.treesync().full_leaves()? {
                key_package.check_extension_support(required_capabilities.extensions())?;
            }
        }
        let proposal = GroupContextExtensionProposal::new(extensions);
        let proposal = Proposal::GroupContextExtensions(proposal);
        MlsPlaintext::member_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // Create application message
    pub fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        credential_bundle: &CredentialBundle,
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsCiphertext, MlsGroupError> {
        let mls_plaintext = MlsPlaintext::new_application(
            self.sender_index(),
            aad,
            msg,
            credential_bundle,
            self.context(),
            self.message_secrets().membership_key(),
            backend,
        )?;
        self.encrypt(mls_plaintext, padding_size, backend)
    }

    // Encrypt an MlsPlaintext into an MlsCiphertext
    pub fn encrypt(
        &mut self,
        mls_plaintext: MlsPlaintext,
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsCiphertext, MlsGroupError> {
        log::trace!("{:?}", mls_plaintext.confirmation_tag());
        MlsCiphertext::try_from_plaintext(
            &mls_plaintext,
            self.ciphersuite,
            backend,
            MlsMessageHeader {
                group_id: self.group_id().clone(),
                epoch: self.context().epoch(),
                sender: self.sender_index(),
            },
            self.message_secrets_mut(),
            padding_size,
        )
        .map_err(MlsGroupError::MlsCiphertextError)
    }

    /// Decrypt an MlsCiphertext into an MlsPlaintext
    pub fn decrypt(
        &mut self,
        mls_ciphertext: &MlsCiphertext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<VerifiableMlsPlaintext, MlsGroupError> {
        Ok(mls_ciphertext.to_plaintext(self.ciphersuite(), backend, &mut self.message_secrets)?)
    }

    /// Set the context of the [`VerifiableMlsPlaintext`] (if it has not been
    /// set already), verify it and return the [`MlsPlaintext`].
    pub fn verify(
        &self,
        mut verifiable: VerifiableMlsPlaintext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        // Verify the signature on the plaintext.
        let tree = self.treesync();

        let leaf_node = tree
            .leaf(verifiable.sender_index())
            // It's an unknown sender either if the index is outside of the tree
            // ...
            .map_err(|_| MlsPlaintextError::UnknownSender)?
            // ... or if the leaf is blank.
            .ok_or(MlsPlaintextError::UnknownSender)?;
        let credential = leaf_node.key_package().credential();
        // Set the context if it has not been set already.
        if !verifiable.has_context() {
            verifiable.set_context(self.context().tls_serialize_detached()?);
        }

        // TODO: what about the tags?
        verifiable
            .verify(backend, credential)
            .map_err(|e| MlsPlaintextError::from(e).into())
    }

    /// Set the context of the `UnverifiedMlsPlaintext` and verify its
    /// membership tag.
    pub fn verify_membership_tag(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        verifiable_mls_plaintext: &mut VerifiableMlsPlaintext,
    ) -> Result<(), MlsGroupError> {
        verifiable_mls_plaintext.set_context(self.context().tls_serialize_detached()?);
        Ok(verifiable_mls_plaintext
            .verify_membership(backend, self.message_secrets().membership_key())?)
    }

    /// Exporter
    pub fn export_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, MlsGroupError> {
        if key_length > u16::MAX.into() {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExporterError::KeyLengthTooLong.into());
        }
        Ok(self
            .group_epoch_secrets
            .exporter_secret()
            .derive_exported_secret(self.ciphersuite(), backend, label, context, key_length)?)
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.group_epoch_secrets().authentication_secret().export()
    }

    /// Loads the state from persisted state
    pub fn load<R: Read>(reader: R) -> Result<MlsGroup, Error> {
        serde_json::from_reader(reader).map_err(|e| e.into())
    }

    /// Persists the state
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let serialized_mls_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_mls_group.into_bytes())
    }

    /// Returns the ratchet tree
    pub fn treesync(&self) -> &TreeSync {
        &self.tree
    }

    /// Get the ciphersuite implementation used in this group.
    pub fn ciphersuite(&self) -> &'static Ciphersuite {
        self.ciphersuite
    }

    /// Get the group context
    pub fn context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        &self.group_context.group_id
    }

    /// Get the members of the group, indexed by their leaves.
    pub fn members(&self) -> Result<BTreeMap<LeafIndex, &Credential>, MlsGroupError> {
        Ok(self
            .tree
            .full_leaves()?
            .into_iter()
            .map(|(index, kp)| (index, kp.credential()))
            .collect())
    }

    /// Get the groups extensions.
    /// Right now this is limited to the ratchet tree extension which is built
    /// on the fly when calling this function.
    pub fn other_extensions(&self) -> Vec<Extension> {
        vec![Extension::RatchetTree(RatchetTreeExtension::new(
            self.treesync().export_nodes(),
        ))]
    }

    /// Get the group context extensions.
    pub fn group_context_extensions(&self) -> &[Extension] {
        self.group_context.extensions()
    }

    /// Get the required capabilities extension of this group.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.group_context.required_capabilities()
    }

    /// Export the `PublicGroupState`
    pub fn export_public_group_state(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
    ) -> Result<PublicGroupState, CredentialError> {
        let pgs_tbs = PublicGroupStateTbs::new(backend, self)?;
        pgs_tbs.sign(backend, credential_bundle)
    }

    /// Returns `true` if the group uses the ratchet tree extension anf `false
    /// otherwise
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
    }
}

// Private and crate functions
impl MlsGroup {
    pub(crate) fn sender_index(&self) -> LeafIndex {
        self.tree.own_leaf_index()
    }

    /// Get a reference to the group epoch secrets from the group
    pub(crate) fn group_epoch_secrets(&self) -> &GroupEpochSecrets {
        &self.group_epoch_secrets
    }

    /// Get a reference to the message secrets from a group
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets
    }

    /// Get a mutable reference to the message secrets from a group
    pub(crate) fn message_secrets_mut(&mut self) -> &mut MessageSecrets {
        &mut self.message_secrets
    }

    /// Current interim transcript hash of the group
    pub(crate) fn interim_transcript_hash(&self) -> &[u8] {
        &self.interim_transcript_hash
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}

// Helper functions

pub(crate) fn update_confirmed_transcript_hash(
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    mls_plaintext_commit_content: &MlsPlaintextCommitContent,
    interim_transcript_hash: &[u8],
) -> Result<Vec<u8>, MlsGroupError> {
    let commit_content_bytes = mls_plaintext_commit_content.tls_serialize_detached()?;
    Ok(ciphersuite.hash(
        backend,
        &[interim_transcript_hash, &commit_content_bytes].concat(),
    )?)
}

pub(crate) fn update_interim_transcript_hash(
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    mls_plaintext_commit_auth_data: &MlsPlaintextCommitAuthData,
    confirmed_transcript_hash: &[u8],
) -> Result<Vec<u8>, InterimTranscriptHashError> {
    let commit_auth_data_bytes = mls_plaintext_commit_auth_data.tls_serialize_detached()?;
    Ok(ciphersuite.hash(
        backend,
        &[confirmed_transcript_hash, &commit_auth_data_bytes].concat(),
    )?)
}
