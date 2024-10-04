use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::Ciphersuite};

use super::{errors::PublicGroupBuildError, PublicGroup};
use crate::{
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::{errors::InvalidExtensionError, Extensions},
    group::{ExtensionType, GroupContext, GroupId},
    key_packages::Lifetime,
    messages::ConfirmationTag,
    schedule::CommitSecret,
    storage::OpenMlsProvider,
    treesync::{
        node::{encryption_keys::EncryptionKeyPair, leaf_node::Capabilities},
        TreeSync,
    },
    versions::ProtocolVersion,
};

#[derive(Debug)]
pub(crate) struct TempBuilderPG1 {
    group_id: GroupId,
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    lifetime: Option<Lifetime>,
    capabilities: Option<Capabilities>,
    leaf_node_extensions: Extensions,
    group_context_extensions: Extensions,
}

impl TempBuilderPG1 {
    pub(crate) fn with_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    pub(crate) fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub(crate) fn with_group_context_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        let is_valid_in_group_context = extensions.application_id().is_none()
            && extensions.ratchet_tree().is_none()
            && extensions.external_pub().is_none();
        if !is_valid_in_group_context {
            return Err(InvalidExtensionError::IllegalInGroupContext);
        }
        self.group_context_extensions = extensions;
        Ok(self)
    }

    pub(crate) fn with_leaf_node_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        // None of the default extensions are leaf node extensions, so only
        // unknown extensions can be leaf node extensions.
        let is_valid_in_leaf_node = extensions
            .iter()
            .all(|e| matches!(e.extension_type(), ExtensionType::Unknown(_)));
        if !is_valid_in_leaf_node {
            return Err(InvalidExtensionError::IllegalInLeafNodes);
        }
        self.leaf_node_extensions = extensions;
        Ok(self)
    }

    pub(crate) fn get_secrets(
        self,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
    ) -> Result<(TempBuilderPG2, CommitSecret, EncryptionKeyPair), PublicGroupBuildError> {
        // If there are no capabilities, we want to provide a default version
        // plus anything in the required capabilities.
        let (required_extensions, required_proposals, required_credentials) =
            if let Some(required_capabilities) =
                self.group_context_extensions.required_capabilities()
            {
                (
                    Some(required_capabilities.extension_types()),
                    Some(required_capabilities.proposal_types()),
                    Some(required_capabilities.credential_types()),
                )
            } else {
                (None, None, None)
            };
        let capabilities = self.capabilities.unwrap_or(Capabilities::new(
            Some(&[ProtocolVersion::default()]),
            Some(&[self.ciphersuite]),
            required_extensions,
            required_proposals,
            required_credentials,
        ));
        let (treesync, commit_secret, leaf_keypair) = TreeSync::new(
            provider,
            signer,
            self.ciphersuite,
            self.credential_with_key,
            self.lifetime.unwrap_or_default(),
            capabilities,
            self.leaf_node_extensions,
        )?;

        let group_context = GroupContext::create_initial_group_context(
            self.ciphersuite,
            self.group_id,
            treesync.tree_hash().to_vec(),
            self.group_context_extensions,
        );
        let next_builder = TempBuilderPG2 {
            treesync,
            group_context,
        };
        Ok((next_builder, commit_secret, leaf_keypair))
    }
}

pub(crate) struct TempBuilderPG2 {
    treesync: TreeSync,
    group_context: GroupContext,
}

impl TempBuilderPG2 {
    pub(crate) fn with_confirmation_tag(
        self,
        confirmation_tag: ConfirmationTag,
    ) -> PublicGroupBuilder {
        PublicGroupBuilder {
            treesync: self.treesync,
            group_context: self.group_context,
            confirmation_tag,
        }
    }

    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.group_context
    }
}

pub(crate) struct PublicGroupBuilder {
    treesync: TreeSync,
    group_context: GroupContext,
    confirmation_tag: ConfirmationTag,
}

impl PublicGroupBuilder {
    pub(crate) fn build(self, crypto: &impl OpenMlsCrypto) -> Result<PublicGroup, LibraryError> {
        PublicGroup::new(
            crypto,
            self.treesync,
            self.group_context,
            self.confirmation_tag,
        )
    }
}

impl PublicGroup {
    /// Create a new [`PublicGroupBuilder`].
    pub(crate) fn builder(
        group_id: GroupId,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
    ) -> TempBuilderPG1 {
        TempBuilderPG1 {
            group_id,
            ciphersuite,
            credential_with_key,
            lifetime: None,
            capabilities: None,
            leaf_node_extensions: Extensions::empty(),
            group_context_extensions: Extensions::empty(),
        }
    }
}
