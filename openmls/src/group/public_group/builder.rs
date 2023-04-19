use openmls_traits::{credential::OpenMlsCredential, signatures::Signer, OpenMlsCryptoProvider};

use crate::{
    error::LibraryError,
    extensions::{
        errors::ExtensionError, Extension, Extensions, ExternalSendersExtension,
        RequiredCapabilitiesExtension,
    },
    group::{config::CryptoConfig, GroupContext, GroupId},
    messages::ConfirmationTag,
    schedule::CommitSecret,
    treesync::{
        node::{
            encryption_keys::EncryptionKeyPair,
            leaf_node::{Capabilities, Lifetime},
        },
        TreeSync,
    },
};

use super::{errors::PublicGroupBuildError, PublicGroup};

pub(crate) struct TempBuilderPG1 {
    group_id: GroupId,
    crypto_config: CryptoConfig,
    lifetime: Option<Lifetime>,
    required_capabilities: Option<RequiredCapabilitiesExtension>,
    external_senders: Option<ExternalSendersExtension>,
    leaf_extensions: Option<Extensions>,
}

impl TempBuilderPG1 {
    pub(crate) fn with_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    pub(crate) fn with_required_capabilities(
        mut self,
        required_capabilities: RequiredCapabilitiesExtension,
    ) -> Self {
        self.required_capabilities = Some(required_capabilities);
        self
    }

    pub(crate) fn with_external_senders(
        mut self,
        external_senders: ExternalSendersExtension,
    ) -> Self {
        if !external_senders.is_empty() {
            self.external_senders = Some(external_senders);
        }
        self
    }

    pub(crate) fn get_secrets(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        credential_with_key: &dyn OpenMlsCredential,
    ) -> Result<(TempBuilderPG2, CommitSecret, EncryptionKeyPair), PublicGroupBuildError> {
        let capabilities = self
            .required_capabilities
            .as_ref()
            .map(|re| re.extension_types());
        let (treesync, commit_secret, leaf_keypair) = TreeSync::new(
            backend,
            signer,
            self.crypto_config,
            credential_with_key,
            self.lifetime.unwrap_or_default(),
            Capabilities::new(
                Some(&[self.crypto_config.version]), // TODO: Allow more versions
                Some(&[self.crypto_config.ciphersuite]), // TODO: allow more ciphersuites
                capabilities,
                None,
                None,
            ),
            self.leaf_extensions.unwrap_or(Extensions::empty()),
        )?;
        let required_capabilities = self.required_capabilities.unwrap_or_default();
        required_capabilities.check_support().map_err(|e| match e {
            ExtensionError::UnsupportedProposalType => {
                PublicGroupBuildError::UnsupportedProposalType
            }
            ExtensionError::UnsupportedExtensionType => {
                PublicGroupBuildError::UnsupportedExtensionType
            }
            _ => LibraryError::custom("Unexpected ExtensionError").into(),
        })?;
        let required_capabilities = Extension::RequiredCapabilities(required_capabilities);
        let extensions =
            if let Some(ext_senders) = self.external_senders.map(Extension::ExternalSenders) {
                vec![required_capabilities, ext_senders]
            } else {
                vec![required_capabilities]
            };
        let group_context = GroupContext::create_initial_group_context(
            self.crypto_config.ciphersuite,
            self.group_id,
            treesync.tree_hash().to_vec(),
            Extensions::from_vec(extensions)?,
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

    pub(crate) fn crypto_config(&self) -> CryptoConfig {
        CryptoConfig {
            ciphersuite: self.group_context.ciphersuite(),
            version: self.group_context.protocol_version(),
        }
    }

    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    pub(crate) fn group_id(&self) -> &GroupId {
        self.group_context.group_id()
    }
}

pub(crate) struct PublicGroupBuilder {
    treesync: TreeSync,
    group_context: GroupContext,
    confirmation_tag: ConfirmationTag,
}

impl PublicGroupBuilder {
    pub(crate) fn build(self) -> PublicGroup {
        PublicGroup::new(self.treesync, self.group_context, self.confirmation_tag)
    }
}

impl PublicGroup {
    /// Create a new [`PublicGroupBuilder`].
    pub(crate) fn builder(group_id: GroupId, crypto_config: CryptoConfig) -> TempBuilderPG1 {
        TempBuilderPG1 {
            group_id,
            crypto_config,
            lifetime: None,
            required_capabilities: None,
            external_senders: None,
            leaf_extensions: None,
        }
    }
}
