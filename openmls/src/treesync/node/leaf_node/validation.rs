use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    ciphersuite::SignaturePublicKey,
    credentials::CredentialType,
    extensions::{Extension, RequiredCapabilitiesExtension},
    treesync::{
        errors::{LeafNodeValidationError, LifetimeError},
        node::{
            encryption_keys::EncryptionKey,
            leaf_node::{LeafNodeSource, OpenMlsLeafNode},
        },
        LeafNode,
    },
};

/// The leaf node was not validated yet.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsDeserialize)]
pub struct Unknown;

/// The leaf node was validated in the context of a key package.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize)]
pub struct ValidKeyPackage;

/// The leaf node was validated in the context of an add, update, or commit.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize)]
pub struct ValidUpdate;

/// The leaf node was validated in the context of a commit's update path.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize)]
pub struct ValidCommit;

/// The leaf node was validated in the context of a ratchet tree.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize)]
pub struct ValidRatchetTree;

/// The leaf node was either a `ValidKeyPackage`, `ValidAddUpdateCommit`, or
/// `ValidRatchetTree` and can be used generically now.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize)]
pub struct Valid;

impl LeafNode<Unknown> {
    // ----- Typestate transitions -----------------------------------------------------------------

    /// Validate the leaf node in the context of a key package.
    #[allow(unused)]
    pub(crate) fn validate_in_key_package<'a>(
        self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
        signature_keys: &[SignaturePublicKey],
        encryption_keys: &[EncryptionKey],
        members_supported_credentials: &[&[CredentialType]],
        currently_in_use: &[CredentialType],
    ) -> Result<LeafNode<ValidKeyPackage>, LeafNodeValidationError> {
        self.validate(
            required_capabilities,
            signature_keys,
            encryption_keys,
            members_supported_credentials,
            currently_in_use,
        )?;

        match self.payload.leaf_node_source {
            LeafNodeSource::KeyPackage(lifetime) => {
                // Check that lifetime range is acceptable.
                if !lifetime.has_acceptable_range() {
                    return Err(LeafNodeValidationError::Lifetime(
                        LifetimeError::RangeTooBig,
                    ));
                }

                // Check that current time is between `Lifetime.not_before` and `Lifetime.not_after`.
                if !lifetime.is_valid() {
                    return Err(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent));
                }

                Ok(LeafNode::<ValidKeyPackage> {
                    payload: self.payload,
                    signature: self.signature,
                    phantom: Default::default(),
                })
            }
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    /// Validate the leaf node in the context of an update.
    #[allow(unused)]
    pub(crate) fn validate_in_update<'a>(
        self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
        signature_keys: &[SignaturePublicKey],
        encryption_keys: &[EncryptionKey],
        members_supported_credentials: &[&[CredentialType]],
        currently_in_use: &[CredentialType],
    ) -> Result<LeafNode<ValidUpdate>, LeafNodeValidationError> {
        self.validate(
            required_capabilities,
            signature_keys,
            encryption_keys,
            members_supported_credentials,
            currently_in_use,
        )?;

        match self.payload.leaf_node_source {
            LeafNodeSource::Update => Ok(LeafNode {
                payload: self.payload,
                signature: self.signature,
                phantom: Default::default(),
            }),
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    /// Validate the leaf node in the context of an update.
    #[allow(unused)]
    pub(crate) fn validate_in_commit<'a>(
        self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
        signature_keys: &[SignaturePublicKey],
        encryption_keys: &[EncryptionKey],
        members_supported_credentials: &[&[CredentialType]],
        currently_in_use: &[CredentialType],
    ) -> Result<LeafNode<ValidCommit>, LeafNodeValidationError> {
        self.validate(
            required_capabilities,
            signature_keys,
            encryption_keys,
            members_supported_credentials,
            currently_in_use,
        )?;

        match self.payload.leaf_node_source {
            LeafNodeSource::Commit(_) => Ok(LeafNode {
                payload: self.payload,
                signature: self.signature,
                phantom: Default::default(),
            }),
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    // ----- Validation methods ------------------------------------------------------------------

    /// Basic validation of leaf node called in all `validate_in_*` methods.
    #[allow(unused)]
    fn validate<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
        signature_keys: &[SignaturePublicKey],
        encryption_keys: &[EncryptionKey],
        members_supported_credentials: &[&[CredentialType]],
        currently_in_use: &[CredentialType],
    ) -> Result<&Self, LeafNodeValidationError> {
        self.validate_required_capabilities(required_capabilities)?
            .validate_that_capabilities_contain_extension_types()?
            .validate_that_capabilities_contain_credential_type()?
            .validate_that_signature_key_is_unique(signature_keys)?
            .validate_that_encryption_key_is_unique(encryption_keys)?
            .validate_against_group_credentials(members_supported_credentials)?
            .validate_credential_in_use(currently_in_use)?;

        Ok(self)
    }

    /// Check that all extensions are listed in capabilities.
    fn validate_that_capabilities_contain_extension_types(
        &self,
    ) -> Result<&Self, LeafNodeValidationError> {
        for id in self
            .payload
            .extensions
            .iter()
            .map(Extension::extension_type)
        {
            if !self.supports_extension(&id) {
                return Err(LeafNodeValidationError::ExtensionsNotInCapabilities);
            }
        }

        Ok(self)
    }

    /// Check that credential type is included in the credentials.
    fn validate_that_capabilities_contain_credential_type(
        &self,
    ) -> Result<&Self, LeafNodeValidationError> {
        if !self
            .payload
            .capabilities
            .credentials
            .contains(&self.payload.credential.credential_type())
        {
            return Err(LeafNodeValidationError::CredentialNotInCapabilities);
        }

        Ok(self)
    }

    /// Validate that the signature key is unique among the members of the group.
    fn validate_that_signature_key_is_unique(
        &self,
        signature_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        if signature_keys.contains(self.signature_key()) {
            return Err(LeafNodeValidationError::SignatureKeyAlreadyInUse);
        }

        Ok(self)
    }

    /// Validate that the encryption key is unique among the members of the group.
    fn validate_that_encryption_key_is_unique(
        &self,
        encryption_keys: &[EncryptionKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        if encryption_keys.contains(self.encryption_key()) {
            return Err(LeafNodeValidationError::EncryptionKeyAlreadyInUse);
        }

        Ok(self)
    }

    /// Verify that the credential type is supported by all members of the group, as
    /// specified by the capabilities field of each member's LeafNode.
    fn validate_against_group_credentials(
        &self,
        members_supported_credentials: &[&[CredentialType]],
    ) -> Result<&Self, LeafNodeValidationError> {
        for member_supported_credentials in members_supported_credentials {
            if !member_supported_credentials.contains(&self.credential().credential_type()) {
                return Err(LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember);
            }
        }

        Ok(self)
    }

    /// Verify that the capabilities field of this LeafNode indicates support for all the
    /// credential types currently in use by other members.
    fn validate_credential_in_use(
        &self,
        currently_in_use: &[CredentialType],
    ) -> Result<&Self, LeafNodeValidationError> {
        for credential in currently_in_use {
            if !self.payload.capabilities.credentials.contains(credential) {
                return Err(LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode);
            }
        }

        Ok(self)
    }
}

// ----- Conversions -------------------------------------------------------------------------------

// LeafNode -> LeafNode

impl From<LeafNode<ValidKeyPackage>> for LeafNode<Valid> {
    fn from(value: LeafNode<ValidKeyPackage>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

impl From<LeafNode<ValidUpdate>> for LeafNode<Valid> {
    fn from(value: LeafNode<ValidUpdate>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

impl From<LeafNode<ValidCommit>> for LeafNode<Valid> {
    fn from(value: LeafNode<ValidCommit>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

// "Invalidate"

impl From<LeafNode<Valid>> for LeafNode<ValidKeyPackage> {
    fn from(value: LeafNode<Valid>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

impl From<LeafNode<Valid>> for LeafNode<ValidUpdate> {
    fn from(value: LeafNode<Valid>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

// impl From<LeafNode<Valid>> for LeafNode<ValidCommit> {
//     fn from(value: LeafNode<Valid>) -> Self {
//         LeafNode {
//             payload: value.payload,
//             signature: value.signature,
//             phantom: Default::default(),
//         }
//     }
// }

impl From<LeafNode<Valid>> for LeafNode<Unknown> {
    fn from(value: LeafNode<Valid>) -> Self {
        LeafNode {
            payload: value.payload,
            signature: value.signature,
            phantom: Default::default(),
        }
    }
}

// LeafNode -> OpenMlsLeafNode

impl From<LeafNode<ValidKeyPackage>> for OpenMlsLeafNode {
    fn from(leaf_node: LeafNode<ValidKeyPackage>) -> Self {
        Self {
            leaf_node: leaf_node.into(),
            leaf_index: None,
        }
    }
}

impl From<LeafNode<ValidUpdate>> for OpenMlsLeafNode {
    fn from(leaf_node: LeafNode<ValidUpdate>) -> Self {
        Self {
            leaf_node: leaf_node.into(),
            leaf_index: None,
        }
    }
}

impl From<LeafNode<ValidCommit>> for OpenMlsLeafNode {
    fn from(leaf_node: LeafNode<ValidCommit>) -> Self {
        Self {
            leaf_node: leaf_node.into(),
            leaf_index: None,
        }
    }
}

impl From<LeafNode<Valid>> for OpenMlsLeafNode {
    fn from(leaf_node: LeafNode<Valid>) -> Self {
        Self {
            leaf_node,
            leaf_index: None,
        }
    }
}

// OpenMlsLeafNode -> LeafNode

impl From<OpenMlsLeafNode> for LeafNode<Valid> {
    fn from(value: OpenMlsLeafNode) -> Self {
        value.leaf_node
    }
}

impl From<OpenMlsLeafNode> for LeafNode<ValidKeyPackage> {
    fn from(value: OpenMlsLeafNode) -> Self {
        LeafNode {
            payload: value.leaf_node.payload,
            signature: value.leaf_node.signature,
            phantom: Default::default(),
        }
    }
}

impl From<OpenMlsLeafNode> for LeafNode<ValidUpdate> {
    fn from(value: OpenMlsLeafNode) -> Self {
        LeafNode {
            payload: value.leaf_node.payload,
            signature: value.leaf_node.signature,
            phantom: Default::default(),
        }
    }
}

impl From<OpenMlsLeafNode> for LeafNode<ValidCommit> {
    fn from(value: OpenMlsLeafNode) -> Self {
        LeafNode {
            payload: value.leaf_node.payload,
            signature: value.leaf_node.signature,
            phantom: Default::default(),
        }
    }
}

impl<T> LeafNode<T> {
    /// Check that all required capabilities are supported by this leaf node.
    // TODO: Implement this for `LeafNode<Unknown>` only.
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<&Self, LeafNodeValidationError> {
        // If the GroupContext has a required_capabilities extension, ...
        if let Some(required_capabilities) = required_capabilities.into() {
            // ... then the required extensions, ...
            for required_extension in required_capabilities.extension_types() {
                if !self.supports_extension(required_extension) {
                    return Err(LeafNodeValidationError::UnsupportedExtensions);
                }
            }

            // ... proposals, ...
            for required_proposal in required_capabilities.proposal_types() {
                if !self.supports_proposal(required_proposal) {
                    return Err(LeafNodeValidationError::UnsupportedProposals);
                }
            }

            // ... and credential types MUST be listed in the LeafNode's capabilities field.
            for required_credential in required_capabilities.credential_types() {
                if !self.supports_credential(required_credential) {
                    return Err(LeafNodeValidationError::UnsupportedCredentials);
                }
            }
        }

        Ok(self)
    }
}

// TODO: Only use this in tests.
impl<T> LeafNode<T> {
    /// Convert a `LeafNode<T>` to `LeafNode<ValidKeyPackage>` without doing any validation.
    /// Note: Do not use this method when possible.
    pub(crate) fn to_key_package_unchecked(self) -> LeafNode<ValidKeyPackage> {
        LeafNode {
            payload: self.payload,
            signature: self.signature,
            phantom: Default::default(),
        }
    }

    /// Convert a `LeafNode<T>` to `LeafNode<ValidUpdate>` without doing any validation.
    /// Note: Do not use this method when possible.
    pub(crate) fn to_update_unchecked(self) -> LeafNode<ValidUpdate> {
        LeafNode {
            payload: self.payload,
            signature: self.signature,
            phantom: Default::default(),
        }
    }

    /// Convert a `LeafNode<T>` to `LeafNode<ValidCommit>` without doing any validation.
    /// Note: Do not use this method when possible.
    pub(crate) fn to_commit_unchecked(self) -> LeafNode<ValidCommit> {
        LeafNode {
            payload: self.payload,
            signature: self.signature,
            phantom: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::marker::PhantomData;
    use crate::treesync::node::leaf_node::ValidCommit;
    use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

    #[test]
    fn that_not_everything_can_be_deserialized() {
        #[derive(
        Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize,
        )]
        struct Test<T> {
            phantom: PhantomData<T>,
        }

        let mut bytes = b"asd".as_slice();
        let valid: Test<ValidCommit> = tls_codec::Deserialize::tls_deserialize(&mut bytes).unwrap();
    }
}