use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{credentials::CredentialType, messages::proposals::ProposalType};

use super::{Deserialize, ExtensionType, Serialize};

/// # Required Capabilities Extension.
///
/// The configuration of a group imposes certain requirements on clients in the
/// group.  At a minimum, all members of the group need to support the ciphersuite
/// and protocol version in use.  Additional requirements can be imposed by
/// including a required capabilities extension in the `GroupContext`.
///
/// This extension lists the extensions and proposal types that must be supported by
/// all members of the group.  For new members, it is enforced by existing members during the
/// application of Add commits.  Existing members should of course be in compliance
/// already.  In order to ensure this continues to be the case even as the group's
/// extensions can be updated, a GroupContextExtensions proposal is invalid if it
/// contains a required capabilities extension that requires capabilities not
/// supported by all current members.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     ExtensionType extension_types<V>;
///     ProposalType proposal_types<V>;
///     CredentialType credential_types<V>;
/// } RequiredCapabilities;
/// ```
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Default,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct RequiredCapabilitiesExtension {
    extension_types: Vec<ExtensionType>,
    proposal_types: Vec<ProposalType>,
    credential_types: Vec<CredentialType>,
}

impl RequiredCapabilitiesExtension {
    /// Creates a new [`RequiredCapabilitiesExtension`] from extension and proposal types.
    pub fn new(
        extension_types: &[ExtensionType],
        proposal_types: &[ProposalType],
        credential_types: &[CredentialType],
    ) -> Self {
        Self {
            extension_types: extension_types.into(),
            proposal_types: proposal_types.into(),
            credential_types: credential_types.into(),
        }
    }

    /// Get a slice with the required extension types.
    pub fn extension_types(&self) -> &[ExtensionType] {
        self.extension_types.as_slice()
    }

    /// Get a slice with the required proposal types.
    pub fn proposal_types(&self) -> &[ProposalType] {
        self.proposal_types.as_slice()
    }

    /// Get a slice with the required credential types.
    pub fn credential_types(&self) -> &[CredentialType] {
        self.credential_types.as_slice()
    }

    /// Checks whether support for the provided extension type is required.
    pub(crate) fn requires_extension_type_support(&self, ext_type: ExtensionType) -> bool {
        self.extension_types.contains(&ext_type)
    }
}
