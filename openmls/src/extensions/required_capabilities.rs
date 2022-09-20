use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU8};

use crate::messages::proposals::ProposalType;

use super::{Deserialize, ExtensionError, ExtensionType, Serialize};

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
    TlsSize,
)]
pub struct RequiredCapabilitiesExtension {
    extensions: TlsVecU8<ExtensionType>,
    proposals: TlsVecU8<ProposalType>,
}

impl RequiredCapabilitiesExtension {
    /// Creates a new [`RequiredCapabilitiesExtension`] from extension and proposal types.
    pub fn new(extensions: &[ExtensionType], proposals: &[ProposalType]) -> Self {
        Self {
            extensions: extensions.into(),
            proposals: proposals.into(),
        }
    }

    /// Get a slice with the required extension types.
    pub(crate) fn extensions(&self) -> &[ExtensionType] {
        self.extensions.as_slice()
    }

    /// Get a slice with the required proposal types.
    pub(crate) fn proposals(&self) -> &[ProposalType] {
        self.proposals.as_slice()
    }

    /// Check if all extension and proposal types are supported.
    pub(crate) fn check_support(&self) -> Result<(), ExtensionError> {
        for extension in self.extensions() {
            if !extension.is_supported() {
                return Err(ExtensionError::UnsupportedExtensionType);
            }
        }
        for proposal in self.proposals() {
            if !proposal.is_supported() {
                return Err(ExtensionError::UnsupportedProposalType);
            }
        }
        Ok(())
    }
}
