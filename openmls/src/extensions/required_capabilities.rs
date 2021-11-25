//! ## Required Capabilities
//!
//! The configuration of a group imposes certain requirements on clients in the
//! group.  At a minimum, all members of the group need to support the ciphersuite
//! and protocol version in use.  Additional requirements can be imposed by
//! including a `required_capabilities` extension in the GroupContext.
//!
//! ```text
//! struct {
//!     ExtensionType extensions<0..255>;
//!     ProposalType proposals<0..255>;
//! } RequiredCapabilities;
//! ```
//!
//! This extension lists the extensions and proposal types that must be supported by
//! all members of the group.  For new members, it is enforced by existing members during the
//! application of Add commits.  Existing members should of course be in compliance
//! already.  In order to ensure this continues to be the case even as the group's
//! extensions can be updated, a GroupContextExtensions proposal is invalid if it
//! contains a `required_capabilities` extension that requires capabililities not
//! supported by all current members.

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU8};

use crate::messages::proposals::ProposalType;

use super::{Deserialize, ExtensionType, Serialize};

#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct RequiredCapabilitiesExtension {
    extensions: TlsVecU8<ExtensionType>,
    proposals: TlsVecU8<ProposalType>,
}

impl RequiredCapabilitiesExtension {
    pub fn new(extensions: &[ExtensionType], proposals: &[ProposalType]) -> Self {
        Self {
            extensions: extensions.into(),
            proposals: proposals.into(),
        }
    }
}
