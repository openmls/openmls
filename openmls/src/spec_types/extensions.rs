use tls_codec::VLBytes;

use super::credential::{Credential, CredentialType};
use super::hpke::HpkePublicKey;
use super::keys::SignaturePublicKey;
use super::proposals::ProposalType;
use super::tree::RatchetTree;

/// MLS Extension Types
///
/// Copied from draft-ietf-mls-protocol-16:
///
/// | Value            | Name                     | Message(s) | Recommended | Reference |
/// |:-----------------|:-------------------------|:-----------|:------------|:----------|
/// | 0x0000           | RESERVED                 | N/A        | N/A         | RFC XXXX  |
/// | 0x0001           | application_id           | LN         | Y           | RFC XXXX  |
/// | 0x0002           | ratchet_tree             | GI         | Y           | RFC XXXX  |
/// | 0x0003           | required_capabilities    | GC         | Y           | RFC XXXX  |
/// | 0x0004           | external_pub             | GI         | Y           | RFC XXXX  |
/// | 0x0005           | external_senders         | GC         | Y           | RFC XXXX  |
/// | 0xff00  - 0xffff | Reserved for Private Use | N/A        | N/A         | RFC XXXX  |
///
/// Note: OpenMLS does not provide a `Reserved` variant in [ExtensionType].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ExtensionType {
    /// The application id extension allows applications to add an explicit,
    /// application-defined identifier to a KeyPackage.
    ApplicationId,

    /// The ratchet tree extensions provides the whole public state of the
    /// ratchet tree.
    RatchetTree,

    /// The required capabilities extension defines the configuration of a group
    /// that imposes certain requirements on clients in the group.
    RequiredCapabilities,

    /// To join a group via an External Commit, a new member needs a GroupInfo
    /// with an ExternalPub extension present in its extensions field.
    ExternalPub,

    /// Group context extension that contains the credentials and signature keys
    /// of senders that are permitted to send external proposals to the group.
    ExternalSenders,

    /// KeyPackage extension that marks a KeyPackage for use in a last resort
    /// scenario.
    LastResort,

    /// A currently unknown extension type.
    Unknown(u16),
}

impl From<u16> for ExtensionType {
    fn from(a: u16) -> Self {
        match a {
            1 => ExtensionType::ApplicationId,
            2 => ExtensionType::RatchetTree,
            3 => ExtensionType::RequiredCapabilities,
            4 => ExtensionType::ExternalPub,
            5 => ExtensionType::ExternalSenders,
            10 => ExtensionType::LastResort,
            unknown => ExtensionType::Unknown(unknown),
        }
    }
}

impl From<ExtensionType> for u16 {
    fn from(value: ExtensionType) -> Self {
        match value {
            ExtensionType::ApplicationId => 1,
            ExtensionType::RatchetTree => 2,
            ExtensionType::RequiredCapabilities => 3,
            ExtensionType::ExternalPub => 4,
            ExtensionType::ExternalSenders => 5,
            ExtensionType::LastResort => 10,
            ExtensionType::Unknown(unknown) => unknown,
        }
    }
}

/// # Extension
///
/// An extension is one of the [`Extension`] enum values.
/// The enum provides a set of common functionality for all extensions.
///
/// See the individual extensions for more details on each extension.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<V>;
/// } Extension;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// An [`ApplicationIdExtension`]
    ApplicationId(ApplicationIdExtension),

    /// A [`RatchetTreeExtension`]
    RatchetTree(RatchetTreeExtension),

    /// A [`RequiredCapabilitiesExtension`]
    RequiredCapabilities(RequiredCapabilitiesExtension),

    /// An [`ExternalPubExtension`]
    ExternalPub(ExternalPubExtension),

    /// An [`ExternalSendersExtension`]
    ExternalSenders(ExternalSendersExtension),

    /// A [`LastResortExtension`]
    LastResort(LastResortExtension),

    /// A currently unknown extension.
    Unknown(u16, UnknownExtension),
}

/// A unknown/unparsed extension represented by raw bytes.
// TODO: should this be VLBytes instead of Vec<u8>?
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UnknownExtension(pub(super) Vec<u8>);

/// A list of extensions with unique extension types.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Extensions {
    pub(super) unique: Vec<Extension>,
}

/// # Application Identifiers
///
/// Within MLS, a KeyPackage is identified by its hash ([`KeyPackageRef`](`crate::ciphersuite::hash_ref::KeyPackageRef`)).
/// The application id extension allows applications to add an explicit,
/// application-defined identifier to a KeyPackage.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ApplicationIdExtension {
    pub(super) key_id: VLBytes,
}

/// # Ratchet Tree Extension.
///
/// The ratchet tree extension contains a list of (optional) [`Node`](crate::treesync::node::Node)s that
/// represent the public state of the tree in an MLS group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// optional<Node> ratchet_tree<V>;
/// ```
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RatchetTreeExtension {
    pub(super) ratchet_tree: RatchetTree,
}

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
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct RequiredCapabilitiesExtension {
    pub(super) extension_types: Vec<ExtensionType>,
    pub(super) proposal_types: Vec<ProposalType>,
    pub(super) credential_types: Vec<CredentialType>,
}

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     HPKEPublicKey external_pub;
/// } ExternalPub;
/// ```
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ExternalPubExtension {
    pub(super) external_pub: HpkePublicKey,
}

/// ExternalSender
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   SignaturePublicKey signature_key;
///   Credential credential;
/// } ExternalSender;
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExternalSender {
    pub(super) signature_key: SignaturePublicKey,
    pub(super) credential: Credential,
}

/// ExternalSender (extension data)
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// ExternalSender external_senders<V>;
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExternalSendersExtension(pub(super) Vec<ExternalSender>);

/// ```c
/// // draft-ietf-mls-extensions-03
/// struct {} LastResort;
/// ```
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct LastResortExtension {}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SenderExtensionIndex(pub(super) u32);
