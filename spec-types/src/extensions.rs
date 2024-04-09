use serde::{Deserialize, Serialize};

use crate::credential::{Credential, CredentialType};
use crate::hpke::HpkePublicKey;
use crate::keys::SignaturePublicKey;
use crate::proposals::ProposalType;
use crate::tree::RatchetTree;

use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Extension {
    /// Returns the [`ExtensionType`]
    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::ApplicationId(_) => ExtensionType::ApplicationId,
            Extension::RatchetTree(_) => ExtensionType::RatchetTree,
            Extension::RequiredCapabilities(_) => ExtensionType::RequiredCapabilities,
            Extension::ExternalPub(_) => ExtensionType::ExternalPub,
            Extension::ExternalSenders(_) => ExtensionType::ExternalSenders,
            Extension::LastResort(_) => ExtensionType::LastResort,
            Extension::Unknown(kind, _) => ExtensionType::Unknown(*kind),
        }
    }
}

/// A unknown/unparsed extension represented by raw bytes.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct UnknownExtension(pub Vec<u8>);

/// A list of extensions with extension types. When well-formed, the list does not contain more
/// than one extension of the same type.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize)]
pub struct Extensions {
    pub unique: Vec<Extension>,
}

/// # Application Identifiers
///
/// Within MLS, a KeyPackage is identified by its hash ([`KeyPackageRef`](`crate::ciphersuite::hash_ref::KeyPackageRef`)).
/// The application id extension allows applications to add an explicit,
/// application-defined identifier to a KeyPackage.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct ApplicationIdExtension {
    pub key_id: VLBytes,
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
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct RatchetTreeExtension {
    pub ratchet_tree: RatchetTree,
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
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Default,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct RequiredCapabilitiesExtension {
    pub extension_types: Vec<ExtensionType>,
    pub proposal_types: Vec<ProposalType>,
    pub credential_types: Vec<CredentialType>,
}

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     HPKEPublicKey external_pub;
/// } ExternalPub;
/// ```
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct ExternalPubExtension {
    pub external_pub: HpkePublicKey,
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
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct ExternalSender {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

/// ExternalSender (extension data)
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// ExternalSender external_senders<V>;
/// ```
pub type ExternalSendersExtension = Vec<ExternalSender>;

/// ```c
/// // draft-ietf-mls-extensions-03
/// struct {} LastResort;
/// ```
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Default,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct LastResortExtension {}

#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct SenderExtensionIndex(pub u32);

mod codec {
    use super::*;

    use std::io::{Read, Write};
    use tls_codec::{Deserialize, DeserializeBytes, Error, Serialize, Size};

    impl Size for ExtensionType {
        fn tls_serialized_len(&self) -> usize {
            2
        }
    }

    impl Deserialize for ExtensionType {
        fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
        where
            Self: Sized,
        {
            let mut extension_type = [0u8; 2];
            bytes.read_exact(&mut extension_type)?;

            Ok(ExtensionType::from(u16::from_be_bytes(extension_type)))
        }
    }

    impl DeserializeBytes for ExtensionType {
        fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
        where
            Self: Sized,
        {
            let mut bytes_ref = bytes;
            let extension_type = ExtensionType::tls_deserialize(&mut bytes_ref)?;
            let remainder = &bytes[extension_type.tls_serialized_len()..];
            Ok((extension_type, remainder))
        }
    }

    impl Serialize for ExtensionType {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
            writer.write_all(&u16::from(*self).to_be_bytes())?;

            Ok(2)
        }
    }

    fn vlbytes_len_len(length: usize) -> usize {
        if length < 0x40 {
            1
        } else if length < 0x3fff {
            2
        } else if length < 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    impl Size for Extension {
        #[inline]
        fn tls_serialized_len(&self) -> usize {
            let extension_type_length = 2;

            // We truncate here and don't catch errors for anything that's
            // too long.
            // This will be caught when (de)serializing.
            let extension_data_len = match self {
                Extension::ApplicationId(e) => e.tls_serialized_len(),
                Extension::RatchetTree(e) => e.tls_serialized_len(),
                Extension::RequiredCapabilities(e) => e.tls_serialized_len(),
                Extension::ExternalPub(e) => e.tls_serialized_len(),
                Extension::ExternalSenders(e) => e.tls_serialized_len(),
                Extension::LastResort(e) => e.tls_serialized_len(),
                Extension::Unknown(_, e) => e.0.len(),
            };

            let vlbytes_len_len = vlbytes_len_len(extension_data_len);

            extension_type_length + vlbytes_len_len + extension_data_len
        }
    }

    impl Size for &Extension {
        #[inline]
        fn tls_serialized_len(&self) -> usize {
            Extension::tls_serialized_len(*self)
        }
    }

    impl Serialize for Extension {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
            // First write the extension type.
            let written = self.extension_type().tls_serialize(writer)?;

            // Now serialize the extension into a separate byte vector.
            let extension_data_len = self.tls_serialized_len();
            let mut extension_data = Vec::with_capacity(extension_data_len);

            let extension_data_written = match self {
                Extension::ApplicationId(e) => e.tls_serialize(&mut extension_data),
                Extension::RatchetTree(e) => e.tls_serialize(&mut extension_data),
                Extension::RequiredCapabilities(e) => e.tls_serialize(&mut extension_data),
                Extension::ExternalPub(e) => e.tls_serialize(&mut extension_data),
                Extension::ExternalSenders(e) => e.tls_serialize(&mut extension_data),
                Extension::LastResort(e) => e.tls_serialize(&mut extension_data),
                Extension::Unknown(_, e) => extension_data
                    .write_all(e.0.as_slice())
                    .map(|_| e.0.len())
                    .map_err(|_| tls_codec::Error::EndOfStream),
            }?;
            debug_assert_eq!(
                extension_data_written,
                extension_data_len - 2 - vlbytes_len_len(extension_data_written)
            );
            debug_assert_eq!(extension_data_written, extension_data.len());

            // Write the serialized extension out.
            extension_data.tls_serialize(writer).map(|l| l + written)
        }
    }

    impl Serialize for &Extension {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
            Extension::tls_serialize(*self, writer)
        }
    }

    impl Deserialize for Extension {
        fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
            // Read the extension type and extension data.
            let extension_type = ExtensionType::tls_deserialize(bytes)?;
            let extension_data = VLBytes::tls_deserialize(bytes)?;

            // Now deserialize the extension itself from the extension data.
            let mut extension_data = extension_data.as_slice();
            Ok(match extension_type {
                ExtensionType::ApplicationId => Extension::ApplicationId(
                    ApplicationIdExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::RatchetTree => Extension::RatchetTree(
                    RatchetTreeExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::RequiredCapabilities => Extension::RequiredCapabilities(
                    RequiredCapabilitiesExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::ExternalPub => Extension::ExternalPub(
                    ExternalPubExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::ExternalSenders => Extension::ExternalSenders(
                    ExternalSendersExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::LastResort => Extension::LastResort(
                    LastResortExtension::tls_deserialize(&mut extension_data)?,
                ),
                ExtensionType::Unknown(unknown) => {
                    Extension::Unknown(unknown, UnknownExtension(extension_data.to_vec()))
                }
            })
        }
    }

    impl DeserializeBytes for Extension {
        fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
        where
            Self: Sized,
        {
            let mut bytes_ref = bytes;
            let extension = Extension::tls_deserialize(&mut bytes_ref)?;
            let remainder = &bytes[extension.tls_serialized_len()..];
            Ok((extension, remainder))
        }
    }

    impl Serialize for Extensions {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
            self.unique.tls_serialize(writer)
        }
    }

    impl Deserialize for Extensions {
        fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
        where
            Self: Sized,
        {
            let candidate: Vec<Extension> = Vec::tls_deserialize(bytes)?;
            Ok(Extensions { unique: candidate })
        }
    }

    impl DeserializeBytes for Extensions {
        fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
        where
            Self: Sized,
        {
            let mut bytes_ref = bytes;
            let extensions = Extensions::tls_deserialize(&mut bytes_ref)?;
            let remainder = &bytes[extensions.tls_serialized_len()..];
            Ok((extensions, remainder))
        }
    }
}
