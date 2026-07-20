//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it. [`Credential`]s represent clients in MLS groups and are used to
//! authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage), as well as each client
//! (leaf node) in the group (tree), contains a [`Credential`] and is
//! authenticated.
//!
//! The [`Credential`] must be checked by an authentication server and the
//! application. This process is out of scope for MLS.
//!
//! Clients can create a [`Credential`].
//!
//! The MLS protocol allows the [`Credential`] representing a client in a group
//! to change over time. Concretely, members can issue an Update proposal or a
//! Full Commit to update their [`LeafNode`],
//! including the [`Credential`] in it. The Update must be authenticated using
//! the signature public key corresponding to the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure the new credential is valid.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

use crate::ciphersuite::SignaturePublicKey;

#[cfg(doc)]
use crate::group::MlsGroup;

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.
///
/// ```c
/// // See IANA registry for registered values
/// uint16 CredentialType;
/// ```
///
/// **IANA Considerations**
///
/// | Value            | Name                     | R | Ref      |
/// |:-----------------|:-------------------------|:--|:---------|
/// | 0x0000           | RESERVED                 | - | RFC XXXX |
/// | 0x0001           | basic                    | Y | RFC XXXX |
/// | 0x0002           | x509                     | Y | RFC XXXX |
/// | 0x0A0A           | GREASE                   | Y | RFC XXXX |
/// | 0x1A1A           | GREASE                   | Y | RFC XXXX |
/// | 0x2A2A           | GREASE                   | Y | RFC XXXX |
/// | 0x3A3A           | GREASE                   | Y | RFC XXXX |
/// | 0x4A4A           | GREASE                   | Y | RFC XXXX |
/// | 0x5A5A           | GREASE                   | Y | RFC XXXX |
/// | 0x6A6A           | GREASE                   | Y | RFC XXXX |
/// | 0x7A7A           | GREASE                   | Y | RFC XXXX |
/// | 0x8A8A           | GREASE                   | Y | RFC XXXX |
/// | 0x9A9A           | GREASE                   | Y | RFC XXXX |
/// | 0xAAAA           | GREASE                   | Y | RFC XXXX |
/// | 0xBABA           | GREASE                   | Y | RFC XXXX |
/// | 0xCACA           | GREASE                   | Y | RFC XXXX |
/// | 0xDADA           | GREASE                   | Y | RFC XXXX |
/// | 0xEAEA           | GREASE                   | Y | RFC XXXX |
/// | 0xF000  - 0xFFFF | Reserved for Private Use | - | RFC XXXX |
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`Certificate`]
    X509 = 2,
    /// Another type of credential that is not in the MLS protocol spec.
    Other(u16),
}

impl Size for CredentialType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl TlsDeserializeTrait for CredentialType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut extension_type = [0u8; 2];
        bytes.read_exact(&mut extension_type)?;

        Ok(CredentialType::from(u16::from_be_bytes(extension_type)))
    }
}

impl TlsSerializeTrait for CredentialType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl DeserializeBytes for CredentialType {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let credential_type = CredentialType::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[credential_type.tls_serialized_len()..];
        Ok((credential_type, remainder))
    }
}

impl From<u16> for CredentialType {
    fn from(value: u16) -> Self {
        match value {
            1 => CredentialType::Basic,
            2 => CredentialType::X509,
            other => CredentialType::Other(other),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::Other(other) => other,
        }
    }
}

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate chain.  Note that X.509
/// certificates are not yet supported by OpenMLS.
///
/// ```c
/// struct {
///     opaque cert_data<V>;
/// } Certificate;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    cert_data: Vec<u8>,
}

/// Credential.
///
/// OpenMLS does not look into credentials and only passes them along.
/// As such they are opaque to the code in OpenMLS and only the basic necessary
/// checks and operations are done.
///
/// OpenMLS provides an implementation of the [`BasicCredential`].
///
/// This struct contains MLS credential data, where the data depends on the
/// type.
///
/// **Note:** While the credential is opaque to OpenMLS, the library must know how
///           to deserialize it. The implementation only works with credentials
///           that are encoded as variable-sized vectors.
///           Other credentials will cause OpenMLS either to crash or exhibit
///           unexpected behaviour.
///
/// ```c
/// struct {
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case basic:
///             opaque identity<V>;
///
///         case x509:
///             Certificate chain<V>;
///     };
/// } Credential;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
)]
pub struct Credential {
    credential_type: CredentialType,
    serialized_credential_content: VLBytes,
}

/// Basic Credential.
///
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes only an
/// `identity` to represent the client.
///
/// Note that this credential does not contain any key material or any other
/// information.
///
/// OpenMLS provides an implementation of signature keys for convenience in the
/// `openmls_basic_credential` crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicCredential {
    identity: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A wrapper around a credential with a corresponding public key.
pub struct CredentialWithKey {
    /// The [`Credential`].
    pub credential: Credential,
    /// The corresponding public key as [`SignaturePublicKey`].
    pub signature_key: SignaturePublicKey,
}
