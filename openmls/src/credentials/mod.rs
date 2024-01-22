//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) as well as each client (leaf node)
//! in the group (tree) contains a [`Credential`] and is authenticated.
//! The [`Credential`] must the be checked by an authentication server and the
//! application, which is out of scope of MLS.
//!
//! Clients can create a [`Credential`].
//!
//! The MLS protocol spec allows the [`Credential`] that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`LeafNode`](crate::treesync::LeafNode), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key corresponding to the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

#[cfg(test)]
mod tests;

use crate::ciphersuite::SignaturePublicKey;

// Public
pub mod errors;

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
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic,
    /// An X.509 [`Certificate`]
    X509,
    /// A currently unknown credential.
    Unknown(u16),
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
            unknown => CredentialType::Unknown(unknown),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::Unknown(unknown) => unknown,
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
/// type. The [`CredentialType`] always matches the [`MlsCredentialType`].
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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Credential {
    serialized_credential: VLBytes,
}

impl tls_codec::Size for Credential {
    fn tls_serialized_len(&self) -> usize {
        self.serialized_credential.as_ref().len()
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(self.serialized_credential.as_slice());
        Ok(self.serialized_credential.as_ref().len())
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        Ok(Self {
            serialized_credential: VLBytes::tls_deserialize(bytes)?,
        })
    }
}

impl tls_codec::DeserializeBytes for Credential {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (serialized_credential, remainder) = VLBytes::tls_deserialize_bytes(bytes)?;
        Ok((
            Self {
                serialized_credential,
            },
            remainder,
        ))
    }
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> Result<CredentialType, Error> {
        CredentialType::tls_deserialize_bytes(self.serialized_credential.as_slice())
            .map(|(ct, _)| ct)
    }

    /// Creates and returns a new [`Credential`] of the given
    /// the serialized credential.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(serialized_credential: Vec<u8>) -> Self {
        Self {
            serialized_credential: serialized_credential.into(),
        }
    }

    /// Get this serialized credential.
    pub fn serialized_credential(&self) -> &[u8] {
        self.serialized_credential.as_slice()
    }
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct BasicCredential {
    identity: VLBytes,
}

/// An internal type for (de)serialization of a basic credential as [`Credential`].
#[derive(TlsSerialize, TlsSize)]
struct MlsBasicCredential {
    credential_type: CredentialType,
    identity: VLBytes,
}

impl BasicCredential {
    /// Create a new basic credential as a [`Credential`].
    pub fn new_credential(identity: Vec<u8>) -> Credential {
        let cred = MlsBasicCredential {
            credential_type: CredentialType::Basic,
            identity: identity.into(),
        };
        Credential {
            // This can't error, because we know the struct above will always serialize
            serialized_credential: cred.tls_serialize_detached().unwrap().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A wrapper around a credential with a corresponding public key.
pub struct CredentialWithKey {
    /// The [`Credential`].
    pub credential: Credential,
    /// The corresponding public key as [`SignaturePublicKey`].
    pub signature_key: SignaturePublicKey,
}

#[cfg(test)]
impl CredentialWithKey {
    pub fn from_parts(credential: Credential, key: &[u8]) -> Self {
        Self {
            credential,
            signature_key: key.into(),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::{types::SignatureScheme, OpenMlsProvider};

    use super::{BasicCredential, CredentialWithKey};

    /// Convenience function that generates a new credential and a key pair for
    /// it (using the basic credential crate).
    /// The signature keys are stored in the key store.
    ///
    /// Returns the [`Credential`] and the [`SignatureKeyPair`].
    pub fn new_credential(
        provider: &impl OpenMlsProvider,
        identity: &[u8],
        signature_scheme: SignatureScheme,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new_credential(identity.into());
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.key_store()).unwrap();

        (
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }
}
