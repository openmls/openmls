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
#[repr(u16)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`Certificate`]
    X509 = 2,
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
    credential_type: CredentialType,
    serialized_credential_content: VLBytes,
}

impl tls_codec::Size for Credential {
    fn tls_serialized_len(&self) -> usize {
        CredentialType::tls_serialized_len(&CredentialType::Basic)
            + self.serialized_credential_content.as_ref().len()
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.credential_type.tls_serialize(writer)?;
        writer.write_all(self.serialized_credential_content.as_slice())?;
        Ok(self.tls_serialized_len())
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        // We can not deserialize arbitrary credentials because we don't know
        // the structure of it. While we don't care, we still need to parse it
        // in order to move the reader forward and read the values in the struct
        // after this credential.

        // The credential type is important, so we read that.
        let credential_type = CredentialType::tls_deserialize(bytes)?;

        // Now we don't know what we get unfortunately.
        // We assume that it is a variable-sized vector. This works for the
        // currently specified credentials and any other credential MUST be
        // encoded in a vector as well. Otherwise this implementation will
        // either crash or exhibit unexpected behaviour.
        let (length, _) = tls_codec::read_variable_length(bytes)?;
        let mut actual_credential_content = vec![0u8; length];
        bytes.read_exact(&mut actual_credential_content)?;

        // Rebuild the credential again.
        let mut serialized_credential = tls_codec::write_length(length)?;
        serialized_credential.append(&mut actual_credential_content);

        Ok(Self {
            serialized_credential_content: serialized_credential.into(),
            credential_type,
        })
    }
}

impl tls_codec::DeserializeBytes for Credential {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let mut bytes_ref = bytes;
        let secret = Self::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[secret.tls_serialized_len()..];
        Ok((secret, remainder))
    }
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Creates and returns a new [`Credential`] of the given
    /// the serialized credential.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(serialized_credential: Vec<u8>) -> Self {
        Self {
            serialized_credential_content: serialized_credential.into(),
            credential_type: CredentialType::Basic,
        }
    }

    /// Get this serialized credential content.
    ///
    /// This is the content of the `select` statement. It is a TLS serialized
    /// vector.
    pub fn serialized_content(&self) -> &[u8] {
        self.serialized_credential_content.as_slice()
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
    credential: Credential,
}

/// An internal type for (de)serialization of a basic credential as [`Credential`].
#[derive(TlsSerialize, TlsSize)]
struct MlsBasicCredential {
    identity: VLBytes,
}

impl BasicCredential {
    /// Create a new basic credential as a [`Credential`].
    pub fn new_credential(identity: Vec<u8>) -> Credential {
        let cred = MlsBasicCredential {
            identity: identity.into(),
        };
        Credential {
            // This can't error, because we know the struct above will always serialize
            serialized_credential_content: cred.tls_serialize_detached().unwrap().into(),
            credential_type: CredentialType::Basic,
        }
    }

    /// Get the identity of this basic credential as byte slice.
    pub fn identity(&self) -> &[u8] {
        self.credential.serialized_content()
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

#[cfg(test)]
mod unit_tests {
    use tls_codec::{Deserialize, DeserializeBytes, Serialize, VLBytes};

    use super::{BasicCredential, Credential};

    #[test]
    fn basic_credential_encoding() {
        let credential = BasicCredential::new_credential("identity".into());
        eprintln!("{credential:#?}");
        let serialized = credential.tls_serialize_detached().unwrap();
        eprintln!("{:#?}", VLBytes::from(serialized.clone()));
        let (deserialized, remainder) = Credential::tls_deserialize_bytes(&serialized).unwrap();
        eprintln!("remainder: {remainder:x?}");

        assert_eq!(credential.credential_type(), deserialized.credential_type());
        assert_eq!(
            credential.serialized_content(),
            deserialized.serialized_content()
        );
        let identity = VLBytes::tls_deserialize_exact(credential.serialized_content()).unwrap();
        assert_eq!(identity.as_slice(), b"identity");
    }
}
