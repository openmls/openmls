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

use openmls_traits::types::SignatureScheme;
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsDeserialize, TlsSerialize, TlsSize, VLBytes,
};

#[cfg(test)]
mod tests;

use crate::{ciphersuite::SignaturePublicKey, prelude::Lifetime};
use errors::*;

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
    /// Proprietary credential used in the Infra protocol.
    Infra,
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
            0xF000 => CredentialType::Infra,
            other => CredentialType::Other(other),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::Infra => 0xF000,
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

/// A credential that contains a (pseudonymous) identity, some metadata, as well
/// as an encrypted signature.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize, TlsDeserialize,
)]
pub struct InfraCredential {
    // (Pseudonymous) identity
    identity: Vec<u8>,
    expiration_data: Lifetime,
    credential_ciphersuite: SignatureScheme,
    verifying_key: SignaturePublicKey,
    encrypted_signature: VLBytes,
}

impl InfraCredential {
    /// Create a new [`InfraCredential`].
    pub fn new(
        identity: Vec<u8>,
        expiration_data: Lifetime,
        credential_ciphersuite: SignatureScheme,
        verifying_key: SignaturePublicKey,
        encrypted_signature: VLBytes,
    ) -> Self {
        Self {
            identity,
            expiration_data,
            credential_ciphersuite,
            verifying_key,
            encrypted_signature,
        }
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        self.identity.as_ref()
    }

    /// Returns the expiration data of a given credential.
    pub fn expiration_data(&self) -> Lifetime {
        self.expiration_data
    }

    /// Returns the credential ciphersuite of a given credential.
    pub fn credential_ciphersuite(&self) -> SignatureScheme {
        self.credential_ciphersuite
    }

    /// Returns the verifying key of a given credential.
    pub fn verifying_key(&self) -> &SignaturePublicKey {
        &self.verifying_key
    }

    /// Returns the encrypted signature of a given credential.
    pub fn encrypted_signature(&self) -> &VLBytes {
        &self.encrypted_signature
    }
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`]
    X509(Certificate),
    /// Proprietary credential used in the Infra protocol.
    Infra(InfraCredential),
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
        // their structure. While we don't care, we still need to parse it
        // in order to move the reader forward and read the values in the struct
        // after this credential.

        // The credential type is important, so we read that.
        let credential_type = CredentialType::tls_deserialize(bytes)?;

        // Now we don't know what we get unfortunately.
        // We assume that it is a variable-sized vector. This works for the
        // currently specified credentials and any other credential MUST be
        // encoded in a vector as well. Otherwise OpenMLS may fail later on
        // or exhibit unexpected behaviour.
        let (length, _) = tls_codec::vlen::read_length(bytes)?;
        let mut actual_credential_content = vec![0u8; length];
        bytes.read_exact(&mut actual_credential_content)?;

        // Rebuild the credential again.
        let mut serialized_credential = Vec::new();
        tls_codec::vlen::write_length(&mut serialized_credential, length)?;
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

impl From<InfraCredential> for Credential {
    fn from(value: InfraCredential) -> Self {
        Self {
            credential_type: CredentialType::Infra,
            serialized_credential_content: value.tls_serialize_detached().unwrap().into(),
        }
    }
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Creates and returns a new [`Credential`] of the given
    /// [`CredentialType`].
    pub fn new(credential_type: CredentialType, serialized_credential: Vec<u8>) -> Self {
        Self {
            credential_type,
            serialized_credential_content: serialized_credential.into(),
        }
    }

    /// Get this serialized credential content.
    ///
    /// This is the content of the `select` statement. It is a TLS serialized
    /// vector.
    pub fn serialized_content(&self) -> &[u8] {
        self.serialized_credential_content.as_slice()
    }

    /// Get the credential, deserialized.
    pub fn deserialized<T: tls_codec::Size + tls_codec::Deserialize>(
        &self,
    ) -> Result<T, tls_codec::Error> {
        T::tls_deserialize_exact(&self.serialized_credential_content)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicCredential {
    header: Vec<u8>,
    identity: Vec<u8>,
}

impl BasicCredential {
    /// Create a new basic credential.
    ///
    /// Errors
    ///
    /// Returns a [`BasicCredentialError`] if the length of the identity is too
    /// large to be encoded as a variable-length vector.
    pub fn new(identity: Vec<u8>) -> Result<Self, BasicCredentialError> {
        let mut header = Vec::new();
        tls_codec::vlen::write_length(&mut header, identity.len())?;
        Ok(Self { header, identity })
    }

    /// Get the identity of this basic credential as byte slice.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}

impl From<BasicCredential> for Credential {
    fn from(mut credential: BasicCredential) -> Self {
        let mut serialized_credential_content = credential.header;
        serialized_credential_content.append(&mut credential.identity);
        Credential {
            serialized_credential_content: serialized_credential_content.into(),
            credential_type: CredentialType::Basic,
        }
    }
}

impl TryFrom<&Credential> for BasicCredential {
    type Error = BasicCredentialError;

    fn try_from(credential: &Credential) -> Result<Self, Self::Error> {
        match credential.credential_type() {
            CredentialType::Basic => {
                let identity: VLBytes = credential.deserialized().unwrap();
                Ok(BasicCredential::new(identity.into())?)
            }
            _ => Err(errors::BasicCredentialError::WrongCredentialType),
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
    ///
    /// [`Credential`]: super::Credential
    pub fn new_credential(
        provider: &impl OpenMlsProvider,
        identity: &[u8],
        signature_scheme: SignatureScheme,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new(identity.into()).unwrap();
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.key_store()).unwrap();

        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }
}

#[cfg(test)]
mod unit_tests {
    use tls_codec::{DeserializeBytes, Serialize};

    use super::{BasicCredential, Credential};

    #[test]
    fn basic_credential_identity_and_codec() {
        const IDENTITY: &str = "identity";
        // Test the identity getter.
        let basic_credential = BasicCredential::new(IDENTITY.into()).unwrap();
        assert_eq!(basic_credential.identity(), IDENTITY.as_bytes());

        // Test the encoding and decoding.
        let credential = Credential::from(basic_credential.clone());
        let serialized = credential.tls_serialize_detached().unwrap();

        let deserialized = Credential::tls_deserialize_exact_bytes(&serialized).unwrap();
        assert_eq!(credential.credential_type(), deserialized.credential_type());
        assert_eq!(
            credential.serialized_content(),
            deserialized.serialized_content()
        );

        let deserialized_basic_credential = BasicCredential::try_from(&deserialized).unwrap();
        assert_eq!(
            deserialized_basic_credential.identity(),
            IDENTITY.as_bytes()
        );
        assert_eq!(basic_credential, deserialized_basic_credential);
    }
}
