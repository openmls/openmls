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

use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

#[cfg(test)]
mod tests;

use crate::{ciphersuite::SignaturePublicKey, group::Member, treesync::LeafNode};
use errors::*;

#[cfg(doc)]
use crate::group::MlsGroup;

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
    /// A GREASE credential type for ensuring extensibility.
    Grease(u16),
    /// Another type of credential that is not in the MLS protocol spec.
    Other(u16),
}

impl CredentialType {
    /// Returns true if this is a GREASE credential type.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// credential types. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    pub fn is_grease(&self) -> bool {
        matches!(self, CredentialType::Grease(_))
    }
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
            other if crate::grease::is_grease_value(other) => CredentialType::Grease(other),
            other => CredentialType::Other(other),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::Grease(value) => value,
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
    identity: VLBytes,
}

impl BasicCredential {
    /// Create a new basic credential.
    ///
    /// Errors
    ///
    /// Returns a [`BasicCredentialError`] if the length of the identity is too
    /// large to be encoded as a variable-length vector.
    pub fn new(identity: Vec<u8>) -> Self {
        Self {
            identity: identity.into(),
        }
    }

    /// Get the identity of this basic credential as byte slice.
    pub fn identity(&self) -> &[u8] {
        self.identity.as_slice()
    }
}

impl From<BasicCredential> for Credential {
    fn from(credential: BasicCredential) -> Self {
        Credential {
            credential_type: CredentialType::Basic,
            serialized_credential_content: credential.identity,
        }
    }
}

impl TryFrom<Credential> for BasicCredential {
    type Error = BasicCredentialError;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        match credential.credential_type {
            CredentialType::Basic => Ok(BasicCredential::new(
                credential.serialized_credential_content.into(),
            )),
            _ => Err(errors::BasicCredentialError::WrongCredentialType),
        }
    }
}

/// Bundle consisting of a [`Signer`] and a [`CredentialWithKey`] to be used to
/// update the signature key in an [`MlsGroup`]. The public key and credential
/// in `credential_with_key` MUST match the signature key exposed by `signer`.
#[derive(Debug, Clone)]
pub struct NewSignerBundle<'a, S: Signer> {
    /// The signer to be used with the group after the update.
    pub signer: &'a S,
    /// The credential and public key corresponding to the `signer`.
    pub credential_with_key: CredentialWithKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A wrapper around a credential with a corresponding public key.
pub struct CredentialWithKey {
    /// The [`Credential`].
    pub credential: Credential,
    /// The corresponding public key as [`SignaturePublicKey`].
    pub signature_key: SignaturePublicKey,
}

impl From<&LeafNode> for CredentialWithKey {
    fn from(leaf_node: &LeafNode) -> Self {
        Self {
            credential: leaf_node.credential().clone(),
            signature_key: leaf_node.signature_key().clone(),
        }
    }
}

impl From<&Member> for CredentialWithKey {
    fn from(member: &Member) -> Self {
        Self {
            credential: member.credential.clone(),
            signature_key: member.signature_key.clone().into(),
        }
    }
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
        let credential = BasicCredential::new(identity.into());
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.storage()).unwrap();

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
    use tls_codec::{
        DeserializeBytes, Serialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
    };

    use super::{BasicCredential, Credential, CredentialType};

    #[test]
    fn basic_credential_identity_and_codec() {
        const IDENTITY: &str = "identity";
        // Test the identity getter.
        let basic_credential = BasicCredential::new(IDENTITY.into());
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

        let deserialized_basic_credential = BasicCredential::try_from(deserialized).unwrap();
        assert_eq!(
            deserialized_basic_credential.identity(),
            IDENTITY.as_bytes()
        );
        assert_eq!(basic_credential, deserialized_basic_credential);
    }

    /// Test the [`Credential`] with a custom credential.
    #[test]
    fn custom_credential() {
        #[derive(
            Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize, TlsDeserializeBytes,
        )]
        struct CustomCredential {
            custom_field1: u32,
            custom_field2: Vec<u8>,
            custom_field3: Option<u8>,
        }

        let custom_credential = CustomCredential {
            custom_field1: 42,
            custom_field2: vec![1, 2, 3],
            custom_field3: Some(2),
        };

        let credential = Credential::new(
            CredentialType::Other(1234),
            custom_credential.tls_serialize_detached().unwrap(),
        );

        let serialized = credential.tls_serialize_detached().unwrap();
        let deserialized = Credential::tls_deserialize_exact_bytes(&serialized).unwrap();
        assert_eq!(credential, deserialized);

        let deserialized_custom_credential =
            CustomCredential::tls_deserialize_exact_bytes(deserialized.serialized_content())
                .unwrap();

        assert_eq!(custom_credential, deserialized_custom_credential);
    }
}
