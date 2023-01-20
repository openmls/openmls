//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it, as well as a signature public key and the corresponding
//! signature scheme. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) that is either
//! pre-published, or that represents a client in a group contains a
//! [`Credential`] and is authenticated by it.
//!
//! Clients can create a [`Credential`].
//!
//! The MLS protocol spec allows the that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`KeyPackage`](crate::key_packages::KeyPackage), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key contained in the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! Credentials are specific to a signature scheme, which has to match the
//! ciphersuite of the [`KeyPackage`](crate::key_packages::KeyPackage) that it
//! is embedded in. Clients can use different credentials, potentially with
//! different signature schemes in different groups.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].
// TODO[FK]: update all the comments here.

use openmls_traits::{types::SignatureScheme, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

// Private
mod codec;
#[cfg(test)]
mod tests;
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
/// | Value            | Name                     | Recommended | Reference |
/// |:-----------------|:-------------------------|:------------|:----------|
/// | 0x0000           | RESERVED                 | N/A         | RFC XXXX  |
/// | 0x0001           | basic                    | Y           | RFC XXXX  |
/// | 0x0002           | x509                     | Y           | RFC XXXX  |
/// | 0xf000  - 0xffff | Reserved for Private Use | N/A         | RFC XXXX  |
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`Certificate`]
    X509 = 2,
}

impl TryFrom<u16> for CredentialType {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CredentialType::Basic),
            2 => Ok(CredentialType::X509),
            _ => Err("Undefined CredentialType"),
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

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`]
    X509(Certificate),
}

/// Credential.
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
    credential: MlsCredentialType,
}

impl Credential {
    /// Creates and returns a new [`Credential`] of the given
    /// [`CredentialType`] for the given identity.
    /// If the credential holds key material, this is generated and stored in
    /// the key store.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CredentialError> {
        let mls_credential = match credential_type {
            CredentialType::Basic => BasicCredential {
                identity: identity.into(),
            },
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: MlsCredentialType::Basic(mls_credential),
        };
        Ok(credential)
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
}

impl From<MlsCredentialType> for Credential {
    fn from(mls_credential_type: MlsCredentialType) -> Self {
        Credential {
            credential_type: match mls_credential_type {
                MlsCredentialType::Basic(_) => CredentialType::Basic,
                MlsCredentialType::X509(_) => CredentialType::X509,
            },
            credential: mls_credential_type,
        }
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
/// OpenMLS provides a [`BasicCredentialKeyPair`] for convenience. But it does
/// not have to be used for [`BasicCredential`]s.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct BasicCredential {
    identity: VLBytes,
}
