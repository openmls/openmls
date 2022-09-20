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
//! Clients can create a [`Credential`] by creating a [`CredentialBundle`] which
//! contains the [`Credential`], as well as the corresponding private key
//! material. The [`CredentialBundle`] can in turn be used to generate a
//! [`KeyPackageBundle`](crate::key_packages::KeyPackageBundle).
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

use openmls_traits::{
    types::{CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{ciphersuite::*, error::LibraryError};

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
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    cert_data: Vec<u8>,
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Credential {
    credential_type: CredentialType,
    credential: MlsCredentialType,
}

impl Credential {
    /// Verifies a signature of a given payload against the public key contained
    /// in a credential.
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential
                .public_key
                .verify(backend, signature, payload)
                .map_err(|_| CredentialError::InvalidSignature),
            // TODO: implement verification for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }

    /// Returns the signature scheme used by the credential.
    pub fn signature_scheme(&self) -> SignatureScheme {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.signature_scheme,
            // TODO: implement getter for signature scheme for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
    /// Returns the public key contained in the credential.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => &basic_credential.public_key,
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
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes an
/// `identity` to represent the client, as well as a signature public key, along
/// with the corresponding signature scheme.
#[derive(Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    identity: TlsByteVecU16,
    signature_scheme: SignatureScheme,
    public_key: SignaturePublicKey,
}

impl BasicCredential {
    /// Verifies a signature issued by a [`BasicCredential`].
    ///
    /// Returns a [`CredentialError`] if the verification fails.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        self.public_key
            .verify(backend, signature, payload)
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

impl PartialEq for BasicCredential {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.public_key == other.public_key
    }
}

/// Credential Bundle.
///
/// This struct contains a [`Credential`] and the private key corresponding to
/// the signature key it contains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq))]
pub struct CredentialBundle {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl CredentialBundle {
    /// Creates and returns a new [`CredentialBundle`] of the given
    /// [`CredentialType`] for the given identity and [`SignatureScheme`]. The
    /// corresponding key material is freshly generated.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CredentialError> {
        let (private_key, public_key) = SignatureKeypair::new(signature_scheme, backend)
            .map_err(LibraryError::unexpected_crypto_error)?
            .into_tuple();
        let mls_credential = match credential_type {
            CredentialType::Basic => BasicCredential {
                identity: identity.into(),
                signature_scheme,
                public_key,
            },
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: MlsCredentialType::Basic(mls_credential),
        };
        Ok(CredentialBundle {
            credential,
            signature_private_key: private_key,
        })
    }

    /// Creates a new [`CredentialBundle`] from an identity and a
    /// [`SignatureKeypair`]. Note that only [`BasicCredential`] is currently
    /// supported.
    pub fn from_parts(identity: Vec<u8>, keypair: SignatureKeypair) -> Self {
        let (signature_private_key, public_key) = keypair.into_tuple();
        let basic_credential = BasicCredential {
            identity: identity.into(),
            signature_scheme: public_key.signature_scheme(),
            public_key,
        };
        let credential = Credential {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(basic_credential),
        };
        Self {
            credential,
            signature_private_key,
        }
    }

    /// Returns a reference to the [`Credential`].
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Separates the bundle into the [`Credential`] and the [`SignaturePrivateKey`].
    pub fn into_parts(self) -> (Credential, SignaturePrivateKey) {
        (self.credential, self.signature_private_key)
    }

    /// Signs the given message `msg` using the private key of the credential bundle.
    pub(crate) fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        msg: &[u8],
    ) -> Result<Signature, CryptoError> {
        self.signature_private_key.sign(backend, msg)
    }

    /// Returns the key pair of the given credential bundle.
    #[cfg(any(feature = "test-utils", test))]
    pub fn key_pair(&self) -> SignatureKeypair {
        let public_key = self.credential().signature_key().clone();
        let private_key = self.signature_private_key.clone();
        SignatureKeypair::from_parts(public_key, private_key)
    }
}
